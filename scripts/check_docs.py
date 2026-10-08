#!/usr/bin/env python3
"""Check the explicit public-document inventory, content tripwires, and local links."""
from pathlib import Path
from html import unescape
import os
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("Status", "Kind", "Updated", "Governed by", "Review when")
MACHINE_PATH = re.compile(r"(?:/Users/[^/\s]+/|/home/[^/\s]+/|file://)")
INTERNAL_PROCESS = re.compile(
    r"internal (?:workflow|planning|review authorization)|confidential planning|"
    r"private (?:review records|planning records)",
    re.IGNORECASE,
)
LINKS = (
    re.compile(r"\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+['\"][^)]*['\"])?\s*\)"),
    re.compile(r"^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)", re.MULTILINE),
)

# Extract attributes independently of HTML parser state. An unfinished script or
# comment in a Markdown example must not hide later public targets. Inspect code
# examples too; this is a disclosure tripwire, not an HTML rendering validator.
HTML_ATTRIBUTES = re.compile(
    r"""\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""",
    re.IGNORECASE,
)


def public_paths(root):
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, text=True, check=True, timeout=30,
    )
    paths = set(filter(None, result.stdout.split("\0")))
    if "README.md" not in paths:
        raise ValueError("public source inventory did not find its README.md positive control")
    return paths


def public_documents(root):
    # Read Mix's actual project configuration without compiling or starting the app.
    marker = "REQUEST_SEAL_PUBLIC_DOCUMENT\t"
    expression = (
        'for entry <- Keyword.fetch!(Keyword.fetch!(Mix.Project.config(), :docs), :extras) do '
        'path = case entry do {path, _options} -> path; path -> path end; '
        'IO.puts("REQUEST_SEAL_PUBLIC_DOCUMENT\\t" <> path) end'
    )
    result = subprocess.run(
        ["mix", "run", "--no-start", "--no-compile", "--no-deps-check", "-e", expression],
        cwd=root, capture_output=True, text=True, check=True, timeout=120,
    )
    entries = [line[len(marker):] for line in result.stdout.splitlines() if line.startswith(marker)]
    if not entries or "README.md" not in entries or len(entries) != len(set(entries)):
        raise ValueError("invalid or empty public document configuration")
    if any(not safe_document_path(p) for p in entries):
        raise ValueError("public document configuration contains an unsafe path")
    return set(entries) | {"AGENTS.md"}


def safe_document_path(path):
    parts = Path(path).parts
    return bool(parts) and not Path(path).is_absolute() and all(
        not part.startswith(".") for part in parts
    ) and Path(path).as_posix() == path


def has_symlink(root, relative):
    item = root
    for part in Path(relative).parts:
        item = item / part
        if item.is_symlink():
            return True
    return False


def inventory_errors(root, approved, paths):
    root = root.resolve()
    errors = []
    if not approved or "README.md" not in approved:
        return ["public documentation inventory must include README.md"]
    candidates = {
        p for p in paths
        if Path(p).suffix.lower() in (".md", ".livemd")
        or p.startswith(("docs/", "livebooks/"))
        or (p.startswith("lib/") and Path(p).suffix != ".ex")
    }
    for path in sorted(candidates - approved):
        # A removal can remain in Git's index before staging. It has no public
        # working-tree bytes; symlinks (including broken ones) still need review.
        if (root / path).exists() or (root / path).is_symlink():
            errors.append(f"{path}: document is not approved for publication")
    for path in sorted(approved):
        if not safe_document_path(path):
            errors.append(f"{path}: public document has an unsafe path")
            continue
        item = root / path
        if path not in paths or not item.is_file():
            errors.append(f"{path}: approved document is missing from public source")
            continue
        resolved = item.resolve()
        if has_symlink(root, path) or not resolved.is_relative_to(root.resolve()):
            errors.append(f"{path}: public document must be a repository file, not a symlink")
    return errors


def content_errors(root, relative, source, paths):
    root = root.resolve()
    errors = []
    path = root / relative
    record = relative in ("AGENTS.md", "CHANGELOG.md", "LICENSE", "NOTICE") or relative.startswith("docs/adr/")
    if not record:
        line = next((x for x in source.splitlines() if x.startswith("**Status:**")), "")
        if not all(f"**{field}:**" in line for field in FIELDS):
            errors.append(f"{relative}: incomplete status metadata")
    if MACHINE_PATH.search(source):
        errors.append(f"{relative}: machine or private file URL")
    if INTERNAL_PROCESS.search(source):
        errors.append(f"{relative}: internal process material is not public documentation")
    targets = [match.group(1).strip("<>") for pattern in LINKS for match in pattern.finditer(source)]
    targets.extend(
        unescape(next(value for value in match.groups() if value is not None))
        for match in HTML_ATTRIBUTES.finditer(source)
    )
    for target in targets:
        try:
            url = urlsplit(target)
        except ValueError:
            errors.append(f"{relative}: malformed link")
            continue
        if url.scheme in ("https", "http", "mailto"):
            continue
        if url.scheme or url.netloc:
            errors.append(f"{relative}: unsupported or private link scheme")
            continue
        target_path = unquote(url.path)
        if not target_path:
            continue
        if any(part.startswith(".") and part not in (".", "..") for part in Path(target_path).parts):
            errors.append(f"{relative}: link targets a private directory or file")
            continue
        lexical = Path(os.path.abspath(path.parent / target_path))
        destination = lexical.resolve()
        if not lexical.is_relative_to(root.resolve()) or not destination.is_relative_to(root.resolve()):
            errors.append(f"{relative}: link escapes public repository")
        elif lexical.relative_to(root.resolve()).as_posix() not in paths:
            errors.append(f"{relative}: link targets unpublished content")
        elif has_symlink(root, lexical.relative_to(root.resolve())):
            errors.append(f"{relative}: local link must not traverse a symlink")
        elif not destination.exists():
            errors.append(f"{relative}: missing local link")
    return errors


def check(root=ROOT):
    approved = public_documents(root)
    paths = public_paths(root)
    errors = inventory_errors(root, approved, paths)
    for relative in sorted(approved):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            errors.extend(content_errors(root, relative, path.read_text(), paths))
    return approved, errors


if __name__ == "__main__":
    try:
        approved, errors = check()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Public-document check failed: {error}")
        sys.exit(1)
    if errors:
        print("\n".join(errors))
        sys.exit(1)
    print(f"PASS: {len(approved)} approved public documents, metadata, disclosure tripwires, and links")
    print("Scope: explicit inventory and named content/link checks; newly approved prose still needs review")
