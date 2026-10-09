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
        comment = re.match(r"\A<!--\s*(.*?)\s*-->", source, re.DOTALL)
        line = comment.group(1) if comment else ""
        if not all(f"{field}:" in line for field in FIELDS):
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


# Architecture fences are declaration-only types/specs/callbacks, including a
# proposed API; evaluating them as scripts would misrepresent their purpose.
FENCE_EXEMPTIONS = {
    "docs/design/architecture.md": "declaration-only types/specs/callbacks, including a proposed API",
}


def elixir_fences(source):
    """Exact bytes in document order; reject container fences rather than skip."""
    blocks, body = [], []
    opening = language = None
    for line in source.splitlines(keepends=True):
        if opening is None:
            # Recognize info words even with a comma, title, or other suffix.
            candidate = re.match(r"^([ \t]*(?:>[ \t]*)*(?:(?:[-+*]|\d+[.)])[ \t]+)?)(`{3,}|~{3,})([^\r\n]*)", line)
            if candidate:
                prefix, marker, info = candidate.groups()
                elixir = re.match(r"elixir(?:\b|$)", info.strip()) is not None
                if elixir and (prefix.strip() or len(prefix) > 3):
                    raise ValueError("indented/list or blockquoted Elixir fence is unsupported; use a top-level fence")
                if not prefix.strip() and len(prefix) <= 3:
                    opening, language, body = marker, elixir, []
        elif re.fullmatch(r" {0,3}" + re.escape(opening[0]) + "{" + str(len(opening)) + r",}\s*", line):
            if language:
                blocks.append("".join(body))
            opening = None
        else:
            body.append(line)
    if opening is not None and language:
        raise ValueError("unclosed Elixir fence")
    return blocks


def paired_test(relative):
    if relative == "README.md":
        return Path("test/readme_test.exs")
    if Path(relative).parent.as_posix() == "docs/guides":
        return Path("test/guides") / (Path(relative).stem.replace("-", "_") + "_test.exs")
    return Path("test/docs") / (relative.removesuffix(".md").replace("/", "_").replace("-", "_") + "_test.exs")


def evaluated_blocks(source):
    """Read direct helper calls, skipping comments, strings, and other sigils.

    The paired-test contract deliberately uses literal document/index arguments
    and unindented ~S heredocs. A substring in another literal is never a call.
    """
    call = re.compile(r"E\.eval\(\s*~S'''\r?\n(.*?)^([ \t]*)'''\s*,\s*binding\s*,\s*\"([^\"]+)\"\s*,\s*(\d+)\s*\)", re.MULTILINE | re.DOTALL)
    finish = re.compile(r'E\.assert_fences\("([^"\n]+)",\s*(\d+)\)')
    blocks, finishes, i = [], [], 0
    while i < len(source):
        match = call.match(source, i)
        if match:
            indent = match[2]
            code = "".join(line[len(indent):] if line.startswith(indent) else line for line in match[1].splitlines(keepends=True))
            blocks.append((match[3], int(match[4]), code))
            i = match.end()
            continue
        match = finish.match(source, i)
        if match:
            finishes.append((match[1], int(match[2])))
            i = match.end()
            continue
        if source[i] == "#":
            end = source.find("\n", i)
            i = len(source) if end < 0 else end + 1
            continue
        # Skip full Elixir sigils and quoted strings, including triple quotes.
        sigil = re.match(r"~[a-zA-Z]([\"'/{\[(<|])", source[i:])
        delimiter = sigil[1] if sigil else source[i] if source[i] in "\"'" else None
        if delimiter:
            begin = i + (2 if sigil else 0)
            triple = source.startswith(delimiter * 3, begin)
            closing = delimiter * 3 if triple else {"{": "}", "[": "]", "(": ")", "<": ">"}.get(delimiter, delimiter)
            cursor = begin + (3 if triple else 1)
            depth = 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                elif not triple and delimiter in "{[(<" and source[cursor] == delimiter:
                    depth += 1
                    cursor += 1
                elif source.startswith(closing, cursor):
                    depth -= 1
                    cursor += len(closing)
                    if depth == 0:
                        break
                else:
                    cursor += 1
            i = cursor
        else:
            i += 1
    return blocks, finishes


def fence_errors(root, relative, source):
    if Path(relative).suffix != ".md":
        return []  # Livebooks have their separate importer/exporter/execution gate.
    try:
        examples = elixir_fences(source)
    except ValueError as error:
        return [f"{relative}: {error}"]
    if relative in FENCE_EXEMPTIONS or not examples:
        return []
    test = paired_test(relative)
    target = root / test
    copies = target.read_bytes().decode("utf-8") if target.is_file() and not target.is_symlink() else ""
    blocks, finishes = evaluated_blocks(copies)
    expected = [(relative, index, example) for index, example in enumerate(examples, 1)]
    errors = []
    if blocks != expected:
        errors.append(f"{relative}: Elixir fences require one-to-one byte-identical evaluated blocks in {test}")
    if finishes != [(relative, len(examples))]:
        errors.append(f"{relative}: {test} must assert execution of all {len(examples)} fences exactly once")
    if "alias RequestSeal.DocsExamples, as: E" not in copies:
        errors.append(f"{relative}: {test} must use the recording evaluation helper")
    return errors


def check(root=ROOT):
    approved = public_documents(root)
    paths = public_paths(root)
    errors = inventory_errors(root, approved, paths)
    for relative in sorted(approved):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            source = path.read_bytes().decode("utf-8")
            errors.extend(content_errors(root, relative, source, paths))
            errors.extend(fence_errors(root, relative, source))
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
    print("Scope: every approved Markdown Elixir fence is paired and executed; Livebooks use their dedicated execution gate")
    for path, reason in FENCE_EXEMPTIONS.items():
        print(f"Fence exemption: {path}: {reason}")
