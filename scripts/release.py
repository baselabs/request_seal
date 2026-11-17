#!/usr/bin/env python3
"""Release identity and reproducible SBOM metadata shared by repository gates."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess
import uuid
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def parse_version(version):
    match = SEMVER.fullmatch(version)
    if not match:
        raise ValueError("package version must be a semantic MAJOR.MINOR.PATCH version")
    return match


def package_version(source):
    matches = re.findall(r'^\s*@version "([^"]+)"\s*$', source, re.MULTILINE)
    if len(matches) != 1 or not re.search(r'\bversion: @version\b', source):
        raise ValueError("mix.exs: package version must use one @version attribute")
    parse_version(matches[0])
    return matches[0]


def install_requirement(version):
    """Pre-1.0 requirements select a patch line; stable majors select a minor line."""
    match = parse_version(version)
    major, minor, patch = match.group(1, 2, 3)
    if match[4] and not development_snapshot(version):
        return f"~> {major}.{minor}.{patch}-{match[4]}"
    return f"~> {major}.{minor}.{patch}" if major == "0" else f"~> {major}.{minor}"


def development_snapshot(version):
    pre = parse_version(version)[4]
    return bool(pre and pre.split(".", 1)[0].startswith("dev"))


def source_ref(version):
    return "main" if development_snapshot(version) else "v" + version


def source_url(source):
    matches = re.findall(r'^\s*source_url: "([^"]+)"', source, re.MULTILINE)
    if len(matches) != 1 or urlsplit(matches[0]).scheme not in ("https", "http"):
        raise ValueError("mix.exs requires one public source_url")
    return matches[0].rstrip("/")


def markdown_lines(source):
    """Yield lines with fenced blocks marked, including their delimiters."""
    fence = None
    for line in source.splitlines(keepends=True):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        fenced = fence is not None or marker is not None
        if marker:
            run, rest = marker.groups()
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not rest.strip():
                fence = None
        yield line, fenced


def pin_markdown_links(body, version, repository_url):
    """Pin Markdown destinations, preserving code and destination delimiters."""
    # Mask block code first; offsets still refer to the original Markdown bytes.
    visible = "".join(
        re.sub(r"[^\n]", " ", line) if fenced or re.match(r"^(?: {4}|\t)", line) else line
        for line, fenced in markdown_lines(body)
    )
    # A code span closes with exactly the same number of backticks, even across lines.
    spans = list(re.finditer(r"`+", visible))
    cursor = 0
    while cursor < len(spans):
        opening = spans[cursor]
        closing = next((index for index in range(cursor + 1, len(spans))
                        if spans[index][0] == opening[0]), None)
        if closing is None:
            cursor += 1
        else:
            end = spans[closing].end()
            visible = visible[:opening.start()] + re.sub(r"[^\n]", " ", visible[opening.start():end]) + visible[end:]
            cursor = closing + 1

    def destination(start):
        if start >= len(visible):
            return None
        if visible[start] == "<":
            end = visible.find(">", start + 1)
            if end >= 0 and "\n" not in visible[start:end]:
                return start + 1, end, end + 1
            return None
        end, depth = start, 0
        while end < len(visible):
            char = visible[end]
            if char == "\\" and end + 1 < len(visible):
                end += 2
                continue
            if char.isspace() or (char == ")" and depth == 0):
                break
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            end += 1
        return (start, end, end) if end > start and depth == 0 else None

    def pinned(target, image):
        if target.startswith(("#", "//")) or urlsplit(target).scheme:
            return target
        if target.startswith("?"):
            raise ValueError("CHANGELOG.md has an invalid relative link: " + target)
        parts = urlsplit(target)
        path = posixpath.normpath(unquote(parts.path).lstrip("/"))
        if path == ".." or path.startswith("../"):
            raise ValueError("CHANGELOG.md link escapes the repository: " + target)
        path = quote(path, safe="/!$&'()*+,;=:@-._~")
        suffix = ("?" + parts.query if parts.query else "") + ("#" + parts.fragment if parts.fragment else "")
        return repository_url.rstrip("/") + ("/raw/v" if image else "/blob/v") + version + "/" + path + suffix

    replacements = []
    # Footnotes have prose after the colon, not a reference-link destination.
    for match in re.finditer(r"^ {0,3}\[(?!\^)(?:\\.|[^\]\\])+\]:[ \t]*", visible, re.MULTILINE):
        found = destination(match.end())
        if found:
            start, end, _ = found
            replacements.append((start, end, pinned(body[start:end], False)))

    cursor = 0
    while cursor < len(visible):
        if visible[cursor] == "\\":
            cursor += 2
            continue
        image = visible.startswith("![", cursor)
        opening = cursor + 1 if image else cursor
        if visible[opening:opening + 1] != "[":
            cursor += 1
            continue
        end, depth = opening + 1, 1
        while end < len(visible) and depth:
            if visible[end] == "\\":
                end += 2
                continue
            if visible[end] == "[":
                depth += 1
            elif visible[end] == "]":
                depth -= 1
            end += 1
        if depth or visible[end:end + 1] != "(":
            cursor += 1
            continue
        start = end + 1
        while start < len(visible) and visible[start].isspace():
            start += 1
        found = destination(start)
        if found:
            start, finish, after = found
            # Only a valid closing delimiter (with optional title) makes a link.
            closing = re.match(r'''(?:\s+(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\([^()]*\)))?\s*\)''', visible[after:])
            if closing:
                replacements.append((start, finish, pinned(body[start:finish], image)))
                cursor = after + closing.end()
                continue
        cursor = end

    for start, end, replacement in sorted(replacements, reverse=True):
        body = body[:start] + replacement + body[end:]
    return body


def release_notes(source, version, repository_url=None):
    """Return only the body of one dated release section, never Unreleased."""
    source = source.replace("\r\n", "\n")
    sections = []
    offset = 0
    for line, fenced in markdown_lines(source):
        if not fenced and line.startswith("## "):
            sections.append((offset, offset + len(line), line.rstrip("\n")))
        offset += len(line)
    heading = re.compile(r"## " + re.escape(version) + r" - (\d{4}-\d{2}-\d{2})[ \t]*$")
    matches = [(index, heading.fullmatch(section[2])) for index, section in enumerate(sections)
               if heading.fullmatch(section[2])]
    if len(matches) != 1:
        raise ValueError("CHANGELOG.md requires one dated section for " + version)
    index, match = matches[0]
    datetime.date.fromisoformat(match[1])
    end = sections[index + 1][0] if index + 1 < len(sections) else len(source)
    body = source[sections[index][1]:end].strip("\n")
    if not body.strip() or not re.sub(r"(?m)^#{3,6}[^\n]*$", "", body).strip():
        raise ValueError("CHANGELOG.md release section is empty for " + version)

    if repository_url is None:
        repository_url = source_url((ROOT / "mix.exs").read_text())

    return pin_markdown_links(body, version, repository_url) + "\n"


def verify_identity(root, event, ref):
    version = package_version((root / "mix.exs").read_text())
    if development_snapshot(version):
        raise ValueError("release verification refuses development snapshots")
    release_notes((root / "CHANGELOG.md").read_text(), version, source_url((root / "mix.exs").read_text()))
    tag = "v" + version
    index = json.loads((root / "corpus/index.json").read_text())
    if index.get("elixir_release") != tag:
        raise ValueError("corpus elixir_release must equal " + tag)
    if event not in ("push", "workflow_dispatch"):
        raise ValueError("release verification requires a tag push or workflow_dispatch")
    if event == "push" and ref != "refs/tags/" + tag:
        raise ValueError("release tag must equal " + tag)

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()

    exists = subprocess.run(["git", "show-ref", "--verify", "--quiet", "refs/tags/" + tag], cwd=root)
    if exists.returncode not in (0, 1):
        raise ValueError("cannot inspect release tag")
    if exists.returncode == 0:
        if git("rev-parse", "refs/tags/" + tag + "^{commit}") != git("rev-parse", "HEAD"):
            raise ValueError("release tag must point at the checked-out commit")
    elif event == "push":
        raise ValueError("release tag is missing")
    return version


def normalize_sbom(path, tarball):
    """Bind a deterministic CycloneDX serial to package identity and exact bytes."""
    try:
        _normalize_sbom(path, tarball)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("Malformed release SBOM: missing or invalid CycloneDX metadata or graph") from error


def _normalize_sbom(path, tarball):
    bom = json.loads(path.read_text())
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        raise ValueError("release SBOM must use CycloneDX 1.6")
    component = bom["metadata"]["component"]
    identity = f'{component["name"]}\n{component["version"]}\n{hashlib.sha256(tarball.read_bytes()).hexdigest()}'
    bom["serialNumber"] = uuid.uuid5(uuid.NAMESPACE_URL, identity).urn
    bom.get("metadata", {}).pop("timestamp", None)
    bom["components"].sort(key=lambda component: component["bom-ref"])
    bom["dependencies"].sort(key=lambda dependency: dependency["ref"])
    for dependency in bom["dependencies"]:
        dependency.get("dependsOn", []).sort()
    path.write_text(json.dumps(bom, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--version", action="store_true")
    choice.add_argument("--install-requirement", action="store_true")
    choice.add_argument("--verify", action="store_true")
    choice.add_argument("--normalize-sbom", type=Path)
    choice.add_argument("--release-notes", action="store_true")
    parser.add_argument("--tarball", type=Path)
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--for-version")
    args = parser.parse_args()
    try:
        if args.normalize_sbom:
            if not args.tarball:
                parser.error("--normalize-sbom requires --tarball")
            normalize_sbom(args.normalize_sbom, args.tarball)
        elif args.release_notes:
            version = args.for_version or package_version((ROOT / "mix.exs").read_text())
            parse_version(version)
            print(release_notes((ROOT / "CHANGELOG.md").read_text(), version), end="")
        elif args.verify:
            version = verify_identity(ROOT, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"])
            if args.notes_file:
                args.notes_file.write_text(release_notes((ROOT / "CHANGELOG.md").read_text(), version))
            print("PASS: release identity " + version)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                    output.write("version=" + version + "\n")
                    output.write("prerelease=" + str(bool(parse_version(version)[4])).lower() + "\n")
        else:
            version = args.for_version or package_version((ROOT / "mix.exs").read_text())
            parse_version(version)
            print(install_requirement(version) if args.install_requirement else version)
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
