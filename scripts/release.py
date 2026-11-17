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
import string
import subprocess
import uuid
from urllib.parse import quote, urlsplit

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


def markdown_blocks(source):
    """Yield code visibility, content offsets and container identity for each line."""
    root = {"paragraph": False}
    containers = []
    fence = None

    def indent(line, offset, column, limit=None):
        while offset < len(line) and line[offset] in " \t" and (limit is None or column < limit):
            column += 4 - column % 4 if line[offset] == "\t" else 1
            offset += 1
        return offset, column

    def interrupts(text):
        return re.match(r"(?:>|[-+*][ \t]|\d{1,9}[.)][ \t]|`{3,}|~{3,}|#{1,6}(?:\s|$))", text)

    for original in source.splitlines(keepends=True):
        # Parse expanded columns, then map content offsets back to source bytes.
        # A container boundary can fall in the middle of a tab expansion.
        line = original.expandtabs(4)
        offsets = [0]
        for index, char in enumerate(original):
            width = 4 - (len(offsets) - 1) % 4 if char == "\t" else 1
            offsets.extend([index + 1] * width)
        offset = column = 0
        lazy = False
        for index, container in enumerate(containers):
            start, col = indent(line, offset, column)
            if container["kind"] == "list" and col >= container["column"]:
                offset, column = indent(line, offset, column, container["column"])
            elif container["kind"] == "quote" and col - column <= 3 and line[start:start + 1] == ">":
                offset, column = start + 1, col + 1
                if line[offset:offset + 1] in (" ", "\t"):
                    offset, column = indent(line, offset, column, column + 1)
            elif not line.strip():
                break  # Blank lines keep list items open.
            elif containers[-1]["paragraph"] and not interrupts(line[start:]) and fence is None:
                lazy = True
                break
            else:
                del containers[index:]
                break

        context = containers[-1] if containers else root
        if fence and fence[0] is not context:
            fence = None
        starts_container = False
        if not lazy and fence is None:
            while True:
                start, col = indent(line, offset, column)
                if col - column > 3:
                    break
                if line[start:start + 1] == ">":
                    offset, column = start + 1, col + 1
                    if line[offset:offset + 1] in (" ", "\t"):
                        offset, column = indent(line, offset, column, column + 1)
                    container = {"kind": "quote", "paragraph": False}
                else:
                    marker = re.match(r"(?:[-+*]|\d{1,9}[.)])(?=[ \t])", line[start:])
                    if marker is None:
                        break
                    offset, column = start + marker.end(), col + marker.end()
                    end, end_column = indent(line, offset, column)
                    if end_column - column <= 4:
                        offset, column = end, end_column
                    else:
                        offset, column = indent(line, offset, column, column + 1)
                    container = {"kind": "list", "column": column, "paragraph": False}
                context["paragraph"] = False
                containers.append(container)
                context = container
                starts_container = True

        start, col = indent(line, offset, column)
        text = line[start:]
        code = False
        if fence:
            code = True
            marker = re.match(r"(`{3,}|~{3,})(.*)$", text)
            if col - column <= 3 and marker:
                run, rest = marker.groups()
                if run[0] == fence[1][0] and len(run) >= len(fence[1]) and not rest.strip():
                    fence = None
        elif not lazy and col - column >= 4 and (starts_container or not context["paragraph"]):
            code = bool(text.strip())
        elif col - column <= 3:
            marker = re.match(r"(`{3,}|~{3,})(.*)$", text)
            if marker and (marker[1][0] == "~" or "`" not in marker[2]):
                fence = context, marker[1]
                code = True
        context["paragraph"] = bool(text.strip()) and not code and not re.match(r"#{1,6}(?:\s|$)", text)
        yield original, code, offsets[offset], context


def markdown_lines(source):
    """Yield lines with container-aware code blocks marked, including fences."""
    for line, code, _, _ in markdown_blocks(source):
        yield line, code


def pin_markdown_links(body, version, repository_url):
    """Pin Markdown destinations, preserving code and destination delimiters."""
    # Mask block code first; offsets still refer to the original Markdown bytes.
    lines = []
    offset = 0
    pieces = []
    for line, code, content, context in markdown_blocks(body):
        lines.append((offset, offset + content, offset + len(line), context))
        pieces.append(re.sub(r"[^\n]", " ", line) if code else " " * content + line[content:])
        offset += len(line)
    visible = "".join(pieces)
    # Exact backtick runs may span lines, but never a blank line.
    spans = list(re.finditer(r"`+", visible))
    cursor = 0
    while cursor < len(spans):
        opening = spans[cursor]
        if len(re.search(r"\\*$", visible[:opening.start()])[0]) % 2:
            cursor += 1
            continue
        closing = next((index for index in range(cursor + 1, len(spans))
                        if spans[index][0] == opening[0]
                        and not re.search(r"\n[ \t]*\n", visible[opening.end():spans[index].start()])), None)
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
        target = re.sub(r"\\([" + re.escape(string.punctuation) + r"])", r"\1", target)
        if target.startswith(("#", "//")) or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", target):
            return target
        if target.startswith("?"):
            raise ValueError("CHANGELOG.md has an invalid relative link: " + target)
        path, fragment_mark, fragment = target.partition("#")
        path, query_mark, query = path.partition("?")
        path = posixpath.normpath(path.lstrip("/"))
        if path == ".." or path.startswith("../"):
            raise ValueError("CHANGELOG.md link escapes the repository: " + target)
        target = path + query_mark + query + fragment_mark + fragment
        target = "".join(quote(char, safe="") if ord(char) <= 32 or ord(char) == 127 or char in "<>()\\" else char
                         for char in target)
        return repository_url.rstrip("/") + ("/raw/v" if image else "/blob/v") + version + "/" + target

    replacements = []
    title = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\((?:\\.|[^()\\])*\))'''

    def label(value):
        return " ".join(value.split()).casefold()

    definitions = {}
    for line_start, content, line_end, context in lines:
        match = re.match(r" {0,3}\[((?!\^)(?:\\.|[^\]\\])+)\]:[ \t]*", visible[content:line_end])
        if not match:
            continue
        start = content + match.end()
        if visible[start:start + 1] == "\n":
            start += 1
            while start < len(visible) and visible[start] in " \t":
                start += 1
        found = destination(start)
        if not found:
            continue
        start, finish, after = found
        ending = re.match(r"[ \t]*(?:\n[ \t]*)?" + title + r"[ \t]*(?:\n|$)", visible[after:])
        if ending is None:
            ending = re.match(r"[ \t]*(?:\n|$)", visible[after:])
        if ending is None:
            continue
        end = after + ending.end()
        if re.search(r"\n[ \t]*\n", visible[line_start:end].rstrip("\n")):
            continue
        if any(other is not context for begin, _, _, other in lines if line_start < begin < end):
            continue
        key = label(match[1])
        definitions.setdefault(key, []).append((start, finish))
        visible = visible[:line_start] + re.sub(r"[^\n]", " ", visible[line_start:end]) + visible[end:]

    uses = {}

    def scan(cursor, limit):
        while cursor < limit:
            if visible[cursor] == "\\":
                cursor += 2
                continue
            image = visible.startswith("![", cursor)
            opening = cursor + 1 if image else cursor
            if visible[opening:opening + 1] != "[":
                cursor += 1
                continue
            end, depth = opening + 1, 1
            while end < limit and depth:
                if visible[end] == "\\":
                    end += 2
                    continue
                if visible[end] == "[":
                    depth += 1
                elif visible[end] == "]":
                    depth -= 1
                end += 1
            if depth:
                cursor += 1
                continue
            scan(opening + 1, end - 1)  # Link text can itself contain an image.
            after_link = end
            inline = False
            if visible[end:end + 1] == "(":
                start = end + 1
                while start < limit and visible[start].isspace():
                    start += 1
                found = destination(start)
                if found:
                    start, finish, after = found
                    closing = re.match(r"(?:\s+" + title + r")?\s*\)", visible[after:limit])
                    if closing:
                        replacements.append((start, finish, pinned(body[start:finish], image)))
                        after_link, inline = after + closing.end(), True
            if not inline:
                reference = re.match(r"\[((?:\\.|[^\[\]\\])*)\]", visible[end:limit])
                key = label((reference[1] if reference and reference[1] else visible[opening + 1:end - 1]))
                if key in definitions:
                    uses.setdefault(key, set()).add(image)
                    if reference:
                        after_link = end + reference.end()
            cursor = after_link

    scan(0, len(visible))
    for key, destinations in definitions.items():
        kinds = uses.get(key, {False})
        if len(kinds) > 1:
            raise ValueError("CHANGELOG.md reference label used by both image and link: " + key)
        for start, finish in destinations:
            replacements.append((start, finish, pinned(body[start:finish], True in kinds)))

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
