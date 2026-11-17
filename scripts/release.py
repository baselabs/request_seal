#!/usr/bin/env python3
"""Release identity and reproducible SBOM metadata shared by repository gates."""
import argparse
import datetime
import hashlib
from html import unescape
from html.parser import HTMLParser
import json
import os
from pathlib import Path
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


# CommonMark 0.31.2 §§4.6 and 6.6. Keep token boundaries and source offsets:
# Keep the original tag spelling when the HTML tokenizer supplies boundaries.
HTML_SPACE = r"[ \t\n\r]"
HTML_NAME = r"[A-Za-z_:][A-Za-z0-9_.:-]*"
HTML_VALUE = r'''(?:"[^"]*"|'[^']*'|[^ \t\n\r"'=<>`]+)'''
HTML_ATTRIBUTE = HTML_NAME + r"(?:" + HTML_SPACE + r"*=" + HTML_SPACE + "*" + HTML_VALUE + r")?"
HTML_OPEN = r"<[A-Za-z][A-Za-z0-9-]*(?:" + HTML_SPACE + "+" + HTML_ATTRIBUTE + r")*" + HTML_SPACE + r"*/?>"
HTML_CLOSE = r"</[A-Za-z][A-Za-z0-9-]*" + HTML_SPACE + r"*>"
HTML_TOKEN = re.compile(
    r"<!--(?:>|->|[\s\S]*?-->)|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<![A-Za-z][^>]*>|"
    + HTML_OPEN + "|" + HTML_CLOSE)
HTML_BLOCK_TAGS = (
    "address article aside base basefont blockquote body caption center col colgroup dd details dialog dir div dl dt "
    "fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li "
    "link main menu menuitem nav noframes ol optgroup option p param search section summary table tbody td tfoot th "
    "thead title tr track ul"
).split()
THEMATIC = re.compile(r"(?:\*[ \t]*){3,}$|(?:-[ \t]*){3,}$|(?:_[ \t]*){3,}$")
SETEXT = re.compile(r"(?:=+|-+)[ \t]*$")


def html_block(text, paragraph):
    if re.match(r"<(?:script|pre|style|textarea)(?:[ \t\n>]|$)", text, re.I):
        return re.compile(r"</(?:script|pre|style|textarea)>", re.I)
    for opening, closing in (("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>")):
        if text.startswith(opening):
            return re.compile(re.escape(closing))
    if re.match(r"<![A-Za-z]", text):
        return re.compile(">")
    if re.match(r"</?(?:" + "|".join(HTML_BLOCK_TAGS) + r")(?:[ \t\n>]|/?>|$)", text, re.I):
        return "blank"
    if not paragraph and re.fullmatch(r"(?:" + HTML_OPEN + "|" + HTML_CLOSE + r")[ \t]*\n?", text):
        return "blank"
    return None


def markdown_blocks(source):
    """Yield code visibility, content offset and leaf-block identity per line."""
    root = {"paragraph": False, "block": None}
    containers = []
    fence = raw = None

    def indent(line, offset, column, limit=None):
        while offset < len(line) and line[offset] in " \t" and (limit is None or column < limit):
            column += 4 - column % 4 if line[offset] == "\t" else 1
            offset += 1
        return offset, column

    def interrupts(text):
        return (THEMATIC.fullmatch(text.rstrip("\r\n")) or
                re.match(r"(?:>|[-+*][ \t]+\S|1[.)][ \t]+\S|`{3,}|~{3,}|#{1,6}(?:[ \t\n]|$))", text) or
                html_block(text, True))

    for original in source.splitlines(keepends=True):
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
            elif not line.strip(" \t\r\n") and container["kind"] == "list":
                break
            elif containers[-1]["paragraph"] and not interrupts(line[start:]) and fence is None and raw is None:
                lazy = True
                break
            else:
                del containers[index:]
                break

        context = containers[-1] if containers else root
        if fence and fence[0] is not context:
            fence = None
        if raw and raw[0] is not context:
            raw = None
        starts_container = False
        if not lazy and fence is None and raw is None:
            while True:
                start, col = indent(line, offset, column)
                if col - column > 3 or THEMATIC.fullmatch(line[start:].rstrip("\r\n")):
                    break
                if line[start:start + 1] == ">":
                    offset, column = start + 1, col + 1
                    if line[offset:offset + 1] in (" ", "\t"):
                        offset, column = indent(line, offset, column, column + 1)
                    container = {"kind": "quote", "paragraph": False, "block": None}
                else:
                    marker = re.match(r"(?:[-+*]|\d{1,9}[.)])(?=[ \t])", line[start:])
                    if marker is None or (context["paragraph"] and not interrupts(line[start:])):
                        break
                    offset, column = start + marker.end(), col + marker.end()
                    end, end_column = indent(line, offset, column)
                    if end_column - column <= 4:
                        offset, column = end, end_column
                    else:
                        offset, column = indent(line, offset, column, column + 1)
                    container = {"kind": "list", "column": column, "paragraph": False, "block": None}
                context["paragraph"] = False
                containers.append(container)
                context = container
                starts_container = True

        start, col = indent(line, offset, column)
        text = line[start:]
        blank = not text.strip(" \t\r\n")
        code = False
        kind = "paragraph"
        block = context["block"]
        if raw and raw[1] == "blank" and blank:
            raw = None
        if fence:
            code = True
            marker = re.match(r"(`{3,}|~{3,})(.*)$", text)
            if col - column <= 3 and marker:
                run, rest = marker.groups()
                if run[0] == fence[1][0] and len(run) >= len(fence[1]) and not rest.strip(" \t\r\n"):
                    fence = None
        elif raw:
            kind = "html"
            if raw[1] != "blank" and raw[1].search(text):
                raw = None
        elif not lazy and col - column >= 4 and (starts_container or not context["paragraph"]):
            code = not blank
        elif col - column <= 3:
            marker = re.match(r"(`{3,}|~{3,})(.*)$", text)
            ending = html_block(text, context["paragraph"])
            if marker and (marker[1][0] == "~" or "`" not in marker[2]):
                fence = context, marker[1]
                code = True
            elif ending:
                kind = "html"
                block = {"kind": kind}
                if ending == "blank" or not ending.search(text):
                    raw = context, ending
            elif not lazy and context["paragraph"] and SETEXT.fullmatch(text.rstrip("\r\n")):
                kind = "underline"
            elif THEMATIC.fullmatch(text.rstrip("\r\n")):
                kind = "break"
            elif re.match(r"#{1,6}(?:[ \t\n]|$)", text):
                kind = "heading"
        if blank and kind != "html":
            kind = "blank"
        if code:
            kind = "code"
        if kind == "paragraph":
            if not context["paragraph"] or block is None:
                block = {"kind": kind}
        elif kind != "html":
            block = {"kind": kind}
        context["paragraph"] = kind == "paragraph"
        context["block"] = block
        yield original, code, offsets[offset], block


def markdown_lines(source):
    """Yield lines with code and raw HTML blocks marked as opaque."""
    for line, code, _, block in markdown_blocks(source):
        yield line, code or block["kind"] == "html"


def pin_markdown_links(body, version, repository_url):
    """Pin CommonMark destinations while preserving all other source bytes."""
    def mask(text):
        return re.sub(r"[^\n]", " ", text)

    pieces, lines, blocks = [], [], []
    offset = 0
    for line, code, content, block in markdown_blocks(body):
        lines.append((offset, offset + content, offset + len(line), block))
        pieces.append(mask(line) if code else " " * content + line[content:])
        if blocks and blocks[-1][2] is block:
            blocks[-1] = blocks[-1][0], offset + len(line), block
        else:
            blocks.append((offset, offset + len(line), block))
        offset += len(line)
    visible = "".join(pieces)
    replacements = []

    def pinned(target, image, html=False):
        original = target
        target = unescape(target)
        if not html:
            target = re.sub(r"\\([" + re.escape(string.punctuation) + r"])", r"\1", target)
        if target.startswith(("#", "//")) or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", target):
            return original
        if target.startswith("?"):
            raise ValueError("CHANGELOG.md has an invalid relative link: " + target)
        path, fragment_mark, fragment = target.partition("#")
        path, query_mark, query = path.partition("?")
        segments = []
        for part in path.lstrip("/").split("/"):
            dots = re.sub("%2e", ".", part, flags=re.I)
            if dots == "..":
                if not segments:
                    raise ValueError("CHANGELOG.md link escapes the repository: " + target)
                segments.pop()
            elif dots != "." and part:
                segments.append(part)
        path = "/".join(segments) or "."
        target = path + query_mark + query + fragment_mark + fragment
        target = "".join(quote(char, safe="") if ord(char) <= 32 or ord(char) == 127 or char in "<>()\\\"'`" else char
                         for char in target)
        if html:
            target = target.replace("&", "&amp;")
        return repository_url.rstrip("/") + ("/raw/v" if image else "/blob/v") + version + "/" + target

    def pin_html(start, end):
        source = visible[start:end]
        line_starts = [0] + [match.end() for match in re.finditer("\n", source)]
        attributes = re.compile(r"[ \t\r\n]+(" + HTML_NAME + r")[ \t\r\n]*=[ \t\r\n]*(" + HTML_VALUE + ")")

        class Attributes(HTMLParser):
            # Browser raw-text elements cannot contain nested HTML attributes.
            CDATA_CONTENT_ELEMENTS = ("script", "style", "textarea")

            def handle_starttag(self, tag, attrs):
                line, column = self.getpos()
                offset = start + line_starts[line - 1] + column
                for attr in attributes.finditer(self.get_starttag_text()):
                    if attr[1].lower() not in ("href", "src"):
                        continue
                    a, b = offset + attr.start(2), offset + attr.end(2)
                    if body[a] in "\"'":
                        a, b = a + 1, b - 1
                    replacements.append((a, b, pinned(body[a:b], attr[1].lower() == "src", html=True)))

        parser = Attributes(convert_charrefs=False)
        parser.feed(source)
        parser.close()

    # Block HTML has no Markdown inlines, even when it contains Markdown fences.
    for start, end, block in blocks:
        if block["kind"] == "html":
            pin_html(start, end)
            visible = visible[:start] + mask(visible[start:end]) + visible[end:]

    title = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\((?:\\.|[^()\\])*\))'''

    def label(value):
        return " ".join(value.split()).casefold()

    def destination(start, limit):
        if start >= limit:
            return None
        if visible[start] == "<":
            end = start + 1
            while end < limit:
                if visible[end] == "\\" and end + 1 < limit and visible[end + 1] in string.punctuation:
                    end += 2
                    continue
                if visible[end] == ">":
                    return start + 1, end, end + 1
                if visible[end] in "\r\n<":
                    return None
                end += 1
            return None
        end, depth = start, 0
        while end < limit:
            char = visible[end]
            if char == "\\" and end + 1 < limit and visible[end + 1] in string.punctuation:
                end += 2
                continue
            if char in " \t\n\r\f\v" or (char == ")" and depth == 0):
                break
            if ord(char) < 32 or char == "<":
                return None
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            end += 1
        return (start, end, end) if depth == 0 else None

    definitions = {}
    allowed = {start for start, _, block in blocks if block["kind"] == "paragraph"}
    for line_start, content, line_end, block in lines:
        if line_start not in allowed:
            continue  # CommonMark §4.7: definitions cannot interrupt paragraphs.
        match = re.match(r" {0,3}\[((?!\^)(?:\\.|[^\]\\])+)\]:[ \t]*", visible[content:line_end])
        if not match:
            continue
        start = content + match.end()
        limit = next(end for begin, end, other in blocks if other is block)
        if visible[start:start + 1] == "\n":
            start += 1
            while start < limit and visible[start] in " \t":
                start += 1
        found = destination(start, limit)
        if not found or found[0] == found[1]:
            continue
        start, finish, after = found
        ending = re.match(r"[ \t]*(?:\n[ \t]*)?" + title + r"[ \t]*(?:\n|$)", visible[after:limit])
        if ending is None:
            ending = re.match(r"[ \t]*(?:\n|$)", visible[after:limit])
        if ending is None:
            continue
        end = after + ending.end()
        if re.search(r"\n[ \t]*\n", visible[line_start:end].rstrip("\n")):
            continue
        key = label(body[content + match.start(1):content + match.end(1)])
        definitions.setdefault(key, []).append((start, finish))
        visible = visible[:line_start] + mask(visible[line_start:end]) + visible[end:]
        allowed.add(end)

    uses = {}
    for begin, limit, block in blocks:
        # CommonMark §§3.1, 6.1, 6.3–6.6 / Appendix: consume in source
        # order, so code/HTML inside a destination is never parsed as link text.
        # An iterative stack lets inner links deactivate earlier link openers
        # without disabling image openers or recursing on nested brackets.
        stack = []
        generation = 0
        cursor = begin
        while cursor < limit:
            char = visible[cursor]
            if char == "\\" and cursor + 1 < limit and visible[cursor + 1] in string.punctuation:
                cursor += 2
                continue
            if char == "`":
                opening = re.match(r"`+", visible[cursor:limit])
                end = cursor + opening.end()
                closing = next((run for run in re.finditer(r"`+", visible[end:limit]) if len(run[0]) == len(opening[0])), None)
                cursor = end + closing.end() if closing else end
                continue
            if char == "<":
                token = HTML_TOKEN.match(visible, cursor, limit)
                if token:
                    pin_html(cursor, token.end())
                    cursor = token.end()
                    continue
                autolink = re.match(r"<(?:[A-Za-z][A-Za-z0-9+.-]{1,31}:[^<>\x00-\x20]*|"
                                    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
                                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                                    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)>", visible[cursor:limit])
                if autolink:
                    cursor += autolink.end()
                    generation += 1
                    continue
            if visible.startswith("![", cursor):
                stack.append((cursor + 1, True, generation))
                cursor += 2
                continue
            if char == "[":
                stack.append((cursor, False, generation))
                cursor += 1
                continue
            if char != "]" or not stack:
                cursor += 1
                continue
            opening, image, opened = stack.pop()
            end = cursor + 1
            cursor = end
            if not image and opened != generation:
                continue
            matched = False
            if visible[end:end + 1] == "(":
                start = end + 1
                while start < limit and visible[start] in " \t\n\r\f\v":
                    start += 1
                found = destination(start, limit)
                if found:
                    start, finish, after = found
                    closing = re.match(r"(?:[ \t\n\r\f\v]+" + title + r")?[ \t\n\r\f\v]*\)", visible[after:limit])
                    if closing:
                        replacements.append((start, finish, pinned(body[start:finish], image)))
                        cursor, matched = after + closing.end(), True
            if not matched:
                reference = re.match(r"\[((?:\\.|[^\[\]\\])*)\]", visible[end:limit])
                key = label(body[end + 1:end + reference.end() - 1] if reference and reference[1]
                            else body[opening + 1:end - 1])
                if key in definitions:
                    uses.setdefault(key, set()).add(image)
                    matched = True
                    if reference:
                        cursor = end + reference.end()
            if matched and not image:
                generation += 1

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
