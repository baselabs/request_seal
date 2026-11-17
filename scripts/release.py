#!/usr/bin/env python3
"""Release identity and reproducible SBOM metadata shared by repository gates."""
import argparse
import base64
import datetime
import hashlib
from http.client import HTTPConnection, HTTPSConnection, HTTPException, IncompleteRead
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from html import unescape
import json
import os
from pathlib import Path
import posixpath
import re
import ssl
import subprocess
import time
import uuid
from urllib.parse import quote, unquote, urljoin, urlsplit
from urllib.request import getproxies, proxy_bypass
from processes import install_signal_handlers, run

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


# A conservative lexical contract, not a general Markdown parser.
DESTINATION = r"(?:<[^<>\s]*>|[^\s()<>]*)"
TITLE = r"(?:\"[^\"\n]*\"|'[^'\n]*')"
INLINE_START = re.compile(r"\]\s*\(")
INLINE = re.compile(r"\]\((" + DESTINATION + r")(?:(?:[ \t]+)" + TITLE + r")?\)")
REFERENCE_START = re.compile(r"\[([^\]\n]*)\][ \t]*:")
REFERENCE = re.compile(r"[ \t]+(" + DESTINATION + r")(?:(?:[ \t]+)" + TITLE + r")?[ \t]*(?=\n|$)")
URL_ATTRIBUTE = re.compile(r"\b(?:href|src)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s<>]*))", re.I)
RAW_HTML = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?=[\s/>]|$)|<![A-Za-z\[]|<\?")
AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^<>\x00-\x20]*)>")
EMAIL_AUTOLINK = re.compile(r"<([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
                            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)>")
# CommonMark inline HTML (inlines.c: handle_pointy_brace). Quoted attribute
# values may contain backticks and angle brackets; they are one inline token.
HTML_INLINE = re.compile(
    r"</[A-Za-z][A-Za-z0-9-]*\s*>|"
    r"<[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*"
    r"(?:\s*=\s*(?:[^\s\"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*\s*/?>|"
    r"<!--(?:[^-]|-(?!->))*-->|<\?.*?\?>|<![A-Z]+\s+[^>]*>|<!\[CDATA\[.*?\]\]>", re.S)
BARE_URL = re.compile(r"(?:https?://|www\.)[^\x09-\x0d\x20<]*", re.I)
# Outside Markdown, quotes delimit source/JSON strings rather than GFM autolinks.
TEXT_URL = re.compile(r"(?:https?://|www\.)[^\x09-\x0d\x20<>\"'`]*", re.I)
FENCE = re.compile(r"([ \t>+*.0-9()-]*(?:\[[ xX]\][ \t]*)?)(`{3,}|~{3,})(.*)$")
DESTINATION_DEADLINE = 180
# https://github.com/github/markup#markups and its registered markup extensions.
MARKDOWN_SUFFIXES = (".md", ".markdown", ".mdown", ".mkdn", ".mkd", ".mdwn", ".mdx", ".litcoffee", ".livemd")
RENDERED_MARKUP = MARKDOWN_SUFFIXES + (
    ".textile", ".rdoc", ".org", ".creole", ".mediawiki", ".wiki", ".rst", ".rest",
    ".rst.txt", ".rest.txt", ".asciidoc", ".adoc", ".asc", ".pod", ".pod6",
)

GITHUB_ASSET_HOSTS = {"github-cloud.githubusercontent.com", "objects.githubusercontent.com",
                      "objects-origin.githubusercontent.com", "release-assets.githubusercontent.com",
                      "github-releases.githubusercontent.com", "github-cloud.s3.amazonaws.com"}
HEX_HOSTS = {"hex.pm", "diff.hex.pm", "preview.hex.pm", "repo.hex.pm"}


def escaped(source, offset):
    start = offset
    while start and source[start - 1] == "\\":
        start -= 1
    return (offset - start) % 2 == 1


def table_cells(text):
    # cmark-gfm ext_scanners.re: _scan_table_cell keeps backslash-pipe
    # together, even when another backslash precedes the escaping one.
    pipes = [match.start() for match in re.finditer(r"\|", text)
             if not match.start() or text[match.start() - 1] != "\\"]
    bounds = [-1, *pipes, len(text)]
    spans = [(left + 1, right) for left, right in zip(bounds, bounds[1:])]
    if pipes and not text[:pipes[0]].strip():
        spans.pop(0)
    if pipes and not text[pipes[-1] + 1:].strip():
        spans.pop()
    return spans


def table_delimiter(text):
    # table.c: try_opening_table_block rejects an indented delimiter;
    # try_opening_table_header requires exactly the header's column count.
    if len(text.expandtabs(4)) - len(text.expandtabs(4).lstrip()) > 3:
        return []
    columns = table_cells(text)
    return columns if ("|" in text or ":" in text) and columns and all(
        re.fullmatch(r"[ \t]*:?-+:?[ \t]*", text[a:b]) for a, b in columns) else []


def container_content(text):
    """Recognize prefixes for rejection, without pretending to parse containers."""
    original = text
    while prefix := re.match(r"[ \t]*(?:>[ \t]?|(?:[-+*]|[0-9]{1,9}[.)])[ \t]+)", text):
        text = text[prefix.end():]
    return text, text != original


def markdown_ambiguities(source):
    """Reject block combinations whose container state is not modeled here."""
    lines = source.splitlines(keepends=True)
    blocks = masked_code(source, spans=False).splitlines(keepends=True)
    container = False
    footnote = False
    table_columns = 0
    offset = 0
    previous = ""
    previous_quote = False
    for index, (original, block) in enumerate(zip(lines, blocks)):
        text = block.rstrip("\r\n")
        content, prefixed = container_content(text)
        raw_content, raw_prefix = container_content(original.rstrip("\r\n"))
        if re.match(r" {0,3}\[(?:\\.|[^\]\\])*\Z", text):
            yield offset, "ambiguous multiline reference label"
        marker = re.match(r" {0,3}(`{3,})(.*)$", text)
        if marker and "`" in marker[2]:
            yield offset, "ambiguous backtick fence info string"
        definition = REFERENCE_START.match(content.lstrip())
        is_footnote = definition is not None and definition[1].startswith("^")
        # Container fences cannot be interpreted by the top-level code masker.
        if text.strip() and raw_prefix and re.match(r"[ \t]*(?:`{3,}|~{3,})", raw_content):
            yield offset, "ambiguous code fence in a container"
        if prefixed:
            container = True
        elif not previous.strip() and text.strip() and not text[0].isspace():
            container = False
        if container and re.fullmatch(r"[ \t]*(?:=+|-+)[ \t]*", content):
            yield offset, "ambiguous setext heading in a container or lazy continuation"
        quote = bool(re.match(r" {0,3}>", text))
        if previous_quote and text.strip() and not quote and previous.strip():
            yield offset, "ambiguous lazy continuation of a block quote"
        if quote and len(raw_content.expandtabs(4)) - len(raw_content.expandtabs(4).lstrip()) >= 4:
            yield offset, "ambiguous indented code in a block quote"
        if index + 1 < len(lines) and text.strip():
            following, next_prefix = container_content(lines[index + 1].rstrip("\r\n"))
            if (container or prefixed or next_prefix or footnote or is_footnote) and table_delimiter(following.lstrip()):
                yield offset, "ambiguous table in a container (list, block quote, or footnote)"
        if definition and (prefixed or container):
            yield offset, f"ambiguous reference definition in a container: {original.strip()!r}"
        if definition and not is_footnote:
            if "`" in content:
                yield offset, "ambiguous backticks in a link reference definition"
            if index + 1 < len(lines) and lines[index + 1].lstrip().startswith(('"', "'", "(")):
                yield offset, "ambiguous multiline link reference definition"
        if is_footnote:
            body = content.lstrip()[definition.end():].lstrip()
            _, nested = container_content(body)
            if nested or REFERENCE_START.match(body):
                yield offset, "ambiguous nested block in a footnote definition"
        if footnote and original.strip() and not is_footnote:
            if previous.strip() or original.startswith(("    ", "\t")):
                yield offset, f"ambiguous reference definition or footnote continuation: {original.strip()!r}"
            else:
                footnote = False
        if is_footnote:
            footnote = True
        if (not text.strip() or prefixed or is_footnote
                or re.match(r" {0,3}#{1,6}(?:[ \t]|$)", text)
                or re.fullmatch(r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})", text)):
            table_columns = 0
        if table_columns and len(table_cells(text)) > table_columns:
            yield offset, "ambiguous table row with excess cells"
        if table_columns and text.strip() and len(text.expandtabs(4)) - len(text.expandtabs(4).lstrip()) >= 4:
            yield offset, "ambiguous indented code after a table"
        if not container and not footnote and index + 1 < len(lines) and text.strip():
            columns = table_delimiter(lines[index + 1].rstrip("\r\n"))
            if columns and len(table_cells(text)) == len(columns):
                table_columns = len(columns)
        previous = original
        previous_quote = quote
        offset += len(original)


def inline_blocks(source):
    """Inline parsing cannot pair delimiters across paragraph/container boundaries."""
    lines = source.splitlines(keepends=True)
    start = offset = 0
    previous_quote = None
    table_quote = None
    delimiter_row = False
    paragraph = False
    for index, line in enumerate(lines):
        text = line.rstrip("\r\n")
        quote = re.match(r"(?: {0,3}>[ \t]?)*", text)[0]
        content = text[len(quote):]
        item = re.match(r"[ \t]*(?:[-+*]|[0-9]{1,9}[.)])[ \t]+", content)
        heading = re.match(r" {0,3}#{1,6}(?:[ \t]|$)", content)
        thematic = re.fullmatch(r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})", content)
        footnote = re.match(r" {0,3}\[\^[^\]\n]+\]:", content)
        if not content.strip() or item or heading or thematic or footnote or quote.count(">") != table_quote:
            table_quote = None
        # cmark-gfm table.c: try_opening_table_header requires equal column
        # counts; row_from_string/contains_inlines give each cell its own parse.
        header = False
        if table_quote is None and content.strip() and not heading and index + 1 < len(lines):
            next_text = lines[index + 1].rstrip("\r\n")
            next_quote = re.match(r"(?: {0,3}>[ \t]?)*", next_text)[0]
            delimiter = next_text[len(next_quote):]
            columns = table_delimiter(delimiter)
            if (quote.count(">") == next_quote.count(">") and ("|" in delimiter or ":" in delimiter)
                    and columns and len(table_cells(content)) == len(columns)):
                table_quote = quote.count(">")
                delimiter_row = False
                header = True
        if table_quote is not None:
            if start < offset:
                yield start, offset
            if not delimiter_row:
                for left, right in table_cells(content):
                    yield offset + len(quote) + left, offset + len(quote) + right
            delimiter_row = header
            offset += len(line)
            start = offset
            previous_quote = quote.count(">")
            paragraph = False
            continue
        # cmark-gfm blocks.c: open_new_blocks accepts setext only while a
        # paragraph is open; a standalone === line starts paragraph text.
        setext = paragraph and re.fullmatch(r" {0,3}(?:=+|-+)[ \t]*", content)
        ending = (not content.strip() or heading or
                  setext or
                  thematic)
        if (item or heading or footnote or quote.count(">") != previous_quote or not content.strip()) and start < offset:
            yield start, offset
            start = offset
        offset += len(line)
        if ending:
            yield start, offset
            start = offset
        previous_quote = quote.count(">")
        paragraph = not ending
    if start < offset:
        yield start, offset


def masked_code(source, *, spans=True):
    """Keep offsets/newlines while hiding blocks and optionally matched spans."""
    chars = list(source)

    def hide(start, end):
        chars[start:end] = ["\n" if char == "\n" else " " for char in source[start:end]]

    offset, fence, indented, blank = 0, None, False, True
    list_indents = []
    for line in source.splitlines(keepends=True):
        text = line.rstrip("\r\n")
        expanded = text.expandtabs(4)
        indentation = len(expanded) - len(expanded.lstrip(" "))
        item = re.match(r" *(?:[-+*]|[0-9]{1,9}[.)])[ \t]+", expanded)
        if text.strip() and (blank or item):
            while list_indents and indentation < list_indents[-1]:
                list_indents.pop()
        base = list_indents[-1] if list_indents else 0
        marker = re.match(r" {0,3}(`{3,}|~{3,})(.*)$", text)
        if fence:
            hide(offset, offset + len(line))
            if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", text):
                fence = None
        elif marker and not (marker[1].startswith("`") and "`" in marker[2]):
            fence = marker[1]
            hide(offset, offset + len(line))
        elif (indented or blank) and text.strip() and indentation >= base + 4:
            indented = True
            hide(offset, offset + len(line))
        else:
            indented = indented and not text.strip()
            if item and indentation < base + 4:
                list_indents.append(item.end())
        blank = not text.strip()
        offset += len(line)
    visible = "".join(chars)
    if not spans:
        return visible
    for beginning, finish in inline_blocks(visible):
        cursor = beginning
        brackets = []
        while cursor < finish:
            # inlines.c: parse_inline/handle_pointy_brace/handle_backticks
            # consume the first construct by position. autolink.c: url_match
            # also consumes a bare URL before a later backtick can open code.
            token = re.search(r"[<`\[\]]|https?://|www\.", visible[cursor:finish], re.I)
            if token is None:
                break
            absolute = cursor + token.start()
            if visible[absolute] in "[]" and not escaped(visible, absolute):
                if visible[absolute] == "[":
                    brackets.append(absolute)
                elif brackets:
                    brackets.pop()
                    link = INLINE.match(visible, absolute, finish)
                    if link:
                        cursor = link.end()
                        continue
            if visible[absolute] == "<" and not escaped(visible, absolute):
                angle = (AUTOLINK.match(visible, absolute, finish) or
                         EMAIL_AUTOLINK.match(visible, absolute, finish) or
                         HTML_INLINE.match(visible, absolute, finish))
                if angle:
                    cursor = angle.end()
                    continue
            url = BARE_URL.match(visible, absolute, finish)
            # autolink.c: match returns NULL while in_bracket is true. This
            # also changes which backticks are available to open a code span.
            if url and not brackets:
                cursor = url.end()
                continue
            if visible[absolute] != "`":
                cursor = absolute + 1
                continue
            opening = re.match(r"`+", visible[absolute:finish])
            # cmark-gfm inlines.c: handle_backslash consumes one backtick;
            # handle_backticks can then open with the rest of the run.
            opening_start = absolute + int(escaped(visible, absolute))
            length = absolute + opening.end() - opening_start
            cursor = absolute + opening.end()
            if not length:
                continue
            closing = next((run for run in re.finditer(r"`+", visible[cursor:finish])
                            if len(run[0]) == length), None)
            if closing is not None:
                cursor += closing.end()
                hide(opening_start, cursor)
    return "".join(chars)


def bare_destination(target):
    """GFM extended-autolink trailing punctuation, parentheses, and entities."""
    # cmark-gfm extensions/autolink.c: autolink_delim trims quotes and ';'.
    # Its cmark_isalpha scan removes only &[A-Za-z]+;, not digits or '#'.
    while True:
        trimmed = target.rstrip("?!.,:*_~'\"")
        if trimmed.endswith(")") and trimmed.count(")") > trimmed.count("("):
            trimmed = trimmed[:-1]
        if trimmed.endswith(";"):
            entity = re.search(r"&[A-Za-z]+;$", trimmed)
            trimmed = trimmed[:entity.start()] if entity else trimmed[:-1]
        if trimmed == target:
            return target
        target = trimmed


def extract_destinations(source, strict=False, markdown=True):
    """One extractor for links, definitions, attributes, autolinks and bare URLs.

    Entries are (source offset, literal destination, ambiguous syntax). Code is
    hidden only for Markdown; tracked JSON and other text retain literal URLs.
    """
    visible = masked_code(source) if markdown else source
    contexts = list(inline_blocks(visible)) if markdown else [(0, len(visible))]
    entries, occupied = [], []
    bracket_ranges = []

    def reject(offset, reason):
        if strict:
            raise ValueError(f"line {1 + source.count(chr(10), 0, offset)}: {reason}")
        entries.append((offset, reason, True))

    if markdown:
        for offset, reason in markdown_ambiguities(source):
            reject(offset, reason)

    def add(start, end, target, ambiguous=False):
        entries.append((start, target[1:-1] if target.startswith("<") and target.endswith(">") else target, ambiguous))
        occupied.append((start, end))

    if markdown:
        previous_definition, previous_boundary, paragraph = False, True, False
        definitions, used_definitions = {}, set()
        footnote_definitions, used_footnotes = {}, set()
        offset = 0
        # Code spans still count as paragraph content for a setext heading;
        # fenced/indented code does not. Keep that block view before masking spans.
        block_lines = masked_code(source, spans=False).splitlines(keepends=True)
        for original, line, block_line in zip(source.splitlines(keepends=True), visible.splitlines(keepends=True), block_lines):
            definition = REFERENCE_START.search(line)
            if definition:
                prefix = line[:definition.start()]
                # cmark-gfm blocks.c: open_new_blocks permits footnote
                # definitions to interrupt a paragraph, unlike link references.
                footnote = definition[1].startswith("^")
                valid = prefix in ("", " ", "  ", "   ") and (footnote or previous_boundary or previous_definition)
                match = REFERENCE.match(line.rstrip("\r\n"), definition.end())
                if strict and not valid:
                    raise ValueError(f"line {1 + source.count(chr(10), 0, offset)}: ambiguous reference definition {original.strip()!r}")
                if footnote:
                    # Footnote bodies are prose, not link destinations. Their URLs
                    # still pass through the ordinary inline/autolink scan below.
                    # The body opens a paragraph, not a link-definition boundary.
                    previous_definition = False
                    footnote_definitions[reference_label(definition[1])] = offset + definition.start()
                else:
                    add(offset + definition.start(), offset + len(line),
                        match[1] if match else line[definition.end():].strip(), not valid or match is None)
                    previous_definition = valid and match is not None
                    if previous_definition:
                        definitions[reference_label(definition[1])] = offset + definition.start()
            else:
                previous_definition = False
            # cmark-gfm blocks.c: open_new_blocks requires an open paragraph
            # before scan_setext_heading_line can create a heading.
            setext = paragraph and re.fullmatch(r" {0,3}(?:=+|-+)[ \t]*", block_line.rstrip("\r\n")) is not None
            previous_boundary = (not block_line.strip() or
                                 re.match(r" {0,3}#{1,6}(?:[ \t]|$)", block_line) is not None or
                                 setext or
                                 re.fullmatch(r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})", block_line.rstrip("\r\n")) is not None)
            paragraph = bool(block_line.strip()) and not previous_boundary and not previous_definition
            offset += len(line)
        for beginning, finish in contexts:
            # inlines.c: handle_close_bracket's delimiter stack. A successful
            # link deactivates earlier link openers; images remain eligible.
            stack = []
            cursor = beginning
            while cursor < finish:
                token = re.search(r"[\[\]<]", visible[cursor:finish])
                if token is None:
                    break
                offset = cursor + token.start()
                cursor = offset + 1
                if escaped(visible, offset) or any(a <= offset < b for a, b in occupied):
                    continue
                if token[0] == "<":
                    angle = (AUTOLINK.match(visible, offset, finish) or
                             EMAIL_AUTOLINK.match(visible, offset, finish) or
                             HTML_INLINE.match(visible, offset, finish))
                    if angle:
                        cursor = angle.end()
                    continue
                if token[0] == "[":
                    image = offset > beginning and visible[offset - 1] == "!" and not escaped(visible, offset - 1)
                    stack.append([offset, True, image])
                    continue
                if not stack:
                    continue
                opening, active, image = stack.pop()
                bracket_ranges.append((opening, cursor))
                if not active:
                    continue
                name = reference_label(visible[opening + 1:offset])
                if name in footnote_definitions and not visible[cursor:finish].startswith(":"):
                    used_footnotes.add(name)
                start = INLINE_START.match(visible, offset, finish)
                match = INLINE.match(visible, offset, finish) if start else None
                if start:
                    candidate = visible[start.end():finish].split("\n", 1)[0].split(")", 1)[0]
                    add(opening, match.end() if match else start.end(), match[1] if match else candidate, match is None)
                    cursor = match.end() if match else start.end()
                else:
                    label = re.match(r"\[([^\[\]\n]*)\]", visible[cursor:finish])
                    name = label[1] if label and label[1] else visible[opening + 1:offset]
                    if reference_label(name) not in definitions:
                        continue
                    used_definitions.add(reference_label(name))
                    if label:
                        cursor += label.end()
                    occupied.append((opening, cursor))
                if not image:
                    for opener in stack:
                        if not opener[2]:
                            opener[1] = False
            # Unclosed brackets still suppress the extended-autolink extension
            # through the remainder of this inline context (autolink.c: match).
            bracket_ranges.extend((opening, finish) for opening, _, _ in stack)
        for label in sorted(definitions.keys() - used_definitions, key=definitions.get):
            for index, (offset, target, ambiguous) in enumerate(entries):
                if offset == definitions[label] and not ambiguous:
                    entries[index] = (offset, target, f"ambiguous unused link reference definition {label!r}")
        for label in sorted(footnote_definitions.keys() - used_footnotes, key=footnote_definitions.get):
            reject(footnote_definitions[label], f"ambiguous unused footnote definition {label!r}")
    for match in URL_ATTRIBUTE.finditer(visible):
        add(match.start(), match.end(), unescape(next(value for value in match.groups() if value is not None)))
    for match in (match for beginning, finish in contexts
                  for pattern in (AUTOLINK, EMAIL_AUTOLINK) for match in pattern.finditer(visible, beginning, finish)):
        if markdown and escaped(visible, match.start()):
            continue
        if not any(start <= match.start() < end for start, end in occupied):
            target = ("mailto:" if "@" in match[1] and ":" not in match[1] else "") + match[1]
            # cmark-gfm houdini_href_escape encodes unsafe href characters.
            # Keep literal destinations only; the gate does not silently
            # validate a different, encoded URL on the author's behalf.
            if markdown and quote(unescape(target), safe="/:#?@!$&'()*+,;=-._~%") != target:
                reject(match.start(), "ambiguous autolink destination encoding")
            add(match.start(), match.end(), target)
    for beginning, finish in contexts:
        cursor = beginning
        while match := (BARE_URL if markdown else TEXT_URL).search(visible, cursor, finish):
            containing = max((end for start, end in occupied + bracket_ranges
                              if start <= match.start() < end), default=None)
            if containing is not None:
                # Restart after the consumed link rather than after a bare-URL
                # candidate that may extend beyond it into another destination.
                cursor = containing
                continue
            # autolink.c: www_match checks the preceding source character;
            # url_match rewinds the complete alphabetic scheme before ':'.
            if markdown and match.start() > beginning:
                previous = source[match.start() - 1]
                if (match[0].lower().startswith("www.") and previous not in "*_~(\t\n\r\f\v "
                        or not match[0].lower().startswith("www.") and previous.isascii() and previous.isalpha()):
                    cursor = match.start() + 1
                    continue
            target = bare_destination(match[0])
            reason = ("ambiguous destination encoding in an extended autolink; use a canonical literal URL"
                      if markdown and quote(target, safe="/:#?@!$&'()*+,;=-._~%") != target else False)
            add(match.start(), match.end(), target, reason)
            cursor = match.end()
    return sorted(entries)


def first_party(url):
    """Recognize repository/package content even on redirecting or alternate hosts."""
    host = unquote(url.hostname or "").lower().rstrip(".").removeprefix("www.")
    decoded = "/" + unquote(url.path).lstrip("/")
    paths = (decoded.lower(), posixpath.normpath(decoded).lower())
    if host in ("request-seal.hexdocs.pm", "request_seal.hexdocs.pm"):
        return "hexdocs"
    if host == "hexdocs.pm" and any(re.match(r"/request[-_]seal(?:/|$)", path) for path in paths):
        return "hexdocs"
    if host in GITHUB_ASSET_HOSTS:
        return "github"  # Opaque asset URLs cannot establish a stable repository ref.
    if host == "baselabs.github.io" and any(re.match(r"/request[-_]seal(?:/|$)", path) for path in paths):
        return "github"
    if host == "github.com" or host.endswith((".github.com", ".githubusercontent.com")):
        if any(re.search(r"(?:^|/)baselabs/request[-_]seal(?:[/.]|$)", path) for path in paths):
            return "github_raw" if host in {"raw.github.com", "raw.githubusercontent.com", "media.githubusercontent.com"} else "github"
    if host in HEX_HOSTS and (any(re.search(r"(?:^|/)request[-_]seal(?:[-/.]|$)", path) for path in paths)
                              or re.search(r"(?:^|[=&/])request[-_]seal(?:[=&/]|$)", unquote(url.query).lower())):
        return "hex"
    return None


def canonical_forms(version=None):
    version = version or "<version>"
    hosts = {"hexdocs": "request-seal.hexdocs.pm", "github": "github.com",
             "github_raw": "raw.githubusercontent.com", "hex": "hex.pm"}
    paths = {"hexdocs": f"/{version}/<page>", "github": f"/baselabs/request_seal/blob/v{version}/<path>",
             "github_raw": f"/baselabs/request_seal/v{version}/<path>", "hex": f"/packages/request_seal/{version}"}
    return {kind: f"https://{host}{paths[kind]}" for kind, host in hosts.items()}


def first_party_syntax(url, kind, version=None):
    host = {"hexdocs": "request-seal.hexdocs.pm", "github": "github.com",
            "github_raw": "raw.githubusercontent.com", "hex": "hex.pm"}[kind]
    prefix = "/" if kind == "hexdocs" else "/packages/request_seal" if kind == "hex" else "/baselabs/request_seal"
    if (url.scheme != "https" or url.netloc != host or (url.path and not url.path.startswith(prefix))
            or "%" in url.path or any(part in (".", "..") for part in url.path.split("/"))
            or url.query or "?" in url.geturl().split("#", 1)[0]):
        raise ValueError("first-party destination requires canonical literal HTTPS host/path, "
                         "no query string, dot segments, credentials, or port; canonical form: "
                         + canonical_forms(version)[kind])


def classify_destination(target, version=None, released=False):
    """Shared first-party forms; release notes additionally bind versioned targets."""
    url = urlsplit("https://" + target if target.lower().startswith("www.") else target)
    kind = first_party(url)
    if not kind:
        return None
    canonical = canonical_forms(version if released else None)[kind]
    if not target.startswith("https://") or re.search(r"[^\x21-\x7e]|[<>\\\"'`]", target):
        raise ValueError("first-party destination requires a literal canonical HTTPS URL; canonical form: " + canonical)
    if "?" in target.split("#", 1)[0]:
        raise ValueError("first-party destination allows no query string; canonical form: " + canonical)
    first_party_syntax(url, kind, version if released else None)
    result = {"kind": kind, "version": None, "ref": None, "path": "", "fragment": url.fragment}
    if "#" in target and not url.fragment:
        raise ValueError("first-party destination requires a nonempty fragment; canonical form: " + canonical)
    if kind == "hexdocs":
        parts = url.path.lstrip("/").split("/", 1)
        if len(parts) == 2 and SEMVER.fullmatch(parts[0]):
            result.update(version=parts[0], path=parts[1] or "index.html")
        elif not released and (url.path in ("", "/") or len(parts) == 1 and parts[0].endswith(".html")):
            result.update(path=parts[0] or "index.html")
        else:
            raise ValueError("HexDocs destination requires an explicit version and page or trailing slash; canonical form: " + canonical)
    elif kind == "hex":
        suffix = url.path.removeprefix("/packages/request_seal")
        if suffix.startswith("/") and SEMVER.fullmatch(suffix[1:]):
            result.update(kind="hex_package", version=suffix[1:])
        elif suffix == "" and not released:
            result.update(kind="hex_package")
        else:
            raise ValueError("canonical package form: " + canonical)
    else:
        suffix = url.path.removeprefix("/baselabs/request_seal")
        if kind == "github" and re.fullmatch(r"/(?:issues|pull)/[1-9][0-9]*", suffix):
            result.update(kind="github_live")
        elif kind == "github" and re.fullmatch(r"/compare/v[^/]+[.]{3}v[^/]+", suffix):
            before, after = suffix.removeprefix("/compare/v").split("...v")
            parse_version(before)
            parse_version(after)
            result.update(kind="github_compare", ref="v" + before, version=after)
        elif kind == "github" and re.fullmatch(r"/security/advisories/GHSA-[a-z0-9-]+", suffix):
            result.update(kind="github_live")
        elif kind == "github" and not released and suffix in ("", "/security"):
            result.update(kind="github_live")
        else:
            prefix = "/blob/" if kind == "github" else "/"
            parts = suffix.removeprefix(prefix).split("/", 1) if suffix.startswith(prefix) else []
            if len(parts) != 2 or not all(parts) or not (parts[0] == "main" or parts[0].startswith("v") and SEMVER.fullmatch(parts[0][1:])):
                raise ValueError("canonical source form: " + canonical + "; raw assets use " + canonical_forms(version)["github_raw"])
            result.update(ref=parts[0], path=parts[1], version=parts[0][1:] if parts[0] != "main" else None)
            if url.fragment and (kind != "github" or not re.fullmatch(r"L[1-9][0-9]*(?:-L[1-9][0-9]*)?", url.fragment)):
                raise ValueError("GitHub source fragment requires #L<n> or #L<n>-L<m>; canonical form: " + canonical)
            if url.fragment and result["path"].lower().endswith(RENDERED_MARKUP):
                raise ValueError("GitHub line fragments do not select lines in rendered markup; canonical form: " + canonical + " (without a line fragment)")
    if result["path"] and (result["path"].endswith("/") or any(part.startswith(".") or not part for part in result["path"].split("/"))):
        raise ValueError("first-party link targets a private or unsafe path; canonical form: " + canonical)
    if url.fragment and result["kind"] not in ("hexdocs", "github"):
        raise ValueError("first-party destination does not allow a fragment; canonical form: " + canonical)
    if released and result["kind"] not in ("github_live",) and result["version"] != version:
        raise ValueError(f"first-party destination must use version {version}; canonical form: {canonical}")
    return result


def validate_destination(target, version):
    """Validate literal authoring syntax and the shared canonical forms."""
    classified = classify_destination(target, version, released=True)
    if (not target or re.search(r"[^\x21-\x7e]|[<>\\\"'`]", target)
            or re.search(r"&(?:#\w+|[A-Za-z][A-Za-z0-9]*);|%(?![0-9A-Fa-f]{2})", target)):
        raise ValueError("requires a literal absolute URL; ambiguous destination syntax")
    url = urlsplit("https://" + target if target.lower().startswith("www.") else target)
    if url.scheme in ("http", "https"):
        if not url.hostname or url.username is not None or url.password is not None:
            raise ValueError("requires an absolute HTTP(S) URL without credentials")
        if "%" in url.hostname or url.hostname.endswith(".") or ".." in url.hostname:
            raise ValueError("requires an unambiguous literal hostname")
        if url.port is not None and not 0 < url.port < 65536:
            raise ValueError("invalid URL port")
    elif url.scheme == "mailto":
        if not re.fullmatch(r"[^@/?#]+@[^@/?#]+", url.path) or url.netloc:
            raise ValueError("requires an absolute mailto URL")
    else:
        raise ValueError("unsupported URL scheme; requires an absolute HTTP(S) or mailto URL")
    return classified["kind"] if classified else None


def source_fragment_errors(fragment, data):
    if not fragment:
        return []
    numbers = [int(value) for value in re.findall(r"[0-9]+", fragment)]
    count = len(data.splitlines())
    if not numbers or numbers[0] > numbers[-1] or numbers[-1] > count:
        return [f"GitHub source fragment #{fragment} exceeds file line count {count} or reverses its range"]
    return []


class PageIDs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        self.ids.update(value for name, value in attrs if name == "id" and value is not None)


def page_ids(data):
    parser = PageIDs()
    parser.feed(data)
    return parser.ids


def reference_label(label):
    return " ".join(label.split()).casefold()


def release_destinations(body, version, first_line=1, all_reference_labels=None):
    """Validate visible destinations and section-local references conservatively."""
    visible = masked_code(body)
    try:
        entries = extract_destinations(body, strict=True)
    except ValueError as error:
        match = re.match(r"line ([0-9]+): (.*)", str(error))
        raise ValueError(f"CHANGELOG.md:{first_line + int(match[1]) - 1}: {match[2]}") from error
    targets = []
    for offset, target, ambiguous in entries:
        line = first_line + body.count("\n", 0, offset)
        try:
            validate_destination(target, version)
            if ambiguous:
                raise ValueError(ambiguous if isinstance(ambiguous, str) else
                                 "ambiguous destination syntax; use a canonical single-line link or reference definition")
        except ValueError as error:
            if isinstance(ambiguous, str) and str(error) != ambiguous:
                error = ValueError(ambiguous + "; " + str(error))
            raise ValueError(f"CHANGELOG.md:{line}: destination {target!r}: {error}") from error
        targets.append(target)
    definitions, footnotes = set(), set()
    for match in REFERENCE_START.finditer(visible):
        label = reference_label(match[1])
        line = first_line + body.count("\n", 0, match.start())
        if not label or label == "^" or "\\" in label or "[" in label:
            raise ValueError(f"CHANGELOG.md:{line}: ambiguous reference definition {label!r}")
        collection = footnotes if label.startswith("^") else definitions
        if label in collection:
            kind = "footnote" if label.startswith("^") else "reference"
            raise ValueError(f"CHANGELOG.md:{line}: duplicate {kind} definition {label!r}")
        collection.add(label)
    known = definitions | {reference_label(match[1]) for match in REFERENCE_START.finditer(body)} | (all_reference_labels or set())
    cursor = 0
    bracket = re.compile(r"\[([^\[\]\n]*)\]")
    while match := bracket.search(visible, cursor):
        cursor = match.end()
        rest = visible[cursor:]
        if rest.startswith("("):
            end = visible.find(")", cursor)
            cursor = end + 1 if end >= 0 else cursor
            continue
        if rest.startswith(":"):
            continue
        label = reference_label(match[1])
        if label.startswith("^"):
            if label not in footnotes:
                line = first_line + body.count("\n", 0, match.start())
                raise ValueError(f"CHANGELOG.md:{line}: footnote {label!r} requires a definition inside the released section")
            continue
        following = re.match(r"\[([^\[\]\n]*)\]", rest)
        # inlines.c: handle_close_bracket can resolve [a][b] before reaching
        # (url) when b is defined. Without b, [b](url) is the inline link.
        explicit = following is not None and not rest[following.end():].startswith("(")
        if following is not None and not explicit and reference_label(following[1]) in known:
            line = first_line + body.count("\n", 0, match.start())
            label = reference_label(following[1])
            if label not in definitions:
                raise ValueError(f"CHANGELOG.md:{line}: reference {label!r} requires a definition inside the released section")
            raise ValueError(f"CHANGELOG.md:{line}: ambiguous reference/inline link precedence for {label!r}")
        if explicit:
            label = reference_label(following[1] or match[1])
            cursor += following.end()
        if (explicit or label in known) and label not in definitions:
            line = first_line + body.count("\n", 0, match.start())
            raise ValueError(f"CHANGELOG.md:{line}: reference {label!r} requires a definition inside the released section")
    raw = RAW_HTML.search(visible)
    if raw:
        line = first_line + body.count("\n", 0, raw.start())
        raise ValueError(f"CHANGELOG.md:{line}: unsupported raw HTML {raw[0]!r}; use Markdown links and images")
    comment = visible.find("<!--")
    if comment >= 0:
        line = first_line + body.count("\n", 0, comment)
        raise ValueError(f"CHANGELOG.md:{line}: unsupported HTML comment; use prose outside comments")
    return targets


def release_notes(source, version):
    """Extract and validate one dated section in the documented CHANGELOG format."""
    parse_version(version)
    source = source.replace("\r\n", "\n")
    if "\r" in source:
        raise ValueError("CHANGELOG.md: unsupported bare carriage return")
    sections = []
    offset = 0
    fence = None
    previous = ""
    for number, line in enumerate(source.splitlines(keepends=True), 1):
        text = line.rstrip("\n")
        marker = FENCE.fullmatch(text)
        if marker and marker[1]:
            raise ValueError(f"CHANGELOG.md:{number}: fences must start in column one, including inside fences")
        if fence:
            if re.fullmatch(re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", text):
                fence = None
            elif marker:
                raise ValueError(f"CHANGELOG.md:{number}: ambiguous closing fence")
        else:
            marker = re.match(r"(`{3,}|~{3,})(.*)$", text)
            if marker:
                # Invalid backtick info is literal paragraph text, rejected by
                # the shared markdown_ambiguities check inside the section.
                if not (marker[1].startswith("`") and "`" in marker[2]):
                    fence = marker[1]
            elif re.match(r"[ \t>+*.0-9()-]*(?:`{3,}|~{3,}|##(?:[ \t]|$))", text):
                if not text.startswith("## "):
                    raise ValueError(f"CHANGELOG.md:{number}: release headings and fences must start in column one")
            if "<!--" in text and not re.fullmatch(r"[^\n]*<!--(?:(?!-->).)*-->[^\n]*", text):
                raise ValueError(f"CHANGELOG.md:{number}: multiline or ambiguous HTML comment is unsupported")
            if text.startswith("## "):
                if previous.strip():
                    raise ValueError(f"CHANGELOG.md:{number}: release heading requires a preceding blank line")
                heading = re.fullmatch(r"## (?:Unreleased(?: ([^ ]+))?|([^ ]+) - (\d{4}-\d{2}-\d{2}))[ \t]*", text)
                if not heading:
                    raise ValueError(f"CHANGELOG.md:{number}: ambiguous release heading {text!r}")
                if heading[1] or heading[2]:
                    parse_version(heading[1] or heading[2])
                if heading[3]:
                    datetime.date.fromisoformat(heading[3])
                sections.append((offset, offset + len(line), heading[2], number + 1))
        previous = text
        offset += len(line)
    if fence:
        raise ValueError("CHANGELOG.md: unclosed top-level fence")
    matches = [index for index, section in enumerate(sections) if section[2] == version]
    if len(matches) != 1:
        raise ValueError("CHANGELOG.md requires one dated section for " + version)
    index = matches[0]
    end = sections[index + 1][0] if index + 1 < len(sections) else len(source)
    original = source[sections[index][1]:end]
    body = original.strip("\n")
    if not body.strip() or not re.sub(r"(?m)^#{3,6}[^\n]*$", "", body).strip():
        raise ValueError("CHANGELOG.md release section is empty for " + version)
    first_line = sections[index][3] + len(original) - len(original.lstrip("\n"))
    labels = {reference_label(match[1]) for match in REFERENCE_START.finditer(source)}
    release_destinations(body, version, first_line, labels)
    raw = RAW_HTML.search(masked_code(source))
    if raw:
        line = 1 + source.count("\n", 0, raw.start())
        raise ValueError(f"CHANGELOG.md:{line}: unsupported raw HTML {raw[0]!r}; release boundaries would be ambiguous")
    return body + "\n"


def retry_after_seconds(value):
    if not value:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        try:
            return max(0, parsedate_to_datetime(value).timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return 0


def read_response_body(response, sock, deadline, collect=False, *, socket_timeout=15):
    """Check the budget between reads, including bodies arriving a byte at a time."""
    body = bytearray()
    received = 0
    try:
        expected = int(response.getheader("Content-Length", ""))
    except ValueError:
        expected = None
    if response.getheader("Transfer-Encoding", "").lower() == "chunked":
        expected = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("destination deadline exceeded while reading response body")
        if not response.isclosed():
            sock.settimeout(min(socket_timeout, remaining))
        try:
            chunk = response.read1(65536)
        except TimeoutError as error:
            if time.monotonic() >= deadline:
                raise TimeoutError("destination deadline exceeded while reading response body") from error
            raise
        if not chunk:
            if expected is not None and received < expected:
                raise IncompleteRead(bytes(body), expected - received)
            return bytes(body)
        received += len(chunk)
        if collect:
            body.extend(chunk)


def destination_connection(authored, proxy, *, timeout):
    """Configure a real connection with urllib-compatible proxy routing."""
    path = authored.path or "/"
    if authored.query:
        path += "?" + authored.query
    headers = {"User-Agent": "RequestSeal-release", "Connection": "close"}
    if proxy:
        # Match urllib.request._parse_proxy's authority handling, including
        # scheme-less values, percent-encoded host:port, and '/' in userinfo.
        scheme = re.match(r"([^/:]+):(.*)", proxy, re.S)
        proxy_scheme = authored.scheme
        authority = proxy
        if scheme and scheme[2].startswith("/"):
            if not scheme[2].startswith("//"):
                raise ValueError("HTTP proxy URL requires an authority")
            proxy_scheme = scheme[1].lower()
            authority = scheme[2][2:]
            slash = authority.find("/", authority.find("@") if "@" in authority else 0)
            if slash >= 0:
                authority = authority[:slash]
        userinfo, separator, hostport = authority.rpartition("@")
        if not separator:
            hostport = authority
        user, has_password, password = userinfo.partition(":")
        hostport = unquote(hostport)
        if proxy_scheme not in ("http", "https") or not hostport:
            raise ValueError("HTTP proxy requires an http:// or https:// endpoint")
        proxy_headers = {}
        # CPython urllib.request._parse_proxy/ProxyHandler.proxy_open
        # send Basic auth only for a nonempty user AND password.
        if user and has_password and password:
            credentials = unquote(user) + ":" + unquote(password)
            proxy_headers["Proxy-Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")
        if authored.scheme == "https":
            # Request.set_proxy preserves HTTPS for either proxy
            # scheme. AbstractHTTPHandler.do_open constructs an
            # HTTPSConnection: plaintext CONNECT, then TLS to the
            # origin. HTTPConnection._get_hostport/set_tunnel use
            # that connection class's default port when omitted.
            connection = HTTPSConnection(hostport, timeout=timeout)
            connection.set_tunnel(authored.hostname, authored.port, headers=proxy_headers)
        else:
            connection_type = HTTPSConnection if proxy_scheme == "https" else HTTPConnection
            connection = connection_type(hostport, timeout=timeout)
            path = authored._replace(fragment="").geturl()
            headers.update(proxy_headers)
    else:
        connection_type = HTTPSConnection if authored.scheme == "https" else HTTPConnection
        connection = connection_type(authored.hostname, authored.port, timeout=timeout)
    return connection, path, headers


def verify_http_destinations(targets, deadline_seconds=DESTINATION_DEADLINE):
    """No redirects; budget retries/body reads. DNS has no stdlib time bound."""
    pending = set(targets)
    all_targets = pending.copy()
    failures = {target: "not requested before deadline" for target in pending}
    due = {target: 0 for target in pending}
    deadline = time.monotonic() + deadline_seconds
    proxies = getproxies()
    backoff = 1
    while pending:
        final = False
        for target in sorted(pending):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if due[target] > time.monotonic():
                continue
            retry_after = 0
            redirect = ""
            status = None
            connection = None
            phase = "connecting or sending request"
            try:
                authored = urlsplit(target)
                proxy = proxies.get(authored.scheme) if not proxy_bypass(authored.netloc) else None
                connection, path, headers = destination_connection(authored, proxy, timeout=min(15, remaining))
                connection.request("GET", path, headers=headers)
                # getresponse may detach a closing connection's socket. Retain
                # the public sock before that, while its response owns the fd.
                sock = connection.sock
                phase = "reading response headers"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("destination deadline exceeded while " + phase)
                sock.settimeout(min(15, remaining))
                with connection.getresponse() as response:
                    status = response.status
                    ids = None
                    if status == 200:
                        phase = "reading response body"
                        data = read_response_body(response, sock, deadline, collect=bool(authored.fragment))
                        ids = page_ids(data.decode("utf-8")) if authored.fragment else None
                    else:
                        retry_after = retry_after_seconds(response.getheader("Retry-After")) if status == 429 else 0
                        resolved = urlsplit(urljoin(target, response.getheader("Location", "")))
                        issue = re.fullmatch(r"/baselabs/request_seal/issues/([1-9][0-9]*)", authored.path)
                        if (300 <= status < 400 and issue and resolved.hostname == "github.com"
                                and resolved.path == "/baselabs/request_seal/pull/" + issue[1]):
                            redirect = "; this number is a pull request; use https://github.com" + resolved.path
            except UnicodeError as error:
                outcome = f"HTTP {status}; " if status is not None else ""
                failures[target] = outcome + f"response decode error: {type(error).__name__}: {error}"
                pending.remove(target)
                final = True
                continue
            except TimeoutError as error:
                # request() includes TCP connect, proxy CONNECT and TLS. Each
                # uses the connection's remaining-budget socket timeout;
                # getresponse() uses the refreshed timeout above. Normalize
                # expiry in every phase, preserving an earlier idle timeout.
                reason = "destination deadline exceeded while " + phase if time.monotonic() >= deadline else str(error)
                failures[target] = "transport error: TimeoutError: " + reason
                due[target] = time.monotonic() + backoff
                continue
            except (HTTPException, ssl.SSLError, OSError) as error:
                failures[target] = f"transport error: {type(error).__name__}: {error}"
                due[target] = time.monotonic() + backoff
                continue
            finally:
                if connection is not None:
                    connection.close()
            print(f"HTTP {status} {target}", flush=True)
            if status == 200:
                pending.remove(target)
                if ids is not None and unquote(urlsplit(target).fragment) not in ids:
                    failures[target] = "HTTP 200; HexDocs fragment is missing from the real page"
                    final = True
                else:
                    failures.pop(target, None)
            else:
                failures[target] = f"HTTP {status} (expected HTTP 200, got {status})" + redirect
                if status == 404 or status == 429 or 500 <= status <= 599:
                    due[target] = time.monotonic() + max(backoff, retry_after)
                else:
                    pending.remove(target)
                    final = True
        remaining = deadline - time.monotonic()
        # Once a permanent failure makes success impossible, report the last
        # result for every destination; do not wait out unrelated 404 retries.
        if final or not pending or remaining <= 0:
            break
        time.sleep(min(max(0, min(due[target] for target in pending) - time.monotonic()), remaining))
        backoff = min(backoff * 2, 10)
    if failures:
        raise ValueError("Release destinations failed:\n" + "\n".join(
            f"{target}: {failures.get(target, 'HTTP 200')}" for target in sorted(all_targets)))


def ref_exists(root, ref):
    result = run(["git", "show-ref", "--verify", "--quiet", ref], cwd=root,
                 capture_output=True, check=False, timeout=30)
    if result.returncode not in (0, 1):
        raise ValueError(f"cannot inspect git ref {ref}")
    return result.returncode == 0


def compare_errors(root, ref, against="HEAD"):
    exists = run(["git", "show-ref", "--verify", "--quiet", "refs/tags/" + ref], cwd=root,
                 capture_output=True, check=False, timeout=30)
    if exists.returncode == 1:
        return ["compare base tag is missing: " + ref]
    exists.check_returncode()
    ancestor = run(["git", "merge-base", "--is-ancestor", "refs/tags/" + ref, against], cwd=root,
                   capture_output=True, check=False, timeout=30)
    if ancestor.returncode == 1:
        return ["compare base tag is not an ancestor of " + against + ": " + ref]
    ancestor.check_returncode()
    return []


def git_source_errors(root, ref, path, fragment=""):
    result = run(["git", "ls-tree", "-z", ref, "--", ":(literal)" + path], cwd=root,
                 capture_output=True, text=True, check=True, timeout=30)
    rows = [row.split("\t", 1) for row in result.stdout.split("\0") if row]
    if not any(name == path and metadata.split()[:2] in (["100644", "blob"], ["100755", "blob"])
               for metadata, name in rows):
        return ["missing or nonregular file in " + ref]
    if fragment:
        data = run(["git", "show", ref + ":" + path], cwd=root,
                   capture_output=True, check=True, timeout=30).stdout
        return source_fragment_errors(fragment, data)
    return []


def verify_published_destinations(body, version, event="push", root=ROOT, deadline_seconds=DESTINATION_DEADLINE):
    """Dispatch checks future source URLs in HEAD; push checks every URL over HTTP."""
    if event not in ("push", "workflow_dispatch"):
        raise ValueError("destination check requires push or workflow_dispatch mode")
    targets, failures = [], []
    for target in sorted(set(release_destinations(body, version))):
        link = classify_destination(target, version, released=True)
        if not link:
            continue
        errors = []
        if event == "workflow_dispatch" and link["kind"] == "github_compare":
            errors = compare_errors(root, link["ref"])
        elif link["kind"] in ("github", "github_raw"):
            ref = "HEAD" if event == "workflow_dispatch" else "refs/tags/" + link["ref"]
            if event == "workflow_dispatch" or link["fragment"]:
                errors = git_source_errors(root, ref, link["path"], link["fragment"])
            if event == "push":
                # Source fragments are checked against git above; HTTP checks
                # the file itself, not GitHub's dynamic line-number markup.
                targets.append(target.split("#", 1)[0])
        else:
            targets.append(target)
        failures.extend(f"{target}: {error}" for error in errors)
    try:
        verify_http_destinations(targets, deadline_seconds)
    except ValueError as error:
        failures.append(str(error))
    if failures:
        raise ValueError("\n".join(failures))


def verify_identity(root, event, ref):
    version = package_version((root / "mix.exs").read_text())
    if development_snapshot(version):
        raise ValueError("release verification refuses development snapshots")
    release_notes((root / "CHANGELOG.md").read_text(), version)
    tag = "v" + version
    index = json.loads((root / "corpus/index.json").read_text())
    if index.get("elixir_release") != tag:
        raise ValueError("corpus elixir_release must equal " + tag)
    if event not in ("push", "workflow_dispatch"):
        raise ValueError("release verification requires a tag push or workflow_dispatch")
    if event == "push" and ref != "refs/tags/" + tag:
        raise ValueError("release tag must equal " + tag)

    def git(*args):
        return run(["git", *args], cwd=root, capture_output=True, text=True, check=True, timeout=30).stdout.strip()

    exists = run(["git", "show-ref", "--verify", "--quiet", "refs/tags/" + tag], cwd=root, check=False, timeout=30)
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
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--version", action="store_true")
    choice.add_argument("--install-requirement", action="store_true")
    choice.add_argument("--verify", action="store_true")
    choice.add_argument("--normalize-sbom", type=Path)
    choice.add_argument("--release-notes", action="store_true")
    choice.add_argument("--check-destinations", action="store_true")
    parser.add_argument("--tarball", type=Path)
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--for-version")
    parser.add_argument("--destination-event", choices=("push", "workflow_dispatch"), default="push",
                        help="push: HTTP for every destination; workflow_dispatch: HEAD tree for source, HTTP for docs")
    args = parser.parse_args()
    try:
        if args.normalize_sbom:
            if not args.tarball:
                parser.error("--normalize-sbom requires --tarball")
            normalize_sbom(args.normalize_sbom, args.tarball)
        elif args.release_notes or args.check_destinations:
            version = args.for_version or package_version((ROOT / "mix.exs").read_text())
            parse_version(version)
            notes = release_notes((ROOT / "CHANGELOG.md").read_text(), version)
            if args.check_destinations:
                verify_published_destinations(notes, version, args.destination_event)
            else:
                print(notes, end="")
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
    except (ValueError, OSError, HTTPException, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
