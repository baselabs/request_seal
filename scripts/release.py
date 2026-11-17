#!/usr/bin/env python3
"""Release identity and reproducible SBOM metadata shared by repository gates."""
import argparse
import datetime
import hashlib
from http.client import HTTPException
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
from urllib.parse import unquote, urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
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
AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^<>\n]*)>")
BARE_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]*", re.I)
FENCE = re.compile(r"([ \t>+*.0-9()-]*(?:\[[ xX]\][ \t]*)?)(`{3,}|~{3,})(.*)$")
DESTINATION_DEADLINE = 180

GITHUB_ASSET_HOSTS = {"github-cloud.githubusercontent.com", "objects.githubusercontent.com",
                      "objects-origin.githubusercontent.com", "release-assets.githubusercontent.com",
                      "github-releases.githubusercontent.com", "github-cloud.s3.amazonaws.com"}
HEX_HOSTS = {"hex.pm", "diff.hex.pm", "preview.hex.pm", "repo.hex.pm"}


def masked_code(source):
    """Keep offsets and newlines while hiding code blocks and matched code spans."""
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
        elif marker:
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
    cursor = 0
    while match := re.search(r"`+", visible[cursor:]):
        start = cursor + match.start()
        end = cursor + match.end()
        closing = re.search(r"(?<!`)" + re.escape(match[0]) + r"(?!`)", visible[end:])
        if closing and "\n\n" not in visible[end:end + closing.start()]:
            cursor = end + closing.end()
            hide(start, cursor)
        else:
            cursor = end
    return "".join(chars)


def bare_destination(target):
    """GFM extended-autolink trailing punctuation, parentheses, and entities."""
    while True:
        trimmed = target.rstrip("?!.,:*_~")
        if trimmed.endswith(")") and trimmed.count(")") > trimmed.count("("):
            trimmed = trimmed[:-1]
        trimmed = re.sub(r"&(?:[A-Za-z0-9]+|#[0-9]+|#[xX][0-9A-Fa-f]+);$", "", trimmed)
        if trimmed == target:
            return target
        target = trimmed


def extract_destinations(source, strict=False, markdown=True):
    """One extractor for links, definitions, attributes, autolinks and bare URLs.

    Entries are (source offset, literal destination, ambiguous syntax). Code is
    hidden only for Markdown; tracked JSON and other text retain literal URLs.
    """
    visible = masked_code(source) if markdown else source
    entries, occupied = [], []

    def add(start, end, target, ambiguous=False):
        entries.append((start, target.removeprefix("<").removesuffix(">"), ambiguous))
        occupied.append((start, end))

    for start in INLINE_START.finditer(visible):
        match = INLINE.match(visible, start.start())
        candidate = visible[start.end():].split("\n", 1)[0].split(")", 1)[0]
        beginning = visible.rfind("[", 0, start.start())
        add(beginning if beginning >= 0 else start.start(), match.end() if match else start.end(),
            match[1] if match else candidate, match is None)
    previous_definition, previous_blank = False, True
    offset = 0
    for original, line in zip(source.splitlines(keepends=True), visible.splitlines(keepends=True)):
        definition = REFERENCE_START.search(line)
        if definition:
            prefix = line[:definition.start()]
            valid = prefix in ("", " ", "  ", "   ") and (previous_blank or previous_definition)
            match = REFERENCE.match(line.rstrip("\r\n"), definition.end())
            if strict and not valid:
                raise ValueError(f"line {1 + source.count(chr(10), 0, offset)}: ambiguous reference definition {original.strip()!r}")
            add(offset + definition.start(), offset + len(line),
                match[1] if match else line[definition.end():].strip(), not valid or match is None)
            previous_definition = valid and match is not None
        else:
            previous_definition = False
        previous_blank = not original.strip()
        offset += len(line)
    for match in URL_ATTRIBUTE.finditer(visible):
        add(match.start(), match.end(), unescape(next(value for value in match.groups() if value is not None)))
    for match in AUTOLINK.finditer(visible):
        if not any(start <= match.start() < end for start, end in occupied):
            add(match.start(), match.end(), match[1])
    for match in BARE_URL.finditer(visible):
        if not any(start <= match.start() < end for start, end in occupied):
            add(match.start(), match.end(), bare_destination(match[0]))
    return sorted(entries)


def first_party(url):
    """Recognize repository/package content even on redirecting or alternate hosts."""
    host = unquote(url.hostname or "").lower().rstrip(".").removeprefix("www.")
    decoded = "/" + unquote(url.path).lstrip("/")
    paths = (decoded.lower(), posixpath.normpath(decoded).lower())
    if host in ("request-seal.hexdocs.pm", "request_seal.hexdocs.pm"):
        return "hexdocs"
    if host == "hexdocs.pm" and any(re.match(r"/request_seal(?:/|$)", path) for path in paths):
        return "hexdocs"
    if host in GITHUB_ASSET_HOSTS:
        return "github"  # Opaque asset URLs cannot establish a stable repository ref.
    if host == "baselabs.github.io" and any(re.match(r"/request_seal(?:/|$)", path) for path in paths):
        return "github"
    if host == "github.com" or host.endswith((".github.com", ".githubusercontent.com")):
        if any(re.search(r"(?:^|/)baselabs/request_seal(?:[/.]|$)", path) for path in paths):
            return "github_raw" if host in {"raw.github.com", "raw.githubusercontent.com", "media.githubusercontent.com"} else "github"
    if host in HEX_HOSTS and (any(re.search(r"(?:^|/)request_seal(?:[-/.]|$)", path) for path in paths)
                              or re.search(r"(?:^|[=&/])request_seal(?:[=&/]|$)", unquote(url.query).lower())):
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
    if result["path"] and (result["path"].endswith("/") or any(part.startswith(".") or not part for part in result["path"].split("/"))):
        raise ValueError("first-party link targets a private or unsafe path; canonical form: " + canonical)
    if url.fragment and result["kind"] not in ("hexdocs", "github"):
        raise ValueError("first-party destination does not allow a fragment; canonical form: " + canonical)
    if released and result["kind"] not in ("github_live",) and result["version"] != version:
        raise ValueError(f"first-party destination must use version {version}; canonical form: {canonical}")
    return result


def validate_destination(target, version):
    """Validate literal authoring syntax and the shared canonical forms."""
    if (not target or re.search(r"[^\x21-\x7e]|[<>\\\"'`]", target)
            or re.search(r"&(?:#\w+|[A-Za-z][A-Za-z0-9]*);|%(?![0-9A-Fa-f]{2})", target)):
        raise ValueError("requires a literal absolute URL; ambiguous destination syntax")
    url = urlsplit("https://" + target if target.lower().startswith("www.") else target)
    classified = classify_destination(target, version, released=True)
    if target.lower().startswith("www.") and classified:
        raise ValueError("first-party destination requires canonical form: " + canonical_forms(version)[first_party(url)])
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
        raise ValueError("requires an absolute HTTP(S) or mailto URL")
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
                raise ValueError("ambiguous destination syntax; use a canonical single-line link or reference definition")
        except ValueError as error:
            raise ValueError(f"CHANGELOG.md:{line}: destination {target!r}: {error}") from error
        targets.append(target)
    definitions = set()
    for match in REFERENCE_START.finditer(visible):
        label = reference_label(match[1])
        line = first_line + body.count("\n", 0, match.start())
        if not label or label.startswith("^") or "\\" in label or "[" in label:
            raise ValueError(f"CHANGELOG.md:{line}: ambiguous reference definition {label!r}")
        if label in definitions:
            raise ValueError(f"CHANGELOG.md:{line}: duplicate reference definition {label!r}")
        definitions.add(label)
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
        following = re.match(r"([ \t]*(?:\n[ \t]*)?)\[([^\[\]\n]*)\]", rest)
        explicit = following is not None and (not following[1] or not following[2] or label not in known)
        if explicit:
            label = reference_label(following[2] or match[1])
            cursor += following.end()
        if (explicit or label in known) and label not in definitions:
            line = first_line + body.count("\n", 0, match.start())
            raise ValueError(f"CHANGELOG.md:{line}: reference {label!r} requires a definition inside the released section")
    raw = RAW_HTML.search(visible)
    if raw:
        line = first_line + body.count("\n", 0, raw.start())
        raise ValueError(f"CHANGELOG.md:{line}: unsupported raw HTML {raw[0]!r}; use Markdown links and images")
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
                if "`" in marker[2]:
                    raise ValueError(f"CHANGELOG.md:{number}: ambiguous fence info")
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


def verify_http_destinations(targets, deadline_seconds=DESTINATION_DEADLINE):
    """No redirects; retry transient errors. Bound: deadline plus one socket timeout."""
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = build_opener(NoRedirect())
    pending = set(targets)
    failures = {target: "not requested before deadline" for target in pending}
    due = {target: 0 for target in pending}
    deadline = time.monotonic() + deadline_seconds
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
            try:
                with opener.open(Request(target, headers={"User-Agent": "RequestSeal-release"}), timeout=min(15, remaining)) as response:
                    status = response.status
                    fragment = urlsplit(target).fragment
                    ids = page_ids(response.read().decode("utf-8")) if status == 200 and fragment else None
            except HTTPError as error:
                status = error.code
                retry_after = retry_after_seconds(error.headers.get("Retry-After")) if status == 429 else 0
                error.close()
            except (HTTPException, ssl.SSLError, OSError, URLError) as error:
                failures[target] = f"transport error: {type(error).__name__}: {error}"
                due[target] = time.monotonic() + backoff
                continue
            print(f"HTTP {status} {target}", flush=True)
            if status == 200:
                pending.remove(target)
                if ids is not None and unquote(urlsplit(target).fragment) not in ids:
                    failures[target] = "HexDocs fragment is missing from the real page"
                    final = True
                else:
                    failures.pop(target, None)
            else:
                failures[target] = f"HTTP {status} (expected HTTP 200, got {status})"
                if status == 404 or status == 429 or 500 <= status <= 599:
                    due[target] = time.monotonic() + max(backoff, retry_after)
                else:
                    pending.remove(target)
                    final = True
                    if 300 <= status < 400:
                        break  # A redirect fails immediately, without another request.
        remaining = deadline - time.monotonic()
        # Once a permanent failure makes success impossible, report the last
        # result for every destination; do not wait out unrelated 404 retries.
        if final or not pending or remaining <= 0:
            break
        time.sleep(min(max(0, min(due[target] for target in pending) - time.monotonic()), remaining))
        backoff = min(backoff * 2, 10)
    if failures:
        raise ValueError("Release destinations failed:\n" + "\n".join(
            f"{target}: {status}" for target, status in sorted(failures.items())))


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
