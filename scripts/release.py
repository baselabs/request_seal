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


# These are lexical authoring rules, including in examples and comments. They
# deliberately do not model Markdown blocks, escaping, or renderer visibility.
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
REFERENCE_USE = re.compile(r"\[([^\[\]\n]+)\](?:[ \t]*(?:\n[ \t]*)?\[([^\[\]\n]*)\])?")
FENCE = re.compile(r"([ \t>+*.0-9()-]*)(`{3,}|~{3,})(.*)$")
DESTINATION_DEADLINE = 180


def first_party(url):
    # Classification includes browser normalization; validation below rejects it.
    host = unquote(url.hostname or "").lower().rstrip(".").removeprefix("www.")
    path = posixpath.normpath("/" + unquote(url.path).lstrip("/")).lower()
    if (host == "request-seal.hexdocs.pm"
            or host == "hexdocs.pm" and (path == "/request_seal" or path.startswith("/request_seal/"))):
        return "hexdocs"
    if host == "raw.githubusercontent.com" and (path == "/baselabs/request_seal" or path.startswith("/baselabs/request_seal/")):
        return "github_raw"
    if host == "github.com" and (path == "/baselabs/request_seal" or path.startswith("/baselabs/request_seal/")):
        # Public advisory permalinks describe security history, not tagged files.
        if (url.netloc == "github.com" and url.scheme == "https"
                and re.fullmatch(r"/baselabs/request_seal/security/advisories/GHSA-[a-z0-9-]+", url.path)):
            return None
        return "github"
    return None


def first_party_syntax(url, kind):
    host = {"hexdocs": "request-seal.hexdocs.pm", "github": "github.com",
            "github_raw": "raw.githubusercontent.com"}[kind]
    prefix = "/" if kind == "hexdocs" else "/baselabs/request_seal/"
    if (url.scheme != "https" or url.netloc != host
            or (url.path and not url.path.startswith(prefix) and url.path != prefix.rstrip("/"))
            or "%" in url.path or any(part in (".", "..") for part in url.path.split("/"))):
        raise ValueError(f"first-party destination requires canonical https://{host}{prefix} "
                         "with literal path/casing, no dot segments, credentials, or port")


def validate_destination(target, version):
    """Classify literal URLs without decoding or rewriting Markdown syntax."""
    if (not target or re.search(r"[^\x21-\x7e]|[<>\\\"'`()]", target)
            or re.search(r"&(?:#\w+|[A-Za-z][A-Za-z0-9]*);|%(?![0-9A-Fa-f]{2})", target)):
        raise ValueError("requires a literal absolute URL; ambiguous destination syntax")
    url = urlsplit(target)
    kind = first_party(url)
    canonical = {
        "hexdocs": f"https://request-seal.hexdocs.pm/{version}/<page>",
        "github": f"https://github.com/baselabs/request_seal/blob/v{version}/<path>",
        "github_raw": f"https://raw.githubusercontent.com/baselabs/request_seal/v{version}/<path>",
    }.get(kind)
    if kind:
        try:
            first_party_syntax(url, kind)
        except ValueError as error:
            raise ValueError(f"{error}; canonical form: {canonical}") from error
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
    if kind:
        if kind == "hexdocs":
            prefix = f"/{version}/"
        elif kind == "github_raw":
            prefix = f"/baselabs/request_seal/v{version}/"
        else:
            prefix = f"/baselabs/request_seal/blob/v{version}/"
        if not url.path.startswith(prefix) or url.path.endswith("/"):
            raise ValueError(f"first-party destination must use version {version}; canonical form: {canonical}")
    return kind


def reference_label(label):
    return " ".join(label.split()).casefold()


def release_destinations(body, version, first_line=1, all_reference_labels=None):
    """Validate every potential destination, without code or comment exemptions."""
    targets = []

    def destination(offset, target, ambiguous=False):
        line = first_line + body.count("\n", 0, offset)
        try:
            validate_destination(target, version)
            if ambiguous:
                raise ValueError("ambiguous destination syntax; use a canonical single-line link or reference definition")
        except ValueError as error:
            raise ValueError(f"CHANGELOG.md:{line}: destination {target!r}: {error}") from error
        targets.append(target)

    for start in INLINE_START.finditer(body):
        match = INLINE.match(body, start.start())
        candidate = body[start.end():].split("\n", 1)[0].split(")", 1)[0]
        destination(start.start(), match[1].removeprefix("<").removesuffix(">") if match else candidate, match is None)
    definitions = set()
    for start in REFERENCE_START.finditer(body):
        match = REFERENCE.match(body, start.end())
        candidate = body[start.end():].split("\n", 1)[0].strip()
        destination(start.start(), match[1].removeprefix("<").removesuffix(">") if match else candidate,
                    match is None or not start[1] or start[1].startswith("^") or "\\" in start[1] or "[" in start[1])
        label = reference_label(start[1])
        if label in definitions:
            line = first_line + body.count("\n", 0, start.start())
            raise ValueError(f"CHANGELOG.md:{line}: duplicate reference definition {start[1]!r}")
        definitions.add(label)
    for match in AUTOLINK.finditer(body):
        destination(match.start(), match[1])
    for match in BARE_URL.finditer(body):
        # Delimiters and sentence punctuation end bare URLs. Internal syntax is
        # still literal and conservative, including inside code and comments.
        destination(match.start(), match[0].rstrip(".,;:!?)]}"))
    known_labels = definitions | (all_reference_labels or set())
    for match in REFERENCE_USE.finditer(body):
        rest = body[match.end():]
        if rest.startswith(("(", ":")):
            continue
        label = reference_label(match[2] or match[1])
        if (match[2] is not None or label in known_labels) and label not in definitions:
            line = first_line + body.count("\n", 0, match.start())
            raise ValueError(f"CHANGELOG.md:{line}: reference {label!r} requires a definition inside the released section")
    for match in URL_ATTRIBUTE.finditer(body):
        destination(match.start(), next(value for value in match.groups() if value is not None))
    raw = RAW_HTML.search(body)
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
    raw = RAW_HTML.search(source)
    if raw:
        line = 1 + source.count("\n", 0, raw.start())
        raise ValueError(f"CHANGELOG.md:{line}: unsupported raw HTML {raw[0]!r}; release boundaries would be ambiguous")
    return body + "\n"


def verify_http_destinations(targets, deadline_seconds=DESTINATION_DEADLINE):
    """Retry propagation failures within one total deadline; never follow redirects."""
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = build_opener(NoRedirect())
    pending = set(targets)
    failures = {target: "not requested before deadline" for target in pending}
    deadline = time.monotonic() + deadline_seconds
    backoff = 1
    while pending:
        redirected = False
        for target in sorted(pending):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with opener.open(Request(target, headers={"User-Agent": "RequestSeal-release"}), timeout=min(15, remaining)) as response:
                    status = response.status
            except HTTPError as error:
                status = error.code
                error.close()
            except (OSError, URLError) as error:
                failures[target] = f"transport error: {error}"
                continue
            print(f"HTTP {status} {target}", flush=True)
            if status == 200:
                pending.remove(target)
                failures.pop(target, None)
            else:
                failures[target] = f"HTTP {status} (expected HTTP 200, got {status})"
                redirected = redirected or 300 <= status < 400
                if status != 404 and not 500 <= status <= 599:
                    pending.remove(target)  # Permanent, including every 3xx.
        remaining = deadline - time.monotonic()
        if redirected or not pending or remaining <= 0:
            break
        time.sleep(min(backoff, remaining))
        backoff = min(backoff * 2, 10)
    if failures:
        raise ValueError("Release destinations failed:\n" + "\n".join(
            f"{target}: {status}" for target, status in sorted(failures.items())))


def verify_published_destinations(body, version, event="push", root=ROOT, deadline_seconds=DESTINATION_DEADLINE):
    """Dispatch checks future source URLs in HEAD; push checks every URL over HTTP."""
    if event not in ("push", "workflow_dispatch"):
        raise ValueError("destination check requires push or workflow_dispatch mode")
    targets, failures = [], []
    for target in sorted(set(release_destinations(body, version))):
        url = urlsplit(target)
        kind = first_party(url)
        if not kind:
            continue
        if event == "workflow_dispatch" and kind in ("github", "github_raw"):
            prefix = f"/baselabs/request_seal/{'blob/' if kind == 'github' else ''}v{version}/"
            path = url.path.removeprefix(prefix)
            result = run(["git", "ls-tree", "-z", "HEAD", "--", ":(literal)" + path], cwd=root,
                         capture_output=True, text=True, check=True, timeout=30)
            rows = [row.split("\t", 1) for row in result.stdout.split("\0") if row]
            if not any(name == path and metadata.split()[:2] in (["100644", "blob"], ["100755", "blob"])
                       for metadata, name in rows):
                failures.append(f"{target}: missing or nonregular file in HEAD")
            else:
                print(f"HEAD regular file {path}", flush=True)
        else:
            targets.append(target)
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
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
