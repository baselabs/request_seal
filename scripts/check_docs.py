#!/usr/bin/env python3
"""Check the explicit public-document inventory, content tripwires, and local links."""
from pathlib import Path
import argparse
from contextlib import nullcontext
import os
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from http.client import HTTPException
import json
from release import (MARKDOWN_SUFFIXES, classify_destination, compare_errors, extract_destinations, first_party,
                     git_source_errors, install_requirement, page_ids,
                     parse_version, ref_exists, source_fragment_errors, verify_http_destinations)
from processes import install_signal_handlers, run, temporary_directory

ROOT = Path(__file__).resolve().parents[1]
MACHINE_PATH = re.compile(r"(?:/Users/[^/\s]+/|/home/[^/\s]+/|file://)")
INTERNAL_PROCESS = re.compile(
    r"internal (?:workflow|planning|review authorization)|confidential planning|"
    r"private (?:review records|planning records)",
    re.IGNORECASE,
)
SOURCE_DOCUMENTS = {"AGENTS.md", "docs/operations/releases.md", "test/fixtures/web_bot_auth/PROVENANCE.md"} | {
    "corpus/sources/" + origin + "/PROVENANCE.md" for origin in (
        "cross-jose", "rfc7518", "rfc7748", "rfc3394", "rfc9421", "rfc6979", "rfc8032", "rfc7515", "rfc7516", "rfc7520",
        "rfc7517", "rfc8037", "wycheproof", "httpwg-structured-fields",
        "web-bot-auth", "local-http",
    )
} | {"corpus/sources/web-bot-auth/upstream-PROVENANCE.md"} | {
    "docs/adr/" + record + ".md" for record in (
        "0001-library-boundary", "0002-lossless-http-and-structured-fields", "0003-source-bound-profiles",
        "0004-key-custody-and-discovery", "0005-atomic-replay-envelope",
        "0006-verification-results-and-observability", "0007-framework-and-proxy-adapters",
        "0008-toolchain-and-compatibility", "0009-cross-language-corpus", "0010-dx-and-livebooks",
        "0011-public-contract-provenance", "0013-extension-profile-boundary",
        "0015-jose-protected-members-and-embedded-keys", "0016-bounded-jwe-open-coordinator",
        "0017-indexed-unwrap-through-a-sink", "0018-ecdh-es-key-agreement", "0019-aes-key-wrap-custody",
        "0020-separate-deadline-clocks", "0021-corpus-case-layout", "0022-typescript-conformance-contract",
        "0023-public-version-line-and-2-0-boundary", "0024-provider-profiles-in-separate-packages",
        "0025-single-label-public-verification", "0026-custody-key-generation-and-derivation",
        "0027-key-handles-replace-closures", "0028-strict-json-object-decoding",
        "0029-ash-onetime-2-custody-and-install-bound-replay", "0030-bounded-non-sending-capture",
        "0032-json-serializations-and-jwt-line",
    )
}
GIT_INSTALL = re.compile(
    r"\bgit\s*:\s*[\"'][^\"']*github\.com[/:]baselabs/request_seal(?:\.git)?[\"']|"
    r"\bgithub\s*:\s*(?:[\"'](?:[^\"']*/)?request_seal(?:\.git)?[\"']|:request_seal\b)",
    re.IGNORECASE,
)
UNPUBLISHED = re.compile(
    r"\bprivate[\s-]+(?:git(?:hub)?\s+)?(?:repository|repo)\b|"
    r"\b(?:repository|repo)\s+(?:is|remains)\s+(?:(?:currently|still)\s+)?private\b|"
    r"\bnot\s+yet\s+published\b|"
    r"\bnot\s+published\s+(?:on\s+Hex\s+)?yet\b|"
    r"\b(?:first\s+)?Hex\s+release\s+(?:is\s+)?(?:coming|planned|forthcoming)\b|"
    r"\bgit\s+dependency\s+(?:requires?|needs?)\s+access\b",
    re.IGNORECASE,
)
INSTALL = re.compile(r"\{\s*:request_seal\s*,\s*([^}]*)\}", re.DOTALL)


def public_paths(root):
    result = run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, text=True, check=True, timeout=30,
    )
    paths = set(filter(None, result.stdout.split("\0")))
    if "README.md" not in paths:
        raise ValueError("public source inventory did not find its README.md positive control")
    return paths


def public_configuration(root):
    # Read Mix's actual project configuration without compiling or starting the app.
    marker = "REQUEST_SEAL_PUBLIC_DOCUMENT\t"
    expression = (
        "project = Mix.Project.config(); "
        'for entry <- Keyword.fetch!(Keyword.fetch!(project, :docs), :extras) do '
        'path = case entry do {path, _options} -> path; path -> path end; '
        'IO.puts("REQUEST_SEAL_PUBLIC_DOCUMENT\\t" <> path) end; '
        'IO.puts("REQUEST_SEAL_VERSION\\t" <> project[:version]); '
        'for pattern <- project[:package][:files] do '
        'IO.puts("REQUEST_SEAL_PACKAGE_PATTERN\\t" <> pattern); '
        'for path <- Path.wildcard(pattern, match_dot: true), File.regular?(path), '
        'do: IO.puts("REQUEST_SEAL_PACKAGE_FILE\\t" <> path) end'
    )
    result = run(
        ["mix", "run", "--no-start", "--no-compile", "--no-deps-check", "-e", expression],
        cwd=root, capture_output=True, text=True, check=True, timeout=120,
    )
    entries = [line[len(marker):] for line in result.stdout.splitlines() if line.startswith(marker)]
    if not entries or "README.md" not in entries or len(entries) != len(set(entries)):
        raise ValueError("invalid or empty public document configuration")
    if any(not safe_document_path(p) for p in entries):
        raise ValueError("public document configuration contains an unsafe path")
    def values(marker):
        return [line[len(marker):] for line in result.stdout.splitlines() if line.startswith(marker)]
    versions = values("REQUEST_SEAL_VERSION\t")
    if len(versions) != 1:
        raise ValueError("invalid package version configuration")
    return {
        "documents": set(entries),
        "version": versions[0],
        "patterns": values("REQUEST_SEAL_PACKAGE_PATTERN\t"),
        "files": set(values("REQUEST_SEAL_PACKAGE_FILE\t")),
    }


def package_errors(root, configuration):
    documents = configuration["documents"]
    patterns = configuration["patterns"]
    files = configuration["files"]
    allowed_patterns = documents | {"lib/**/*.ex", "mix.exs"}
    errors = []
    for path in sorted(documents):
        if path in SOURCE_DOCUMENTS or not (
            path in {"README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "NOTICE"}
            or path.startswith(("docs/", "livebooks/"))
        ):
            errors.append(f"{path}: document is outside the package allowlist")
    if set(patterns) != allowed_patterns or len(patterns) != len(set(patterns)):
        errors.append("package file list must contain only lib/**/*.ex, mix.exs, and explicit public documents")
    expected = documents | {"mix.exs"} | {
        path.relative_to(root).as_posix() for path in (root / "lib").rglob("*.ex")
    }
    if not any(path.startswith("lib/") for path in files):
        errors.append("package file list did not find its library positive control")
    for path in sorted(files - expected):
        errors.append(f"{path}: file is outside the package allowlist")
    for path in sorted(expected - files):
        errors.append(f"{path}: required package file is missing")
    for path in sorted(files):
        if not safe_document_path(path) or has_symlink(root, path):
            errors.append(f"{path}: package file must have a safe path and no symlink")
    try:
        parse_version(configuration["version"])
    except ValueError as error:
        errors.append(str(error))
    return errors


def release_errors(relative, source, version=None):
    errors = []
    if GIT_INSTALL.search(source):
        errors.append(f"{relative}: RequestSeal requires a Hex install, not a Git dependency")
    if UNPUBLISHED.search(source):
        errors.append(f"{relative}: outdated release wording")
    # Released changelog entries describe the dependency requirements at that time.
    install_source = re.split(r"^## (?!Unreleased\b)", source, maxsplit=1, flags=re.MULTILINE)[0] if relative == "CHANGELOG.md" else source
    for install in INSTALL.finditer(install_source):
        if (relative == "docs/operations/releases.md"
                and install[1].strip() == 'System.fetch_env!("REQUIREMENT")'
                and 'export REQUIREMENT=$(python3 scripts/release.py --install-requirement)' in source):
            continue
        requirement = re.match(r'[\"\']([^\"\']+)[\"\']\s*(?:,|$)', install[1].strip())
        if not requirement:
            errors.append(f"{relative}: RequestSeal requires a versioned Hex install")
        elif version is not None and requirement[1] != install_requirement(version):
            errors.append(f"{relative}: RequestSeal install requirement must be {install_requirement(version)}")
    return errors


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


def documentation_inventory(output, version):
    if not (output / "api-reference.html").is_file():
        raise ValueError("documentation output is missing api-reference.html for " + version)
    return {path.relative_to(output).as_posix(): page_ids(path.read_text()) if path.suffix == ".html" else set()
            for path in output.rglob("*") if path.is_file() and not has_symlink(output, path.relative_to(output))}


def hex_metadata(version=None):
    endpoint = "https://hex.pm" + "/api/packages/request_seal" + ("/releases/" + version if version else "")
    try:
        with urlopen(Request(endpoint, headers={"User-Agent": "RequestSeal-docs"}), timeout=15) as response:
            return json.load(response)
    except HTTPError as error:
        status = error.code
        error.close()
        if status == 404:
            raise ValueError("version not published on Hex: " + str(version)) from error
        raise ValueError(f"Hex unreachable: HTTP {status}") from error
    except (OSError, URLError, HTTPException) as error:
        raise ValueError(f"Hex unreachable: {error}") from error


def documentation_pages(root, requested_version, current_version, docs_output=None):
    """Read real ExDoc output or Hex's published documentation, never derive names."""
    parse_version(requested_version)
    if requested_version == current_version and docs_output is not None:
        return documentation_inventory(Path(docs_output), requested_version)
    with temporary_directory(prefix="requestseal-docs-") as directory:
        scratch = Path(directory)
        if requested_version == current_version:
            output = scratch / "current"
            run(["mix", "docs", "--warnings-as-errors", "--formatter", "html", "--output", output],
                cwd=root, extra_env={"MIX_ENV": "dev"}, timeout=900)
        else:
            hex_home = scratch / "hex"
            try:
                result = run(["mix", "hex.docs", "fetch", "request_seal", requested_version],
                             cwd=root, extra_env={"HEX_HOME": str(hex_home)}, check=False, timeout=180)
            except (OSError, subprocess.SubprocessError) as error:
                hex_metadata(requested_version)
                raise ValueError("Hex unreachable: documentation fetch failed for published version " + requested_version) from error
            output = hex_home / "docs/hexpm/request_seal" / requested_version
            if result.returncode or not (output / "api-reference.html").is_file():
                hex_metadata(requested_version)  # Distinguish absence from a failed transport.
                raise ValueError("Hex unreachable: documentation fetch failed for published version " + requested_version)
        return documentation_inventory(output, requested_version)


def published_documents(root, version):
    """Use the shipped inventory for historical source links, without evaluating old code."""
    parse_version(version)
    with temporary_directory(prefix="requestseal-package-") as directory:
        output = Path(directory) / "package"
        try:
            result = run(["mix", "hex.package", "fetch", "request_seal", version, "--unpack", "--output", output],
                         cwd=root, extra_env={"HEX_HOME": str(Path(directory) / "hex")}, check=False, timeout=180)
        except (OSError, subprocess.SubprocessError) as error:
            hex_metadata(version)
            raise ValueError("Hex unreachable: package fetch failed for published version " + version) from error
        if result.returncode:
            hex_metadata(version)
            raise ValueError("Hex unreachable: package fetch failed for published version " + version)
        if not (output / "README.md").is_file():
            raise ValueError("published package is missing README.md for " + version)
        return {path.relative_to(output).as_posix() for path in output.rglob("*")
                if path.is_file() and not has_symlink(output, path.relative_to(output))}


def first_party_link_errors(root, relative, url, version, published, references):
    """Use the shared classifier, working tree/tags, real ExDoc, and Hex artifacts."""
    try:
        authored = url if isinstance(url, str) else url.geturl()
        url = urlsplit("https://" + authored if authored.lower().startswith("www.") else authored)
        link = classify_destination(authored)
        if link is None:
            return []
        kind, target, fragment = link["kind"], link["path"], link["fragment"]
        if kind == "hexdocs":
            release_version = link["version"]
            if release_version is None:
                if "HEX_LATEST" not in references:
                    try:
                        references["HEX_LATEST"] = hex_metadata()["latest_stable_version"]
                    except ValueError as error:
                        references["HEX_LATEST"] = error
                if isinstance(references["HEX_LATEST"], ValueError):
                    return [str(references["HEX_LATEST"])]
                release_version = references["HEX_LATEST"]
            key = ("hexdocs", release_version)
            if key not in references:
                try:
                    references[key] = documentation_pages(root, release_version, version, references.get("DOCS_OUTPUT"))
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    references[key] = f"cannot inspect HexDocs {release_version}: {error}"
            pages = references[key]
            if isinstance(pages, str):
                return [pages]
            if target not in pages:
                return ["HexDocs page is missing from real documentation output for " + release_version]
            if fragment and unquote(fragment) not in pages[target]:
                return ["HexDocs fragment is missing from real documentation output for " + release_version]
            return []
        if kind in ("github_live", "hex_package"):
            if (kind == "hex_package" and version is not None and link.get("version") == version
                    and not ref_exists(root, "refs/tags/v" + version)):
                # The current release's package page does not exist until Hex
                # publication. Historical/tagged releases still require HTTP.
                return []
            key = ("HTTP", url.geturl())
            if key not in references:
                try:
                    verify_http_destinations([url.geturl()])
                    references[key] = []
                except ValueError as error:
                    references[key] = [str(error)]
            return references[key]
        if kind == "github_compare":
            errors = compare_errors(root, link["ref"])
            if errors:
                return errors
            if link["version"] != version and not ref_exists(root, "refs/tags/v" + link["version"]):
                return ["compare destination tag is missing: v" + link["version"]]
            return []
        name = link["ref"]
        ref = None if name == "main" else "refs/tags/" + name
        if name == "v" + str(version) and not ref_exists(root, ref):
            ref = None
        key = ref or "WORKTREE"
        if key not in references:
            if ref is None:
                references[key] = public_configuration(root), {p: "100644" for p in public_paths(root)}
            else:
                if not ref_exists(root, ref):
                    return ["first-party destination ref is missing: " + ref]
                listing = run(["git", "ls-tree", "-r", "-z", ref], cwd=root,
                              capture_output=True, text=True, check=True, timeout=30).stdout
                tree = {row.split("\t", 1)[1]: row.split(" ", 1)[0] for row in listing.split("\0") if row}
                references[key] = None, tree
        configuration, tree = references[key]
        if target not in tree or tree[target] not in ("100644", "100755"):
            return ["GitHub link targets missing or nonregular content at " + key]
        if ref is None and (has_symlink(root, target) or not (root / target).is_file()):
            return ["GitHub link targets missing or symlinked content"]
        if fragment:
            errors = source_fragment_errors(fragment, (root / target).read_bytes()) if ref is None else git_source_errors(root, ref, target, fragment)
            if errors:
                return errors
        if published is not None and relative in published and Path(target).suffix in (".md", ".livemd"):
            if ref is None:
                documents = configuration["documents"]
            else:
                inventory_key = ("package", name)
                if inventory_key not in references:
                    try:
                        references[inventory_key] = published_documents(root, name.removeprefix("v"))
                    except (OSError, ValueError, subprocess.SubprocessError) as error:
                        references[inventory_key] = str(error)
                documents = references[inventory_key]
                if isinstance(documents, str):
                    return [documents]
            if target not in documents:
                return ["published document links a repository-only document at " + key]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return [str(error)]
    return []


def content_errors(root, relative, source, paths, version=None, published=None, references=None, *, check_links=True):
    root = root.resolve()
    errors = []
    path = root / relative
    references = {} if references is None else references
    if MACHINE_PATH.search(source):
        errors.append(f"{relative}: machine or private file URL")
    if INTERNAL_PROCESS.search(source):
        errors.append(f"{relative}: internal process material is not public documentation")
    errors.extend(release_errors(relative, source, version))
    if not check_links:
        return errors
    for offset, target, ambiguous in extract_destinations(source):
        if ambiguous:
            line = 1 + source.count("\n", 0, offset)
            errors.append(f"{relative}:{line}: {target}: ambiguous destination syntax")
            continue
        try:
            url = urlsplit("https://" + target if target.lower().startswith("www.") else target)
        except ValueError:
            errors.append(f"{relative}: malformed link")
            continue
        if url.scheme in ("https", "http", "mailto"):
            errors.extend(f"{relative}: {target}: {error}" for error in
                          first_party_link_errors(root, relative, target, version, published, references))
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
        elif (published is not None and relative in published
              and lexical.suffix in (".md", ".livemd")
              and lexical.relative_to(root.resolve()).as_posix() not in published):
            # HexDocs carries only the published documents; such a link breaks there.
            errors.append(f"{relative}: published document links a repository-only document")
        elif has_symlink(root, lexical.relative_to(root.resolve())):
            errors.append(f"{relative}: local link must not traverse a symlink")
        elif not destination.exists():
            errors.append(f"{relative}: missing local link")
    return errors


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
    if not examples:
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


def link_scan_paths(paths, configuration):
    """The package/docs inventories plus repository publication sources."""
    return configuration["files"] | configuration["documents"] | {
        relative for relative in paths
        if relative.startswith(("livebooks/", "corpus/", ".github/"))
        or (Path(relative).suffix.lower() in MARKDOWN_SUFFIXES
            and not relative.startswith(("test/", "scripts/")))
    }


def tracked_link_errors(root, paths, version, published, references, checked=(), configuration=None):
    """Scan UTF-8 publication sources; fixtures have no authored destinations."""
    configuration = public_configuration(root) if configuration is None else configuration
    errors = []
    for relative in sorted(link_scan_paths(paths, configuration) - set(checked)):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for offset, target, ambiguous in extract_destinations(source, markdown=path.suffix.lower() in MARKDOWN_SUFFIXES):
            if ambiguous:
                line = 1 + source.count("\n", 0, offset)
                errors.append(f"{relative}:{line}: {target}: ambiguous destination syntax")
                continue
            is_first_party = False
            try:
                url = urlsplit("https://" + target if target.lower().startswith("www.") else target)
                is_first_party = first_party(url) is not None
                if not is_first_party:
                    continue
                classify_destination(target)
                reasons = first_party_link_errors(root, relative, target, version, published, references)
                line = 1 + source.count("\n", 0, offset)
                errors.extend(f"{relative}:{line}: {target}: {reason}" for reason in reasons)
            except ValueError as error:
                if is_first_party:
                    line = 1 + source.count("\n", 0, offset)
                    errors.append(f"{relative}:{line}: {target}: {error}")
    return errors


def check(root=ROOT, docs_output=None):
    configuration = public_configuration(root)
    approved = configuration["documents"] | SOURCE_DOCUMENTS
    paths = public_paths(root)
    scan_paths = link_scan_paths(paths, configuration)
    errors = inventory_errors(root, approved, paths)
    errors.extend(package_errors(root, configuration))
    with temporary_directory(prefix="requestseal-docs-") if docs_output is None else nullcontext() as scratch:
        if docs_output is None:
            docs_output = Path(scratch) / "current"
            run(["mix", "docs", "--warnings-as-errors", "--output", docs_output],
                cwd=root, extra_env={"MIX_ENV": "dev"}, timeout=900)
        references = {"WORKTREE": (configuration, {p: "100644" for p in paths}), "DOCS_OUTPUT": docs_output}
        references[("hexdocs", configuration["version"])] = documentation_inventory(Path(docs_output), configuration["version"])
        for relative in sorted(approved):
            path = root / relative
            if path.is_file() and not path.is_symlink():
                source = path.read_bytes().decode("utf-8")
                errors.extend(content_errors(root, relative, source, paths, configuration["version"], configuration["documents"], references,
                                             check_links=relative in scan_paths))
                errors.extend(fence_errors(root, relative, source))
        errors.extend(tracked_link_errors(root, paths, configuration["version"], configuration["documents"], references,
                                         approved, configuration))
        for relative in sorted(configuration["files"] - approved):
            path = root / relative
            if path.is_file() and not path.is_symlink():
                errors.extend(release_errors(relative, path.read_text(), configuration["version"]))
    return approved, errors


if __name__ == "__main__":
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docs-output", type=Path, help="Reuse real ExDoc output built by the caller")
    args = parser.parse_args()
    try:
        approved, errors = check(docs_output=args.docs_output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Public-document check failed: {error}")
        sys.exit(1)
    if errors:
        print("\n".join(errors))
        sys.exit(1)
    print(f"PASS: {len(approved)} approved public documents, disclosure tripwires, and links")
    print("Scope: every approved Markdown Elixir fence is paired and executed; Livebooks use their dedicated execution gate")
