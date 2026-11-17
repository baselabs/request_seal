#!/usr/bin/env python3
"""Release identity and reproducible SBOM metadata shared by repository gates."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

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


def release_notes(source, version):
    """Return only the body of one dated release section, never Unreleased."""
    heading = re.compile(r"^## " + re.escape(version) + r" - (\d{4}-\d{2}-\d{2})[ \t]*$", re.MULTILINE)
    matches = list(heading.finditer(source))
    if len(matches) != 1:
        raise ValueError("CHANGELOG.md requires one dated section for " + version)
    datetime.date.fromisoformat(matches[0][1])
    body = re.split(r"^## ", source[matches[0].end():], maxsplit=1, flags=re.MULTILINE)[0].strip()
    if not body or not re.sub(r"(?m)^#{3,6}[^\n]*$", "", body).strip():
        raise ValueError("CHANGELOG.md release section is empty for " + version)
    return body + "\n"


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
    parser.add_argument("--tarball", type=Path)
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--for-version")
    args = parser.parse_args()
    try:
        if args.normalize_sbom:
            if not args.tarball:
                parser.error("--normalize-sbom requires --tarball")
            normalize_sbom(args.normalize_sbom, args.tarball)
        elif args.verify:
            version = verify_identity(ROOT, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"])
            if args.notes_file:
                args.notes_file.write_text(release_notes((ROOT / "CHANGELOG.md").read_text(), version))
            print("PASS: release identity " + version)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                    output.write("version=" + version + "\n")
        else:
            version = args.for_version or package_version((ROOT / "mix.exs").read_text())
            parse_version(version)
            print(install_requirement(version) if args.install_requirement else version)
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
