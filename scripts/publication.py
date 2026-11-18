#!/usr/bin/env python3
"""Inspect archives, plan missing Hex uploads anonymously, and read both archives back."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from processes import install_signal_handlers

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "request_seal"


def registry_errors(package, metadata):
    if metadata is None:
        return ["Package does not exist on Hex; first publication is the owner's decision: " + package]
    if not isinstance(metadata, dict) or metadata.get("name") != package:
        return ["Registry package identity differs: " + package]
    releases = metadata.get("releases")
    if not isinstance(releases, list) or not releases or any(
            not isinstance(row, dict) or not isinstance(row.get("version"), str) for row in releases):
        return ["Registry release inventory is missing or invalid: " + package]
    return []


def registry_response(path, status, metadata):
    """Only an explicit 404 means absence; all uncertain responses refuse."""
    if status == 404:
        return None
    if status != 200:
        raise ValueError(f"Cannot read Hex package {PACKAGE}{path}: HTTP {status}")
    if not isinstance(metadata, dict):
        raise ValueError("Hex returned invalid metadata: " + PACKAGE + path)
    return metadata


def read_registry(path):
    request = Request("https://hex.pm/api/packages/" + PACKAGE + path,
                      headers={"User-Agent": "RequestSeal-publication"})
    try:
        with urlopen(request, timeout=30) as response:
            status = response.status
            metadata = json.load(response)
    except HTTPError as error:
        status = error.code
        error.close()
        metadata = None
    return registry_response(path, status, metadata)


def check_registry():
    metadata = read_registry("")
    errors = registry_errors(PACKAGE, metadata)
    if errors:
        raise ValueError("; ".join(errors))
    print(f"PASS: Hex name already exists: {PACKAGE}")
    return metadata


def upload_plan(package, version, metadata, release, checksum):
    """Constructed or public API responses determine exactly which files may be uploaded.

    Hex's API renders release.outer_checksum as `checksum`, not the inner CHECKSUM:
    https://github.com/hexpm/hexpm/blob/main/lib/hexpm_web/views/api/release_view.ex
    That is SHA-256 of the entire .tar:
    https://github.com/hexpm/hex_core/blob/main/src/hex_tarball.erl
    """
    errors = registry_errors(package, metadata)
    if errors:
        raise ValueError("; ".join(errors))
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Inspected package checksum is invalid")
    if release is None:
        if any(row["version"] == version for row in metadata["releases"]):
            raise ValueError(f"Hex lists {package} {version} but its release metadata is absent")
        return "package-and-docs"
    if not isinstance(release, dict) or release.get("version") != version:
        raise ValueError(f"Registry release identity differs: {package} {version}")
    if "retirement" not in release:
        raise ValueError("Registry release retirement state is missing")
    if release["retirement"] is not None:
        raise ValueError(f"Version is retired; refusing publication: {package} {version}")
    served = release.get("checksum")
    if not isinstance(served, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", served):
        raise ValueError("Registry release checksum is missing or invalid")
    if served.lower() != checksum:
        raise ValueError(f"Published package bytes differ from the inspected archive: {package} {version}; never replace")
    if type(release.get("has_docs")) is not bool:
        raise ValueError("Registry release documentation state is missing or invalid")
    return "none" if release["has_docs"] else "docs"


def plan_upload(version, directory, github_output):
    metadata = check_registry()
    release = read_registry("/releases/" + version)
    tarball = directory / f"{PACKAGE}-{version}.tar"
    plan = upload_plan(PACKAGE, version, metadata, release, hashlib.sha256(tarball.read_bytes()).hexdigest())
    # Only constant, validated choices reach the keyed no-project uploader.
    with github_output.open("a") as output:
        output.write(f"upload={plan}\n")
    print("PASS: upload plan: " + plan)


def archive_errors(expected, served, label):
    """Compare actual readback bytes without evaluating package or documentation code."""
    return [] if expected == served else [f"Published {label} bytes differ from the inspected archive; never replace"]


def readback_errors(package, version, metadata, release, checksum):
    plan = upload_plan(package, version, metadata, release, checksum)
    return [] if plan == "none" else [
        "Hex publication is incomplete (missing " + plan + "); approve any held uploads and dispatch again"]


def verify_registry(version, directory):
    metadata = check_registry()
    release = read_registry("/releases/" + version)
    package = (directory / f"{PACKAGE}-{version}.tar").read_bytes()
    errors = readback_errors(PACKAGE, version, metadata, release, hashlib.sha256(package).hexdigest())
    if errors:
        raise ValueError("; ".join(errors))
    for path, expected, label in (
            (f"tarballs/{PACKAGE}-{version}.tar", package, "package"),
            (f"docs/{PACKAGE}-{version}.tar.gz", (directory / f"{PACKAGE}-{version}-docs.tar.gz").read_bytes(), "documentation")):
        request = Request("https://repo.hex.pm/" + path, headers={"User-Agent": "RequestSeal-publication"})
        with urlopen(request, timeout=30) as response:
            errors = archive_errors(expected, response.read(), label)
        if errors:
            raise ValueError("; ".join(errors))
    print("PASS: Hex serves both inspected archives byte for byte")


def members(archive):
    result = {}
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if (not member.name or path.is_absolute() or path.as_posix() != member.name.rstrip("/")
                or any(part in (".", "..") or part.startswith(".") for part in member.name.rstrip("/").split("/"))
                or not (member.isfile() or member.isdir()) or member.name in result):
            raise ValueError("Archive has an unsafe, duplicate, or nonregular member: " + member.name)
        result[member.name] = member
    return result


def inspect_package(tarball, version, files, root=ROOT):
    with tarfile.open(tarball) as archive:
        entries = members(archive)
        if set(entries) != {"VERSION", "CHECKSUM", "metadata.config", "contents.tar.gz"} or any(
                not member.isfile() for member in entries.values()):
            raise ValueError("Hex archive must contain exactly the four regular package members")
        data = {name: archive.extractfile(member).read() for name, member in entries.items()}
    digest = hashlib.sha256(data["VERSION"] + data["metadata.config"] + data["contents.tar.gz"]).hexdigest()
    if data["VERSION"] != b"3" or data["CHECKSUM"].decode().lower() != digest:
        raise ValueError("Hex archive checksum or format differs")
    metadata = data["metadata.config"].decode()
    for name, value in (("name", PACKAGE), ("version", version)):
        values = re.findall(r'\{<<"' + name + r'">>,\s*<<"([^"\n]+)">>\}\.', metadata)
        if values != [value]:
            raise ValueError("Hex archive metadata differs: " + name)
    with tarfile.open(fileobj=io.BytesIO(data["contents.tar.gz"]), mode="r:gz") as contents:
        entries = members(contents)
        actual = {name for name, member in entries.items() if member.isfile()}
        if actual != set(files):
            raise ValueError("Hex package file inventory differs from the explicit public configuration")
        for name in sorted(actual):
            if contents.extractfile(entries[name]).read() != (root / name).read_bytes():
                raise ValueError("Hex package bytes differ from the inspected source: " + name)
    print("PASS: package checksum, identity, public inventory, and source bytes")


def build_docs_archive(directory, output):
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    if not (directory / "index.html").is_file() or not (directory / "api-reference.html").is_file():
        raise ValueError("Documentation lacks index.html or api-reference.html")
    if any(path.is_symlink() for path in directory.rglob("*")):
        raise ValueError("Documentation contains a symlink")
    with output.open("wb") as destination, gzip.GzipFile(filename="", fileobj=destination, mode="wb", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for path in files:
                name = path.relative_to(directory).as_posix()
                # ExDoc cleanup inventories are build state, not public docs.
                if name.startswith(".build"):
                    continue
                data = path.read_bytes()
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(data), 0o644, 946684800
                archive.addfile(member, io.BytesIO(data))
    with tarfile.open(output, "r:gz") as archive:
        entries = members(archive)
        expected = {path.relative_to(directory).as_posix() for path in files
                    if not path.relative_to(directory).as_posix().startswith(".build")}
        if set(entries) != expected or any(not entry.isfile() for entry in entries.values()):
            raise ValueError("Documentation archive inventory differs")
        for name, member in entries.items():
            if archive.extractfile(member).read() != (directory / name).read_bytes():
                raise ValueError("Documentation archive bytes differ: " + name)
    print("PASS: deterministic documentation archive inspected")


def prepare(directory, docs, version):
    from check_docs import public_configuration
    from release import package_version
    if version != package_version((ROOT / "mix.exs").read_text()):
        raise ValueError("Requested publication version differs from mix.exs")
    configuration = public_configuration(ROOT)
    inspect_package(directory / f"{PACKAGE}-{version}.tar", version, configuration["files"])
    build_docs_archive(docs, directory / f"{PACKAGE}-{version}-docs.tar.gz")


if __name__ == "__main__":
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-registry", action="store_true")
    modes.add_argument("--plan-upload", action="store_true")
    modes.add_argument("--verify-registry", action="store_true")
    parser.add_argument("--version", required=True)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--docs", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        if args.check_registry:
            check_registry()
        elif args.plan_upload or args.verify_registry:
            if not args.directory or (args.plan_upload and not args.github_output):
                parser.error("registry planning/readback requires --directory and planning requires --github-output")
            if args.plan_upload:
                plan_upload(args.version, args.directory, args.github_output)
            else:
                verify_registry(args.version, args.directory)
        else:
            if not args.directory or not args.docs:
                parser.error("archive inspection requires --directory and --docs")
            prepare(args.directory, args.docs, args.version)
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(str(error))
