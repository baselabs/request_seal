#!/usr/bin/env python3
"""Inspect publication archives and anonymously refuse absent names or existing versions."""
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


def registry_errors(package, version, metadata):
    if not isinstance(metadata, dict) or metadata.get("name") != package:
        return ["Registry package identity differs: " + package]
    releases = metadata.get("releases")
    if not isinstance(releases, list) or not releases or any(
            not isinstance(row, dict) or not isinstance(row.get("version"), str) for row in releases):
        return ["Registry release inventory is missing or invalid: " + package]
    if any(row["version"] == version for row in releases):
        return [f"Version is already published: {package} {version}"]
    return []


def check_registry(version):
    request = Request("https://hex.pm/api/packages/" + PACKAGE,
                      headers={"User-Agent": "RequestSeal-publication"})
    try:
        with urlopen(request, timeout=30) as response:
            metadata = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            raise ValueError("Package does not exist on Hex; first publication is the owner's decision: " + PACKAGE) from None
        raise ValueError(f"Cannot read Hex package {PACKAGE}: HTTP {error.code}") from None
    errors = registry_errors(PACKAGE, version, metadata)
    if errors:
        raise ValueError("; ".join(errors))
    print(f"PASS: Hex name exists and {PACKAGE} {version} is unpublished")


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
    parser.add_argument("--check-registry", action="store_true")
    parser.add_argument("--version", required=True)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--docs", type=Path)
    args = parser.parse_args()
    try:
        if args.check_registry:
            check_registry(args.version)
        else:
            if not args.directory or not args.docs:
                parser.error("archive inspection requires --directory and --docs")
            prepare(args.directory, args.docs, args.version)
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(str(error))
