#!/usr/bin/env python3
"""Build and verify a deterministic package SBOM for CI and release artifacts."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile

from release import normalize_sbom, package_version
from processes import install_signal_handlers, run, temporary_directory

ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION = "0.12.1"
TOOL_PLATFORMS = {
    ("Linux", "x86_64"): ("mix_sbom_Linux_X64", "b490502890f692672f14619bd12798462a613ecfbab2652bd26f8c909a050fd1"),
    ("Linux", "aarch64"): ("mix_sbom_Linux_ARM64", "1366218a3a99cf9d1775513819808d0590b565ee18a307b48b141c8a1337e2ed"),
    ("Darwin", "x86_64"): ("mix_sbom_macOS_X64", "ff4cfdf710c2e2e1c9f1c57dfe2667f3a9e52b1bd2054b655e576654b9a04294"),
    ("Darwin", "arm64"): ("mix_sbom_macOS_ARM64", "7930b9e35dce94e16072ab75a12d4faf2c26b1664d5d2b6c040ccff6a1242f46"),
}


def tool_platform(system=None):
    system = system or os.uname()
    machine = system.machine
    if machine in ("arm64", "aarch64"):
        machine = "aarch64" if system.sysname == "Linux" else "arm64"
    try:
        return TOOL_PLATFORMS[(system.sysname, machine)]
    except KeyError:
        supported = ", ".join(" ".join(platform) for platform in TOOL_PLATFORMS)
        raise ValueError(f"Unsupported SBOM platform {system.sysname} {system.machine}; supported platforms: {supported}") from None


def verify_tool(path, digest=None):
    if hashlib.sha256(path.read_bytes()).hexdigest() != (digest or tool_platform()[1]):
        raise ValueError("SBOM binary checksum mismatch; refusing to execute")


def generate(output, tarball=None):
    environment = dict(os.environ, MIX_ENV="prod")
    asset, digest = tool_platform()
    url = f"https://github.com/erlef/mix_sbom/releases/download/v{TOOL_VERSION}/{asset}"

    with temporary_directory(prefix="requestseal-sbom-") as directory:
        scratch = Path(directory)
        # Burrito's extracted runtime belongs to this invocation, like the binary.
        environment["MIX_SBOM_INSTALL_DIR"] = str(scratch / "runtime")
        binary = scratch / "mix_sbom"
        run(["curl", "--fail", "--location", "--silent", "--show-error", "--retry", "3", "--max-time", "120",
             "--output", binary, url], cwd=ROOT, extra_env=environment)
        verify_tool(binary, digest)
        binary.chmod(0o700)
        run(["mix", "deps.get", "--check-locked"], cwd=ROOT, extra_env=environment)
        if tarball is None:
            version = package_version((ROOT / "mix.exs").read_text())
            tarball = scratch / f"request_seal-{version}.tar"
            run(["mix", "hex.build", "--output", tarball], cwd=ROOT, extra_env=environment)
        package = scratch / "package"
        package.mkdir()
        with tarfile.open(tarball) as archive:
            with tarfile.open(fileobj=io.BytesIO(archive.extractfile("contents.tar.gz").read()), mode="r:gz") as contents:
                contents.extractall(package, filter="data")
        run(["mix", "run", "--no-start", "scripts/release_sbom.exs", "--prepare", package], cwd=ROOT, extra_env=environment)
        bom = scratch / "sbom.cdx.json"
        run([binary, "cyclonedx", package, "--output", bom, "--schema", "1.6", "--format", "json",
            "--only", "prod", "--classification", "library", "--exclude-system-dependencies",
             "--no-enhance-metadata", "--no-vulnerabilities", "--force"], cwd=ROOT, extra_env=environment)
        run(["mix", "run", "--no-start", "scripts/release_sbom.exs", "--rewrite-scopes", bom], cwd=ROOT, extra_env=environment)
        normalize_sbom(bom, tarball)
        run(["mix", "run", "--no-start", "scripts/release_sbom.exs", "--verify", bom], cwd=ROOT, extra_env=environment)
        output.write_bytes(bom.read_bytes())
    print("PASS: checksum-pinned SBOM generated and verified; scratch files deleted", flush=True)


if __name__ == "__main__":
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tarball", type=Path)
    parser.add_argument("--output", type=Path, default=Path("sbom.cdx.json"))
    args = parser.parse_args()
    try:
        generate(args.output.resolve(), args.tarball.resolve() if args.tarball else None)
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"SBOM command deadline exceeded after {error.timeout}s: {error.cmd}")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
