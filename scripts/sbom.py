#!/usr/bin/env python3
"""Build and verify a deterministic package SBOM for CI and release artifacts."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

from release import normalize_sbom, package_version

ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION = "0.12.1"
TOOL_SHA256 = "b490502890f692672f14619bd12798462a613ecfbab2652bd26f8c909a050fd1"
TOOL_URL = f"https://github.com/erlef/mix_sbom/releases/download/v{TOOL_VERSION}/mix_sbom_Linux_X64"


def verify_tool(path):
    if hashlib.sha256(path.read_bytes()).hexdigest() != TOOL_SHA256:
        raise ValueError("SBOM binary checksum mismatch; refusing to execute")


def generate(output, tarball=None):
    environment = dict(os.environ, MIX_ENV="prod")
    # The public asset is a Linux x86-64 binary; unsupported toolchains must fail.
    if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        raise ValueError("SBOM generation requires Linux x86-64")

    def run(*args):
        print("RUN " + " ".join(map(str, args)), flush=True)
        subprocess.run(list(map(str, args)), cwd=ROOT, env=environment, check=True, timeout=900)

    with tempfile.TemporaryDirectory(prefix="requestseal-sbom-") as directory:
        scratch = Path(directory)
        # Burrito's extracted runtime belongs to this invocation, like the binary.
        environment["MIX_SBOM_INSTALL_DIR"] = str(scratch / "runtime")
        binary = scratch / "mix_sbom"
        run("curl", "--fail", "--location", "--silent", "--show-error", "--retry", "3", "--max-time", "120",
            "--output", binary, TOOL_URL)
        verify_tool(binary)
        binary.chmod(0o700)
        run("mix", "deps.get", "--check-locked")
        if tarball is None:
            version = package_version((ROOT / "mix.exs").read_text())
            tarball = scratch / f"request_seal-{version}.tar"
            run("mix", "hex.build", "--output", tarball)
        package = scratch / "package"
        package.mkdir()
        with tarfile.open(tarball) as archive:
            with tarfile.open(fileobj=io.BytesIO(archive.extractfile("contents.tar.gz").read()), mode="r:gz") as contents:
                contents.extractall(package, filter="data")
        run("mix", "run", "--no-start", "scripts/release_sbom.exs", "--prepare", package)
        bom = scratch / "sbom.cdx.json"
        run(binary, "cyclonedx", package, "--output", bom, "--schema", "1.6", "--format", "json",
            "--only", "prod", "--classification", "library", "--exclude-system-dependencies",
            "--no-enhance-metadata", "--no-vulnerabilities", "--force")
        run("mix", "run", "--no-start", "scripts/release_sbom.exs", "--rewrite-scopes", bom)
        normalize_sbom(bom, tarball)
        run("mix", "run", "--no-start", "scripts/release_sbom.exs", "--verify", bom)
        output.write_bytes(bom.read_bytes())
    print("PASS: checksum-pinned SBOM generated and verified; scratch files deleted", flush=True)


if __name__ == "__main__":
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
