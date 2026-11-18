#!/usr/bin/env python3
"""Read CI runtime lanes and the Node pin from .tool-versions, and service images from
.github/service-images: the one home of every pin a workflow uses."""
import argparse
import json
import os
import subprocess
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def toolchain(source):
    pins = {}
    for line in source.splitlines():
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        name, *versions = fields
        if name in pins:
            raise ValueError(f"Duplicate tool pin: {name}")
        pins[name] = versions

    elixir = pins.get("elixir", [])
    erlang = pins.get("erlang", [])
    node = pins.get("nodejs", [])
    if len(elixir) != 3 or len(erlang) != 3 or len(node) != 1:
        raise ValueError("Expected three paired Elixir/OTP pins and one Node pin")
    if not re.fullmatch(r"\d+\.\d+\.\d+", node[0]):
        raise ValueError("Node must have an exact version pin")

    pairs = []
    for version, otp in zip(elixir, erlang):
        match = re.fullmatch(r"(\d+\.\d+\.\d+)-otp-(\d+)", version)
        if not match or not re.fullmatch(r"\d+(?:\.\d+)+", otp):
            raise ValueError("Expected exact Elixir-otp-major and OTP version pins")
        if match[2] != otp.split(".")[0]:
            raise ValueError("Positionally paired Elixir and OTP pins disagree")
        pairs.append({"elixir": match[1], "otp": otp})
    pairs.sort(key=lambda pair: tuple(map(int, pair["elixir"].split("."))))
    if len({pair["elixir"] for pair in pairs}) != 3:
        raise ValueError("Elixir runtime lanes must be distinct")
    lanes = [dict(lane=lane, **pair) for lane, pair in zip(("floor", "mid", "latest"), pairs)]
    return {"matrix": {"include": lanes}, "node": node[0], **pairs[-1]}


SERVICES = {"postgres": re.compile(r"postgres@sha256:[0-9a-f]{64}")}


def service_images(source):
    """Each CI service image, pinned by digest so a moving tag cannot change what runs."""
    images = {}
    for line in source.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        name, separator, image = (part.strip() for part in entry.partition("="))
        if not separator or name not in SERVICES:
            raise ValueError(f"Unknown service image entry: {entry}")
        if name in images:
            raise ValueError(f"Duplicate service image: {name}")
        if not SERVICES[name].fullmatch(image):
            raise ValueError(f"Service image {name} must be pinned by sha256 digest")
        images[name] = image
    if images.keys() != SERVICES.keys():
        raise ValueError("Expected exactly one image for each service: " + ", ".join(SERVICES))
    return {f"{name}_image": image for name, image in images.items()}


def installed_errors(expected_elixir, expected_otp, installed):
    """Compare full releases, including every OTP patch component."""
    expected = [expected_elixir, expected_otp]
    return [] if installed == expected else [f"Runtime differs: expected {expected}, installed {installed}"]


def verify_installed():
    expression = ('IO.puts(System.version()); '
                  'IO.puts(File.read!(Path.join([to_string(:code.root_dir()), '
                  '"releases", System.otp_release(), "OTP_VERSION"])) |> String.trim())')
    installed = subprocess.run(["elixir", "-e", expression], check=True, capture_output=True,
                               text=True, timeout=30).stdout.splitlines()
    errors = installed_errors(os.environ["EXPECTED_ELIXIR"], os.environ["EXPECTED_OTP"], installed)
    if errors:
        raise SystemExit("; ".join(errors))
    print("PASS: installed Elixir and full OTP release match .tool-versions")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--verify-installed", action="store_true")
    args = parser.parse_args()
    if args.verify_installed:
        if args.github_output:
            parser.error("--verify-installed cannot write GitHub outputs")
        verify_installed()
        return
    configuration = toolchain((ROOT / ".tool-versions").read_text())
    configuration |= service_images((ROOT / ".github/service-images").read_text())
    if args.github_output:
        with args.github_output.open("a") as output:
            for key, value in configuration.items():
                value = json.dumps(value, separators=(",", ":")) if isinstance(value, dict) else value
                output.write(f"{key}={value}\n")
    else:
        print(json.dumps(configuration))


if __name__ == "__main__":
    main()
