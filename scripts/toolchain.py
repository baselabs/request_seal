#!/usr/bin/env python3
"""Read CI runtime lanes and the Node pin from .tool-versions."""
import argparse
import json
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    configuration = toolchain((ROOT / ".tool-versions").read_text())
    if args.github_output:
        with args.github_output.open("a") as output:
            for key, value in configuration.items():
                value = json.dumps(value, separators=(",", ":")) if isinstance(value, dict) else value
                output.write(f"{key}={value}\n")
    else:
        print(json.dumps(configuration))


if __name__ == "__main__":
    main()
