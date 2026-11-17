#!/usr/bin/env python3
"""Prove JWE guards non-vacuous by applying each committed reversing patch."""
import argparse
import json
from pathlib import Path
import sys

import processes

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "test/mutations/jwe_open"


def command(argv, *, check=True):
    return processes.run(argv, cwd=ROOT, capture_output=True, text=True, check=check)


def clean():
    status = command(["git", "status", "--porcelain", "--untracked-files=all"]).stdout
    if status:
        raise RuntimeError("mutation runner requires a clean tree:\n" + status)


def prove(entry):
    patch = DIRECTORY / entry["patch"]
    clean()
    applied = False
    evidence = ""
    try:
        command(["git", "apply", "--check", patch])
        command(["git", "apply", patch])
        applied = True
        result = command(["mix", "test", entry["file"], "--only", entry["selection"]], check=False)
        evidence = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            raise RuntimeError("mutation remained GREEN")
        if entry["failure"] not in evidence:
            raise RuntimeError("mutation failed without its claimed assertion:\n" + evidence)
        return "RED: " + entry["failure"]
    finally:
        if applied:
            command(["git", "apply", "-R", patch])
        clean()


def main():
    processes.install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="One patch basename; otherwise every mutation")
    args = parser.parse_args()
    entries = json.loads((DIRECTORY / "manifest.json").read_text())["mutations"]
    if args.only:
        entries = [entry for entry in entries if entry["patch"] == args.only]
        if not entries:
            parser.error("unknown mutation")
    rows = []
    failed = False
    for entry in entries:
        try:
            evidence = prove(entry)
        except Exception as error:
            failed = True
            evidence = "FAIL: " + str(error)
        rows.append((entry["patch"], entry["test"], evidence))
        if "clean tree" in evidence:
            break
    print("| Mutation | Test | Red evidence |")
    print("|---|---|---|")
    for patch, test, evidence in rows:
        print(f"| {patch} | {test} | {evidence.replace('|', '/').replace(chr(10), ' ')} |")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
