#!/usr/bin/env python3
"""Prove guards non-vacuous by applying each committed reversing patch."""
import argparse
import json
from pathlib import Path
import sys

import processes

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "test/mutations/jwe_open"


def command(argv, *, check=True, root=ROOT):
    return processes.run(argv, cwd=root, capture_output=True, text=True, check=check)


def clean(root=ROOT):
    status = command(["git", "status", "--porcelain", "--untracked-files=all"], root=root).stdout
    if status:
        raise RuntimeError("mutation runner requires a clean tree:\n" + status)


def prove(entry, *, green=None, root=ROOT, directory=DIRECTORY,
          test_command=("mix", "test")):
    patch = directory / entry["patch"]
    clean(root)
    argv = [*test_command, entry["file"], "--only", "test:test " + entry["test"]]
    # The cache belongs to this run, whose baseline and command stay unchanged.
    # Never cache a failing or tree-dirtying baseline.
    head = command(["git", "rev-parse", "HEAD"], root=root).stdout.strip()
    key = tuple(map(str, [root, head, *argv]))
    if green is None or key not in green:
        result = command(argv, root=root, check=False)
        if result.returncode != 0:
            raise RuntimeError("baseline is not GREEN:\n" +
                               (result.stdout or "") + (result.stderr or ""))
        clean(root)
        if green is not None:
            green.add(key)
    applied = False
    try:
        command(["git", "apply", "--check", patch], root=root)
        command(["git", "apply", patch], root=root)
        applied = True
        result = command(argv, root=root, check=False)
        evidence = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            raise RuntimeError("mutation remained GREEN")
        if entry["failure"] not in evidence:
            raise RuntimeError("mutation failed without its claimed assertion:\n" + evidence)
        return "GREEN baseline; RED: " + entry["failure"]
    finally:
        if applied:
            command(["git", "apply", "-R", patch], root=root)
        clean(root)


def main():
    processes.install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("jwe_open", "finch"),
                        help="One suite; otherwise every suite")
    parser.add_argument("--only", help="One patch basename; otherwise every mutation")
    args = parser.parse_args()
    entries = []
    for suite in ([args.suite] if args.suite else ["jwe_open", "finch"]):
        directory = ROOT / "test/mutations" / suite
        entries.extend((directory, entry) for entry in
                       json.loads((directory / "manifest.json").read_text())["mutations"])
    if args.only:
        entries = [(directory, entry) for directory, entry in entries if entry["patch"] == args.only]
        if not entries:
            parser.error("unknown mutation")
    rows = []
    green = set()
    failed = False
    for directory, entry in entries:
        try:
            evidence = prove(entry, green=green, directory=directory)
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
