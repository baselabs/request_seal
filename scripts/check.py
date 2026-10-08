#!/usr/bin/env python3
"""Run the checked-in scaffold contract on macOS and Linux; no service startup."""
import argparse
import os
import math
import re
import selectors
import time
import signal
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def run(argv, cwd=ROOT, timeout=900, extra_env=None):
    print("RUN " + " ".join(argv), flush=True)
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True)
        status = process.wait(timeout=timeout)
        if status:
            raise subprocess.CalledProcessError(status, argv)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # Kill any descendants still in the group even if the direct child exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise SystemExit(f"Deadline exceeded after {timeout}s: {argv}")

def stop_group(process):
    # Keep an unreaped leader until all signals finish; never target a reused pgid.
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        # macOS denies signaling a group whose leader exited unreaped; the
        # SIGKILL step below proves the exit before discharging the error.
        pass
    time.sleep(0.2)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Some hosts deny signaling an exited, unreaped group leader. Only
        # discharge that error when wait proves this owned child already exited.
        process.wait(timeout=0)
    process.wait()


def execute_notebook(script, completion, timeout=300, maximum_output=1_048_576):
    """Execute a real exported notebook with bounded bytes, time, and descendants."""
    if not math.isfinite(timeout) or timeout <= 0 or maximum_output <= 0:
        raise ValueError("Notebook execution limits must be positive and finite")
    if not completion or "\n" in completion or "\r" in completion:
        raise ValueError("Notebook completion must be one nonempty line")
    script = Path(script).resolve(strict=True)
    process = subprocess.Popen(["elixir", str(script)], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Notebook execution deadline exceeded:\n" + output.decode("utf-8", errors="replace"))
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(output) + len(chunk) > maximum_output:
                        raise ValueError("Notebook output limit exceeded:\n" + output.decode("utf-8", errors="replace"))
                    output.extend(chunk)
        try:
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Notebook execution deadline exceeded:\n" + output.decode("utf-8", errors="replace")) from error
        text = output.decode("utf-8")
        if status:
            raise ValueError(f"Notebook failed ({status}):\n{text}")
        if text.splitlines().count(completion) != 1:
            raise ValueError(f"Notebook did not complete exactly once:\n{text}")
        return text, status
    finally:
        try:
            stop_group(process)
        finally:
            process.stdout.close()


def toolchain_errors(sources):
    """Validate the consumer range, exact tooling identity, and all three CI lanes."""
    errors = []
    versions = {}
    for number, line in enumerate(sources[".tool-versions"].splitlines(), 1):
        tokens = line.partition("#")[0].split()
        if not tokens:
            continue
        if len(tokens) != 2 or tokens[0] in versions:
            return [f"Invalid version-manager declaration on line {number}"]
        versions[tokens[0]] = tokens[1]
    match = re.fullmatch(r"(\d+\.\d+\.\d+)-otp-(\d+)", versions.get("elixir", ""))
    otp = versions.get("erlang", "")
    if not match or not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", otp):
        return ["Invalid exact version-manager identity"]
    node = versions.get("nodejs", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", node):
        errors.append("Node requires an exact version-manager identity")
    elixir, major = match.groups()
    if otp.split(".")[0] != major:
        errors.append("Version-manager Elixir/OTP identities disagree")
    postgres_env = "\n        env:\n          REQUESTSEAL_REPLAY_PG_URL: postgres://postgres:postgres@127.0.0.1:${{ job.services.postgres.ports['5432'] }}/postgres"
    required = {
        "mix.exs": ['elixir: "~> 1.18"', "unless Code.ensure_loaded?(:json) do",
            '{:finch, ">= 0.23.0 and < 0.25.0", optional: true, runtime: false}',
            '{:req, "~> 0.7.4", optional: true, runtime: false}'],
        "tools/notebooks/mix.exs": [f'elixir: "{elixir}"'],
        "config/config.exs": ["minimum_otp = 27", ":erlang.system_info(:otp_release) |> to_string() |> String.to_integer()", "if running_otp < minimum_otp do"],
        "tools/notebooks/config/config.exs": ['import_config "../../../config/config.exs"', f'expected_otp = "{major}"', 'to_string(:erlang.system_info(:otp_release))', "if running_otp != expected_otp do"],
        "livebooks/environment.livemd": [f'"{elixir}" = System.version()', f'"{major}" = System.otp_release()'],
        ".github/workflows/ci.yml": [
            "runs-on: ubuntu-24.04", "timeout-minutes: 40", "fail-fast: false",
            "postgres:\n        image: postgres:18",
            "- lane: mid\n            elixir: '1.19.5'\n            otp: '28.5.0.7'",
            "- if: matrix.lane == 'mid'\n        run: mix test --warnings-as-errors" + postgres_env,
            "- if: matrix.lane == 'floor'\n        run: python3 scripts/check_optional_clients.py",
            "- lane: floor\n            elixir: '1.18.4'\n            otp: '27.3.4'",
            f"- lane: latest\n            elixir: '{elixir}'\n            otp: '{otp}'",
            "elixir-version: ${{ matrix.elixir }}", "otp-version: ${{ matrix.otp }}",
            "version-type: strict", f"node-version: '{node}'",
            "- if: matrix.lane == 'floor'\n        run: mix test --warnings-as-errors" + postgres_env,
            "- if: matrix.lane == 'latest'\n        run: python3 scripts/check.py" + postgres_env,
        ],
    }
    for path, values in required.items():
        for value in values:
            if sources[path].count(value) != 1:
                errors.append(f"{path}: missing or duplicated toolchain binding {value}")
    actions = re.findall(r"uses:\s*(\S+)", sources[".github/workflows/ci.yml"])
    required_actions = {"actions/checkout", "erlef/setup-beam", "actions/setup-python", "actions/setup-node"}
    if not required_actions.issubset({action.split("@", 1)[0] for action in actions}) or any(not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action) for action in actions):
        errors.append("CI actions must use immutable commit identities")
    return errors


def check_toolchain():
    paths = (".tool-versions", "mix.exs", "config/config.exs", ".github/workflows/ci.yml",
        "tools/notebooks/mix.exs", "tools/notebooks/config/config.exs", "livebooks/environment.livemd")
    errors = toolchain_errors({path: (ROOT/path).read_text() for path in paths})
    if errors:
        raise ValueError("\n".join(errors))
    print("PASS: consumer range, development/notebook pins, and all three CI lanes agree; CI actions use immutable commits")


def normalize_exdoc_inventory(output, project_root=ROOT):
    # ExDoc 0.40 emits absolute paths for copied Livebooks in its cleanup inventory.
    # Keep cleanup functional without including developer paths in served artifacts.
    output = output.resolve()
    project_root = project_root.resolve()
    for inventory in sorted(output.glob(".build*")):
        if not inventory.is_file() or inventory.is_symlink():
            raise ValueError("ExDoc inventory must be a regular generated file")
        entries = []
        for value in inventory.read_text().splitlines():
            item = Path(value)
            target = (item if item.is_absolute() else output / item).resolve()
            # EPUB uses paths relative to the invoking project; HTML/Markdown
            # inventories use paths relative to their output directory.
            if not item.is_absolute() and not target.is_file() and inventory.name == ".build.epub":
                target = (project_root / item).resolve()
            if not target.is_relative_to(output) or not target.is_file():
                raise ValueError("ExDoc inventory targets a missing or outside file")
            entries.append(target.relative_to(output).as_posix())
        inventory.write_text("".join(entry + "\n" for entry in entries))


def notebooks():
    tooling = ROOT / "tools/notebooks"
    run(["mix", "deps.get", "--check-locked"], tooling)
    run(["mix", "hex.audit"], tooling)
    run(["mix", "format", "--check-formatted"], tooling)
    run(["mix", "run", "--no-start", "check.exs", "--self-test"], tooling)
    run(["mix", "run", "--no-start", "check.exs"], tooling,
        extra_env={"REQUESTSEAL_PATH": str(ROOT), "REQUESTSEAL_PYTHON": sys.executable})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notebooks-only", action="store_true")
    parser.add_argument("--execute-notebook", nargs=2, metavar=("SCRIPT", "COMPLETION"))
    parser.add_argument("--notebook-timeout", type=float, default=300)
    args = parser.parse_args()
    try:
        if args.execute_notebook:
            output, _ = execute_notebook(*args.execute_notebook, timeout=args.notebook_timeout)
            print(output, end="")
            raise SystemExit(0)
        check_toolchain()
        if not args.notebooks_only:
            run(["mix", "format", "--check-formatted"])
            run(["mix", "compile", "--warnings-as-errors"])
            run(["mix", "test", "--warnings-as-errors"])
            run([sys.executable, "scripts/check_optional_clients.py"])
            run([sys.executable, "-m", "unittest", "discover", "-s", "test", "-p", "*_test.py"])
            run([sys.executable, "scripts/check_docs.py"])
            run(["mix", "docs", "--warnings-as-errors"])
            normalize_exdoc_inventory(ROOT / "doc")
            run(["mix", "hex.audit"])
        notebooks()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
    except (ValueError, TimeoutError) as error:
        raise SystemExit(str(error))
    print("PASS: library contract and all shipped notebooks")
