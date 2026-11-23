#!/usr/bin/env python3
"""Run one paired JWE benchmark round or collect a publication verdict."""
import argparse
import json
import math
import os
from pathlib import Path
from statistics import median
import subprocess
import sys

from host_conditions import load_average, metrics
import processes
from release import package_version

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ROOT / "bench/release_gates"
BASELINE = "1.0.0"
ROUNDS = 24
WORKLOADS = ("page", "single")
SIZES = {
    "release": {"pairs": 3, "page": 15, "single": 2000},
    "self-check": {"pairs": 1, "page": 3, "single": 10},
}
GATES = {
    "page_absolute_us": ("page", "candidate_us", 5, 4200),
    "page_relative": ("page", "ratio", 20, 1.00),
    "single_absolute_us": ("single", "candidate_us", 5, 140),
    "single_relative": ("single", "ratio", 20, 3.2),
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def sides(mode):
    return ("baseline", "candidate") * SIZES[mode]["pairs"]


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def observe(window, cpus):
    counters = {key: window[key] for key in ("cpu_before", "cpu_after", "process_before", "process_after")}
    loads = (window["load_before"], window["load_after"])
    if not all(nonempty(value) for value in (*loads, counters["cpu_before"], counters["cpu_after"])):
        raise ValueError("incomplete /proc window")
    observation = {"loadavg": max(loads, key=load_average), **counters}
    return metrics(observation, cpus)


def summarize(sample_sets, host, mode, candidate_version):
    cpus = host["logical_cpus"]
    if type(cpus) is not int or cpus < 1 or not all(
            nonempty(host[key]) for key in ("cpu_model", "image_version")):
        raise ValueError("incomplete host identity")
    order = sides(mode)
    if len(sample_sets) != len(order):
        raise ValueError("wrong number of sample sets")
    otp, schedulers = sample_sets[0]["otp"], sample_sets[0]["schedulers_online"]
    if not nonempty(otp) or type(schedulers) is not int or not 0 < schedulers <= cpus:
        raise ValueError("incomplete runtime identity")

    versions = {"baseline": BASELINE, "candidate": candidate_version}
    times = {name: {side: [] for side in versions} for name in WORKLOADS}
    rejected = []
    for index, (side, sample_set) in enumerate(zip(order, sample_sets), 1):
        if (sample_set["side"] != side or sample_set["version"] != versions[side] or
                sample_set["otp"] != otp or type(sample_set["schedulers_online"]) is not int or
                sample_set["schedulers_online"] != schedulers):
            raise ValueError(f"sample set {index} used a different side, version or runtime")
        for name in WORKLOADS:
            window = sample_set[name]
            if (type(window["samples"]) is not int or window["samples"] < SIZES[mode][name] or
                    type(window["warmups"]) is not int or window["warmups"] != 30 or
                    not positive(window["median_us"])):
                raise ValueError(f"invalid {name} evidence for sample set {index}")
            times[name][side].append(window["median_us"])
        observation = observe(sample_set["host_window"], cpus)
        if sample_set["admission"] != observation:
            raise ValueError(f"invalid host admission for sample set {index}")
        if not observation["admitted"]:
            rejected.append({"sample_set": index, "side": side, "load": observation["load"],
                             "steal": observation["steal"], "foreign_cpu": observation["foreign_cpu"],
                             "resolution": observation["resolution"]})

    workloads = {}
    for name, by_side in times.items():
        baseline = median(by_side["baseline"])
        candidate = median(by_side["candidate"])
        ratio = candidate / baseline
        if not positive(ratio):
            raise ValueError(f"invalid {name} ratio")
        workloads[name] = {"baseline_us": baseline, "candidate_us": candidate, "ratio": ratio}
    return {"otp": otp, "schedulers_online": schedulers, "versions": versions,
            "admitted": not rejected, "rejected_windows": rejected, "workloads": workloads}


def run_round(args, mode, candidate_version):
    output = {"round": args.id, "commit": args.commit, "mode": mode, "sample_sets": []}
    try:
        cpus = os.cpu_count()
        if cpus is None:
            raise ValueError("unavailable logical CPU count")
        cpu_model = next(line.split(":", 1)[1].strip()
                         for line in Path("/proc/cpuinfo").read_text().splitlines()
                         if line.startswith("model name"))
        output["host"] = {"logical_cpus": cpus, "cpu_model": cpu_model,
                          "image_version": os.environ["ImageVersion"]}
        with processes.temporary_directory(prefix="requestseal-release-gate-") as scratch:
            environments = {}
            for side in dict.fromkeys(sides(mode)):
                environments[side] = {"MIX_ENV": "prod",
                                      "MIX_BUILD_PATH": str(Path(scratch) / side / "_build"),
                                      "MIX_DEPS_PATH": str(Path(scratch) / side / "deps")}
                for command in (["mix", "deps.get", "--check-locked"], ["mix", "hex.audit"],
                                ["mix", "deps.audit"], ["mix", "compile", "--warnings-as-errors"]):
                    processes.run(command, cwd=PROJECTS / side, extra_env=environments[side], timeout=180)
            for index, side in enumerate(sides(mode), 1):
                path = Path(scratch) / f"sample-{index}.json"
                processes.run(["mix", "run", "--no-compile", "--no-deps-check",
                               "workload.exs", mode, path],
                              cwd=PROJECTS / side, extra_env=environments[side], timeout=120)
                sample_set = json.loads(path.read_text())
                sample_set["admission"] = observe(sample_set["host_window"], cpus)
                output["sample_sets"].append({"side": side, **sample_set})
        output.update(summarize(output["sample_sets"], output["host"], mode, candidate_version))
        print(f"Round {args.id} ({mode}): {'admitted' if output['admitted'] else 'unmeasured'}")
        return 0
    except (OSError, StopIteration, subprocess.SubprocessError, KeyError, TypeError,
            ValueError, OverflowError, IndexError) as error:
        output["error"] = str(error) or type(error).__name__
        print(f"Round {args.id} ({mode}) unmeasured: {output['error']}", file=sys.stderr)
        return 1
    finally:
        write_json(args.output, output)


def collect(paths, mode, commit, candidate_version):
    expected = set(range(1, (1 if mode == "self-check" else ROUNDS) + 1))
    admitted, rejected, errors, seen = {}, {}, [], set()
    host_windows = []
    for path in sorted(paths):
        try:
            round_data = json.loads(path.read_text())
            number = round_data["round"]
            if type(number) is not int or number not in expected or number in seen:
                raise ValueError("unexpected or duplicate round number")
            seen.add(number)
            if round_data["commit"] != commit or round_data["mode"] != mode:
                raise ValueError("different commit or measurement mode")
            if "error" in round_data:
                raise ValueError(f"round did not complete: {round_data['error']}")
            summary = summarize(round_data["sample_sets"], round_data["host"], mode, candidate_version)
            if (type(round_data["admitted"]) is not bool or
                    any(round_data[key] != value for key, value in summary.items())):
                raise ValueError("stored round summary disagrees with sample sets")
            if mode == "self-check":
                host_windows = [
                    {"sample_set": index, "side": sample_set["side"], **sample_set["admission"]}
                    for index, sample_set in enumerate(round_data["sample_sets"], 1)
                ]
            if summary["admitted"]:
                admitted[number] = summary["workloads"]
            else:
                rejected[number] = summary["rejected_windows"]
        except (OSError, KeyError, TypeError, ValueError, OverflowError, IndexError) as error:
            errors.append(f"{path.parent.name}/{path.name}: {error}")

    missing = sorted(expected - seen)
    if missing:
        errors.append("missing round artifacts: " + ", ".join(map(str, missing)))

    gates = {}
    if mode == "release":
        for name, (workload, metric, minimum, limit) in GATES.items():
            value = median(row[workload][metric] for row in admitted.values()) if len(admitted) >= minimum else None
            status = "unmeasured" if value is None else "pass" if value <= limit else "fail"
            gates[name] = {"status": status, "value": value, "limit": limit, "min_rounds": minimum}

    verdict = {"mode": mode, "commit": commit, "versions": {"baseline": BASELINE, "candidate": candidate_version},
               "passed": not errors and all(gate["status"] == "pass" for gate in gates.values()),
               "admitted_rounds": sorted(admitted), "unmeasured_rounds": rejected,
               "missing_rounds": missing, "errors": errors, "gates": gates}
    if mode == "self-check":
        verdict["host_windows"] = host_windows
    return verdict


def print_verdict(verdict):
    print(f"{verdict['mode']} verdict for {verdict['commit']}")
    print(f"Admitted rounds: {len(verdict['admitted_rounds'])}")
    for number, reasons in verdict["unmeasured_rounds"].items():
        for reason in reasons:
            print(f"Round {number} unmeasured ({reason['side']}, "
                  f"sample set {reason['sample_set']}): load {reason['load']}, "
                  f"steal {reason['steal']}%, foreign CPU {reason['foreign_cpu']}%, "
                  f"resolution {reason['resolution']} percentage points")
    for error in verdict["errors"]:
        print(error)
    if verdict["mode"] == "self-check":
        print("Self-check: schema and measurement mechanics only")
        for window in verdict["host_windows"]:
            print(f"Self-check {window['side']} (sample set {window['sample_set']}): "
                  f"foreign CPU {window['foreign_cpu']}%, steal {window['steal']}%, "
                  f"resolution {window['resolution']} percentage points")
    else:
        print(f"{'Gate':<20} {'Median':>12} {'Limit':>8} {'Rounds needed':>14}  Result")
        for name, gate in verdict["gates"].items():
            value = "-" if gate["value"] is None else f"{gate['value']:.6g}"
            print(f"{name:<20} {value:>12} {gate['limit']:>8g} {gate['min_rounds']:>14}  {gate['status']}")
    print("PASS" if verdict["passed"] else "FAIL")


def main():
    processes.install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("round")
    run.add_argument("--id", required=True, type=int, choices=range(1, ROUNDS + 1))
    verdict = commands.add_parser("collect")
    verdict.add_argument("--rounds", required=True, type=Path)
    for command in (run, verdict):
        command.add_argument("--self-check", action="store_true")
        command.add_argument("--commit", required=True)
        command.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    mode = "self-check" if args.self_check else "release"
    candidate_version = package_version((ROOT / "mix.exs").read_text())
    if args.command == "round":
        if args.self_check and args.id != 1:
            parser.error("self-check uses round 1")
        return run_round(args, mode, candidate_version)
    result = collect(args.rounds.rglob("round.json"), mode, args.commit, candidate_version)
    write_json(args.output, result)
    print_verdict(result)
    return int(not result["passed"])


if __name__ == "__main__":
    sys.exit(main())
