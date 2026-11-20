#!/usr/bin/env python3
"""Measure absolute trigger-to-last-end-marker monotonic microseconds against
Bounds B(10,000), and derived K_pf against Bounds K_pf. Samples are admitted only
when /proc/loadavg is at most the host logical CPU admission count and /proc/stat CPU steal is at
most 5% over the sample window. Exhausted host-condition or placement budgets
fail, never skip. Retain host identity, observations and absolute headroom.
CPU counter windows span at least 20 ms; that observation delay is outside all
timed units and does not alter the absolute runtime measurements.
End markers use VM exit timestamps, or DOWN receipt upper bounds from a dedicated
high-priority receiver for sensitive children. Collection has a separate hang cap;
all samples survive a bound violation, with placement and incomplete-lifecycle
diagnostics.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import sys

import processes

ROOT = Path(__file__).resolve().parents[1]


def bounds():
    """Independently check reported constants against the shipped Bounds source."""
    source = (ROOT / "lib/request_seal/jose/jwe/bounds.ex").read_text()
    values = {}
    for name in ("max_tokens", "base_teardown_us", "per_item_teardown_us", "preflight_us"):
        match = re.search(r"^  @" + name + r" ([\d_]+)$", source, re.MULTILINE)
        if match is None:
            raise ValueError("cannot read Bounds constant: " + name)
        values[name] = int(match[1].replace("_", ""))
    if ("def teardown(n), do: @base_teardown_us + @per_item_teardown_us * n" not in source or
            "def preflight, do: @preflight_us" not in source):
        raise ValueError("Bounds derivation changed; update its independent gate check")
    n = values["max_tokens"]
    return n, values["base_teardown_us"] + values["per_item_teardown_us"] * n, values["preflight_us"]


def cpu_times(text):
    """Parse Linux's aggregate CPU counters; guest time is already in user/nice."""
    fields = text.splitlines()[0].split()
    if fields[0] != "cpu" or len(fields) < 9:
        raise ValueError("missing aggregate /proc/stat CPU counters")
    values = [int(value) for value in fields[1:9]]
    if any(value < 0 for value in values):
        raise ValueError("negative CPU counter")
    return sum(values), values[7]


def load_average(text):
    value = float(text.split()[0])
    if not math.isfinite(value) or value < 0:
        raise ValueError("invalid /proc/loadavg")
    return value


def steal_percent(before, after):
    total_before, steal_before = cpu_times(before)
    total_after, steal_after = cpu_times(after)
    elapsed, stolen = total_after - total_before, steal_after - steal_before
    if elapsed <= 0 or stolen < 0 or stolen > elapsed:
        return None
    return 100 * stolen / elapsed


def admit(observations, cpus, attempts):
    """Replay the shared load/steal retry budget from retained /proc samples."""
    seen = []
    for observation in observations[:attempts]:
        load = load_average(observation["loadavg"])
        steal = steal_percent(observation["cpu_before"], observation["cpu_after"])
        seen.append({"load": load, "steal": steal})
        if observation["load"] != load or observation["steal"] != steal:
            raise ValueError("host observation disagrees with /proc counters")
        if load <= cpus and load <= os.cpu_count() and steal is not None and 0 <= steal <= 5:
            return observation
    raise ValueError("host condition exhausted: " + json.dumps(seen))


def cpu_counters(text):
    cpu_times(text)
    return tuple(int(value) for value in text.splitlines()[0].split()[1:9])


def monotonic(before, after):
    return all(a <= b for a, b in zip(cpu_counters(before), cpu_counters(after)))


def host_snapshot():
    """Read on the runner, independently of the Elixir report producer."""
    return {"stat": Path("/proc/stat").read_text().splitlines()[0],
            "loadavg": Path("/proc/loadavg").read_text().strip()}


def bracketed(history, brackets):
    previous = brackets["before"]["stat"]
    for row in history:
        if not (monotonic(previous, row["cpu_before"]) and
                monotonic(row["cpu_before"], row["cpu_after"]) and
                monotonic(row["cpu_after"], brackets["after"]["stat"])):
            return False
        previous = row["cpu_after"]
    return True


def host_samples(conditions, loads, steals, online, attempts, cpus, brackets, *, ordered=True):
    if not (len(conditions) == len(loads) == len(steals) == 5):
        return False
    previous = brackets["before"]["stat"]
    for history, load, steal in zip(conditions, loads, steals):
        if not history or len(history) > attempts:
            return False
        # An exit upper bound can originate in a one- or two-scheduler peer.
        selected_online = history[-1]["schedulers_online"]
        if selected_online not in online or any(
                row["schedulers_online"] != selected_online for row in history):
            return False
        if any(row["admission_cpus"] != cpus for row in history) or not bracketed(history, brackets):
            return False
        if ordered and not monotonic(previous, history[0]["cpu_before"]):
            return False
        previous = history[-1]["cpu_after"]
        accepted = admit(history, cpus, attempts)
        if accepted is not history[-1] or accepted["load"] != load or accepted["steal"] != steal:
            return False
    return True


def markdown(report):
    if "error" in report:
        return ("Teardown gate failed: " + report["error"] + "\nHost: " +
                json.dumps(report.get("host", {})) + "\n" + report.get("output", ""))
    host, constants = report["host"], report["constants"]
    rows = [f"Host: {host['cpu_model']}; logical CPUs: {host['logical_cpus']}; "
            f"online schedulers: {host['schedulers_online']}; admission CPUs: {host['admission_cpus']}; "
            f"OTP: {host['otp']}.",
            f"Absolute limits from Bounds: B({constants['n']}) = {constants['b_us']} us; "
            f"K_pf = {constants['k_pf_us']} us.", "",
            "| Scenario | Five trigger-to-last-end times (us) | Max / B | Load | CPU steal (%) |",
            "|---|---|---|---|---|"]
    for sample in report["scenarios"]:
        rows.append("| {} | {} | {:.3%} | {} | {} |".format(sample["scenario"],
            ", ".join(map(str, sample["times_us"])),
            max(sample["times_us"]) / constants["b_us"],
            ", ".join(map(str, sample["loads"])), ", ".join(map(str, sample["steals"]))))
    for sample in report["scenarios"]:
        for index, (elapsed, placement, diagnostic) in enumerate(zip(
                sample["times_us"], sample["placements"], sample["diagnostics"]), 1):
            if elapsed > constants["b_us"] or not complete(diagnostic):
                rows.append(f"\n{sample['scenario']} sample {index}: {elapsed} us; "
                            f"{placement}; {json.dumps(diagnostic, sort_keys=True)}")
    # Heap/reduction observations and VM-shared GC intervals are diagnostic
    # evidence only. Neither their availability nor their values decide pass.
    workers = {sample["scenario"]: [d.get("workers", []) for d in sample["diagnostics"]]
               for sample in report["scenarios"]}
    rows += ["", "Worker observations (last-live end snapshots; VM-shared GC deltas):",
             "```json", json.dumps(workers, indent=2), "```"]
    rows += ["", "| Unit | Five times (us) | Load | CPU steal (%) |", "|---|---|---|---|"]
    for name, values in report["units_us"].items():
        loads, steals = report["units_loads"][name], report["units_steals"][name]
        rows.append(f"| {name} | {', '.join(map(str, values))} | {loads} | {steals} |")
    for sample in report["scenarios"]:
        if sample["scenario"].startswith("D/"):
            rows.append(f"| {sample['scenario']} cooperative exit | {sample['preflight_exit_us']} | | |")
    rows += ["", "Unit entry-module setup (no measured operation executed):", "```json",
             json.dumps(report.get("unit_setup", []), indent=2), "```",
             "Retained scan timings:", "```json",
             json.dumps(report.get("units_details", {}).get("separator_and_accounting", []), indent=2),
             "```"]
    rows += ["", f"Derived K_pf: {report['derived_k_pf_us']} us; "
             f"{report['derived_k_pf_us'] / constants['k_pf_us']:.3%} of Bounds K_pf.",
             f"S5c preflight exits: {report['s5c_exit_us']} us.", "",
             "Host observations (including rejected attempts):", "```json",
             json.dumps({"scenarios": {row["scenario"]: row["host_conditions"]
                                      for row in report["scenarios"]},
                         "units": report["units_host_conditions"],
                         "runner_brackets": report["host_brackets"]}, indent=2), "```"]
    return "\n".join(rows) + "\n"


def passes(report):
    """Recompute derived bounds and host admission; reject incomplete artifacts."""
    try:
        return _passes(report)
    except (KeyError, TypeError, ValueError, IndexError, ZeroDivisionError):
        return False


def complete(diagnostic):
    if not (isinstance(diagnostic, dict) and diagnostic.get("remaining") == 0 and
            diagnostic.get("missing_end_roles") == [] and
            diagnostic.get("live_roles") == [] and diagnostic.get("failures") == []):
        return False
    births, receipts = diagnostic.get("birth_roles"), diagnostic.get("receiver_ends")
    if not isinstance(births, dict) or not births or not isinstance(receipts, list):
        return False
    observed = {}
    for row in receipts:
        if not isinstance(row, dict):
            return False
        role, count = row.get("role"), row.get("count")
        if (not isinstance(role, str) or role in observed or
                not isinstance(count, int) or isinstance(count, bool) or count <= 0):
            return False
        observed[role] = count
    return observed == births


def _passes(report):
    expected = {f"{trigger}/{topology}" for trigger in ("S1", "S4", "S5", "S7")
                for topology in ("resolvers", "queued", "custody")}
    expected |= {"S5c", "D/token_scan", "D/expected", "D/name"}
    constants, host = report["constants"], report["host"]
    bound, k_pf, attempts = constants["b_us"], constants["k_pf_us"], constants["load_attempts"]
    if (constants["n"], bound, k_pf) != bounds():
        return False
    if not (bound > 0 and k_pf > 0 and attempts > 0 and constants["placement_attempts"] > 0
            and host["schedulers_online"] > 0 and host["logical_cpus"] > 0
            and host["cpu_model"].strip() and host["otp"].strip()):
        return False
    cpus = host["admission_cpus"]
    if (not isinstance(cpus, int) or not 0 < cpus <= host["logical_cpus"] or
            not os.cpu_count() or cpus > os.cpu_count() or
            report["final_report_observer_queue"] != "off_heap" or
            constants["collection_cap_us"] != 10_000_000 or
            attempts != 30 or constants["placement_attempts"] != 20):
        return False
    brackets = report["host_brackets"]
    for snapshot in brackets.values():
        cpu_times(snapshot["stat"])
        load_average(snapshot["loadavg"])
    if set(brackets) != {"before", "after"} or not monotonic(
            brackets["before"]["stat"], brackets["after"]["stat"]):
        return False
    rows = report["scenarios"]
    if len(rows) != len(expected) or {row["scenario"] for row in rows} != expected:
        return False
    for row in rows:
        online = (1 if row["scenario"] == "S5c" else 2 if row["scenario"].startswith("D/")
                  else host["schedulers_online"])
        if len(row["times_us"]) != 5 or any(
                not math.isfinite(value) or not 0 <= value <= bound for value in row["times_us"]):
            return False
        if (len(row["placements"]) != 5 or not all(row["placements"]) or
                len(row["diagnostics"]) != 5 or not all(complete(d) for d in row["diagnostics"])):
            return False
        if row["headroom"] != max(row["times_us"]) / bound or not host_samples(
                row["host_conditions"], row["loads"], row["steals"], {online}, attempts, cpus, brackets):
            return False
    units = report["units_us"]
    if set(units) != {"separator_and_accounting", "expected_validation_and_serialization",
                      "permitted_name_validation", "final_report", "preflight_exit", "aead"}:
        return False
    if any(len(values) != 5 or any(not math.isfinite(value) or value < 0 for value in values)
           for values in units.values()):
        return False
    for key in ("units_loads", "units_steals", "units_host_conditions"):
        if set(report[key]) != set(units):
            return False
    for name in units:
        online = {host["schedulers_online"]}
        if name == "preflight_exit":
            online |= {1, 2}
        if not host_samples(report["units_host_conditions"][name], report["units_loads"][name],
                            report["units_steals"][name], online, attempts, cpus, brackets,
                            ordered=name != "preflight_exit"):
            return False
    longest = max(value for name, values in units.items()
                  if name not in {"final_report", "preflight_exit", "aead"} for value in values)
    final_report, exit_bound = max(units["final_report"]), max(units["preflight_exit"])
    derived = longest + final_report + exit_bound
    if (report["derived_k_pf_us"] != derived or derived > k_pf or
            report["headroom"]["derived_k_pf"] != derived / k_pf or
            report["derivation"] != {"longest_unit_us": longest, "final_report_us": final_report,
                                     "exit_upper_bound_us": exit_bound}):
        return False
    exits = [report["s5c_exit_us"]] + [row["preflight_exit_us"] for row in rows
                                      if row["scenario"].startswith("D/")]
    return all(len(values) == 5 and all(math.isfinite(value) and 0 <= value <= exit_bound
                                       for value in values) for values in exits)


def append_summary(summary):
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write(summary)


def main():
    processes.install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.unlink(missing_ok=True)
    before = host_snapshot()
    result = processes.run(["mix", "run", "scripts/jwe_teardown_gate.exs", str(args.output)],
        cwd=ROOT, extra_env={"MIX_ENV": "test"}, check=False, timeout=3600,
        capture_output=True, text=True)
    after = host_snapshot()
    brackets = {"before": before, "after": after}
    if not args.output.is_file():
        failure = {"host_brackets": brackets, "error": "gate did not produce measurements", "exit_code": result.returncode,
                   "output": (result.stdout or "") + (result.stderr or "")}
        args.output.write_text(json.dumps(failure, indent=2) + "\n")
        append_summary("Teardown gate failed before measurements: " + failure["error"] + "\n")
        return result.returncode or 1
    report = json.loads(args.output.read_text())
    report["host_brackets"] = brackets
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    summary = markdown(report)
    append_summary(summary)
    if result.returncode:
        return result.returncode
    return int(not passes(report))


if __name__ == "__main__":
    sys.exit(main())
