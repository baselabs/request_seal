#!/usr/bin/env python3
"""Run the release teardown gate on CI and retain its machine-readable artifact."""
import argparse
import json
import os
from pathlib import Path
import sys

import processes

ROOT = Path(__file__).resolve().parents[1]


def markdown(report):
    rows = ["| Scenario | Five trigger-to-last-end times (us) | Max (us) | Load |",
            "|---|---|---|---|"]
    for sample in report["scenarios"]:
        rows.append("| {} | {} | {} | {} |".format(sample["scenario"],
            ", ".join(str(value) for value in sample["times_us"]),
            max(sample["times_us"]), ", ".join(str(value) for value in sample["loads"])))
    rows += ["", "| Unit | Five times (us) | Load |", "|---|---|---|"]
    for name, values in report["units_us"].items():
        loads = report["units_loads"][name]
        rows.append(f"| {name} | {', '.join(map(str, values))} | {', '.join(map(str, loads))} |")
    for sample in report["scenarios"]:
        if sample["scenario"].startswith("D/"):
            rows.append(f"| {sample['scenario']} cooperative exit | {sample['preflight_exit_us']} | |")
    rows += ["", f"Derived K_pf: {report['derived_k_pf_us']} us; limit: 5000 us.",
             f"S5c preflight exits: {report['s5c_exit_us']} us."]
    return "\n".join(rows) + "\n"


def passes(report):
    """Refuse missing samples as well as measurements outside the contract."""
    expected = {f"{trigger}/{topology}" for trigger in ("S1", "S4", "S5", "S7")
                for topology in ("resolvers", "queued", "custody")}
    expected |= {"S5c", "D/token_scan", "D/expected", "D/name"}
    rows = report["scenarios"]
    if len(rows) != len(expected) or {row["scenario"] for row in rows} != expected:
        return False
    for row in rows:
        online = (1 if row["scenario"] == "S5c" else 2 if row["scenario"].startswith("D/")
                  else report["constants"]["schedulers_online"])
        if len(row["times_us"]) != 5 or len(row["loads"]) != 5:
            return False
        if any(value < 0 or value > 170_000 for value in row["times_us"]):
            return False
        if any(value < 0 or value > online for value in row["loads"]):
            return False
    units = report["units_us"]
    if set(units) != {"separator_and_accounting", "expected_validation_and_serialization",
                      "permitted_name_validation", "final_report", "preflight_exit", "aead"}:
        return False
    if any(len(values) != 5 or any(value < 0 for value in values) for values in units.values()):
        return False
    unit_loads = report["units_loads"]
    if set(unit_loads) != set(units) or any(
            len(values) != 5 or any(value < 0 or value > report["constants"]["schedulers_online"]
                                    for value in values) for values in unit_loads.values()):
        return False
    exits = [report["s5c_exit_us"]] + [row["preflight_exit_us"] for row in rows
                                      if row["scenario"].startswith("D/")]
    return (all(len(values) == 5 and all(0 <= value <= 5_000 for value in values)
                for values in exits) and 0 <= report["derived_k_pf_us"] <= 5_000)


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
    result = processes.run(["mix", "run", "scripts/jwe_teardown_gate.exs", str(args.output)],
        cwd=ROOT, extra_env={"MIX_ENV": "test"}, check=False, timeout=3600)
    if not args.output.is_file():
        failure = {"error": "gate did not produce measurements", "exit_code": result.returncode}
        args.output.write_text(json.dumps(failure, indent=2) + "\n")
        append_summary("Teardown gate failed before measurements: " + failure["error"] + "\n")
        return result.returncode or 1
    report = json.loads(args.output.read_text())
    summary = markdown(report)
    append_summary(summary)
    if result.returncode:
        return result.returncode
    return int(not passes(report))


if __name__ == "__main__":
    sys.exit(main())
