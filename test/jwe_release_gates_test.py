"""Exercise the paired collector with synthetic round artifacts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jwe_release_gates as gate  # noqa: E402

COMMIT = "a" * 40
CANDIDATE = "2.0.0-dev"
CPU_BEFORE = "cpu 0 0 0 1000 0 0 0 0"
CPU_AFTER = "cpu 0 0 0 1095 0 0 0 5"
NORMAL_LOAD = "4.00 0.00 0.00 1/42 123"
HIGH_LOAD = "4.01 0.00 0.00 1/42 123"
HIGH_STEAL = "cpu 0 0 0 1094 0 0 0 6"


def artifact(number=1, page=(4200, 4200), single=(43.75, 140), *, reject=None, self_check=False):
    pairs, page_count, single_count = (1, 3, 10) if self_check else (3, 15, 2000)
    mode = "self-check" if self_check else "release"
    versions = {"baseline": "1.0.0", "candidate": CANDIDATE}
    runtime = {"otp": "29", "schedulers_online": 4}
    sets, rejected = [], []
    for offset, side in enumerate(["baseline", "candidate"] * pairs):
        sample_set = {"side": side, "version": versions[side], **runtime}
        for name, times, count in (("page", page, page_count), ("single", single, single_count)):
            load_breach = reject == "load" and offset == 0 and name == "page"
            steal_breach = reject == "steal" and offset == 1 and name == "single"
            loadavg, load = (HIGH_LOAD, 4.01) if load_breach else (NORMAL_LOAD, 4.0)
            after, steal = (HIGH_STEAL, 6.0) if steal_breach else (CPU_AFTER, 5.0)
            admitted = not (load_breach or steal_breach)
            sample_set[name] = {
                "median_us": times[offset % 2],
                "samples": count,
                "warmups": 30,
                "load_before": NORMAL_LOAD,
                "load_after": loadavg,
                "cpu_before": CPU_BEFORE,
                "cpu_after": after,
                "admission": {"loadavg": loadavg, "load": load, "cpu_before": CPU_BEFORE,
                              "cpu_after": after, "steal": steal, "admitted": admitted},
            }
            if not admitted:
                rejected.append({"sample_set": offset + 1, "side": side, "workload": name,
                                 "load": load, "steal": steal})
        sets.append(sample_set)
    return {
        "round": number,
        "commit": COMMIT,
        "mode": mode,
        "host": {"logical_cpus": 4, "cpu_model": "CPU fixture", "image_version": "fixture"},
        **runtime,
        "versions": versions,
        "admitted": not rejected,
        "rejected_windows": rejected,
        "sample_sets": sets,
        "workloads": {name: {"baseline_us": a, "candidate_us": b, "ratio": b / a}
                      for name, (a, b) in (("page", page), ("single", single))},
    }


def collect(rows, mode="release"):
    with tempfile.TemporaryDirectory() as scratch:
        paths = []
        for index, row in enumerate(rows, 1):
            path = Path(scratch) / f"round-{index}" / "round.json"
            path.parent.mkdir()
            path.write_text(json.dumps(row) if not isinstance(row, str) else row)
            paths.append(path)
        return gate.collect(paths, mode, COMMIT, CANDIDATE)


def statuses(verdict):
    return {name: decision["status"] for name, decision in verdict["gates"].items()}


class ReleaseGatesTest(unittest.TestCase):
    def test_all_four_exact_thresholds_and_host_boundaries_pass(self):
        verdict = collect([artifact(i) for i in range(1, gate.ROUNDS + 1)])
        self.assertTrue(verdict["passed"], verdict)
        self.assertEqual(gate.ROUNDS, len(verdict["admitted_rounds"]))
        self.assertEqual({"page_absolute_us": 4200, "page_relative": 1.0,
                          "single_absolute_us": 140, "single_relative": 3.2},
                         {name: decision["value"] for name, decision in verdict["gates"].items()})

    def test_each_gate_can_fail_in_isolation(self):
        for failed, settings in (
            ("page_absolute_us", {"page": (4500, 4201)}),
            ("page_relative", {"page": (4199, 4200)}),
            ("single_absolute_us", {"single": (47, 141)}),
            ("single_relative", {"single": (43, 140)}),
        ):
            with self.subTest(failed=failed):
                verdict = collect([artifact(i, **settings) for i in range(1, gate.ROUNDS + 1)])
                self.assertFalse(verdict["passed"])
                self.assertEqual({name: "fail" if name == failed else "pass" for name in gate.GATES},
                                 statuses(verdict))

    def test_relative_uses_median_of_ratios_and_round_uses_median_of_each_side(self):
        rows = [artifact(i, page=(100, 100) if i <= 8 else (4000, 4000) if i <= 16 else (1000, 4200))
                for i in range(1, gate.ROUNDS + 1)]
        rows[0]["sample_sets"][0]["page"]["median_us"] = 1
        rows[0]["sample_sets"][1]["page"]["median_us"] = 100_000
        verdict = collect(rows)
        self.assertTrue(verdict["passed"], verdict)
        self.assertEqual(1.0, verdict["gates"]["page_relative"]["value"])
        self.assertEqual(4000, verdict["gates"]["page_absolute_us"]["value"])

    def test_fewer_than_five_admitted_rounds_leave_every_gate_unmeasured(self):
        verdict = collect([artifact(i, reject="load" if i > 4 else None) for i in range(1, gate.ROUNDS + 1)])
        self.assertFalse(verdict["passed"])
        self.assertEqual([1, 2, 3, 4], verdict["admitted_rounds"])
        self.assertEqual({name: "unmeasured" for name in gate.GATES}, statuses(verdict))
        self.assertEqual(gate.ROUNDS - 4, len(verdict["unmeasured_rounds"]))
        self.assertEqual([], verdict["errors"])

    def test_five_admitted_rounds_measure_both_absolute_gates(self):
        verdict = collect([artifact(i, reject="load" if i > 5 else None) for i in range(1, gate.ROUNDS + 1)])
        self.assertEqual({"page_absolute_us": "pass", "page_relative": "unmeasured",
                          "single_absolute_us": "pass", "single_relative": "unmeasured"},
                         statuses(verdict))

    def test_twenty_admitted_rounds_measure_every_gate(self):
        verdict = collect([artifact(i, reject="load" if i > 20 else None) for i in range(1, gate.ROUNDS + 1)])
        self.assertTrue(verdict["passed"], verdict)
        self.assertEqual(list(range(1, 21)), verdict["admitted_rounds"])
        self.assertEqual({name: "pass" for name in gate.GATES}, statuses(verdict))

    def test_either_host_rule_excludes_a_whole_round_and_leaves_ratios_unmeasured(self):
        for rule, value, measured in (("load", 4.01, "load"), ("steal", 6, "steal")):
            with self.subTest(rule=rule):
                verdict = collect([artifact(i, reject=rule if i >= 20 else None)
                                   for i in range(1, gate.ROUNDS + 1)])
                self.assertFalse(verdict["passed"])
                self.assertEqual(19, len(verdict["admitted_rounds"]))
                self.assertEqual({"page_absolute_us": "pass", "page_relative": "unmeasured",
                                  "single_absolute_us": "pass", "single_relative": "unmeasured"},
                                 statuses(verdict))
                self.assertEqual(value, verdict["unmeasured_rounds"][20][0][measured])
                self.assertEqual([], verdict["errors"])

    def test_malformed_or_incomplete_round_evidence_fails(self):
        for issue in ("invalid-json", "missing", "duplicate", "order", "missing-window", "counts",
                      "version", "commit", "forged-admission", "invalid-proc", "skewed-ratio", "runtime-error"):
            with self.subTest(issue=issue):
                rows = [artifact(i) for i in range(1, gate.ROUNDS)]
                last = artifact(gate.ROUNDS)
                if issue == "invalid-json":
                    last = "["
                elif issue == "duplicate":
                    last["round"] = gate.ROUNDS - 1
                elif issue == "order":
                    last["sample_sets"][0], last["sample_sets"][1] = last["sample_sets"][1], last["sample_sets"][0]
                elif issue == "missing-window":
                    del last["sample_sets"][0]["single"]
                elif issue == "counts":
                    last["sample_sets"][0]["page"]["samples"] = 14
                elif issue == "version":
                    last["sample_sets"][1]["version"] = "2.0.0"
                elif issue == "commit":
                    last["commit"] = "b" * 40
                elif issue == "forged-admission":
                    last["sample_sets"][0]["page"]["load_after"] = HIGH_LOAD
                elif issue == "invalid-proc":
                    last["sample_sets"][0]["single"]["cpu_before"] = False
                elif issue == "skewed-ratio":
                    last["workloads"]["page"]["ratio"] = 0.5
                elif issue == "runtime-error":
                    last["error"] = "measurement process exited"
                if issue != "missing":
                    rows.append(last)
                verdict = collect(rows)
                self.assertFalse(verdict["passed"])
                self.assertTrue(verdict["errors"])

    def test_self_check_checks_schema_without_thresholds_or_admission(self):
        row = artifact(page=(1, 10_000), reject="steal", self_check=True)
        verdict = collect([row], "self-check")
        self.assertTrue(verdict["passed"], verdict)
        self.assertEqual({}, verdict["gates"])
        self.assertEqual([], verdict["admitted_rounds"])
        self.assertFalse(collect([row])["passed"])
        row["sample_sets"].pop()
        self.assertFalse(collect([row], "self-check")["passed"])


if __name__ == "__main__":
    unittest.main()
