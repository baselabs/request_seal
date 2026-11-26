"""Exercise the paired collector with synthetic round artifacts."""
from contextlib import redirect_stdout
import io
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
CPU_BEFORE = "cpu 10 20 30 1000 50 60 70 0 15 19"
CPU_AFTER = "cpu 210 70 130 1184 350 110 120 66 185 69"
NORMAL_LOAD = "4.00 0.00 0.00 1/42 123"
HIGH_LOAD = "4.01 0.00 0.00 1/42 123"
HIGH_STEAL = "cpu 210 70 130 1183 350 110 120 67 185 69"


def process_stat(user, system, *, pid=123, ppid=1, waited=0, start=1234):
    # Field 2 may contain spaces and parentheses.
    return f"{pid} (beam ) smp) S {ppid} 2 3 0 -1 0 0 0 0 0 {user} {system} {waited} 0 20 0 8 0 {start}"


def artifact(number=1, page=(4200, 4200), single=(43.75, 140), *,
             reject=None, high_load=False, self_check=False):
    pairs, page_count, single_count = (1, 3, 10) if self_check else (3, 15, 2000)
    mode = "self-check" if self_check else "release"
    versions = {"baseline": "1.0.0", "candidate": CANDIDATE}
    runtime = {"otp": "29", "schedulers_online": 4}
    sets, rejected = [], []
    for offset, side in enumerate(["baseline", "candidate"] * pairs):
        sample_set = {"side": side, "version": versions[side], **runtime}
        breach = reject if offset == 1 else None
        foreign_ticks = {"foreign": 117, "skew": -17}.get(breach, 0 if high_load else 116)
        loadavg, load = (HIGH_LOAD, 4.01) if high_load else (NORMAL_LOAD, 4.0)
        sample_set["host_window"] = {
            "load_before": NORMAL_LOAD,
            "load_after": loadavg,
            "cpu_before": CPU_BEFORE,
            "cpu_after": HIGH_STEAL if breach == "steal" else CPU_AFTER,
            "process_before": [process_stat(20, 10)],
            "process_after": [process_stat(30, 450 - foreign_ticks)],
        }
        sample_set["admission"] = {
            "load": load, "steal": 6.7 if breach == "steal" else 6.6,
            "foreign_cpu": foreign_ticks / 10, "resolution": 1.6, "admitted": breach is None,
        }
        if breach:
            metrics = {key: value for key, value in sample_set["admission"].items() if key != "admitted"}
            rejected.append({"sample_set": offset + 1, "side": side, **metrics})
        for name, times, count in (("page", page, page_count), ("single", single, single_count)):
            sample_set[name] = {
                "median_us": times[offset % 2],
                "samples": count,
                "warmups": 30,
            }
        sets.append(sample_set)
    return {
        "round": number,
        "commit": COMMIT,
        "mode": mode,
        "host": {"logical_cpus": 4, "cpu_model": "CPU fixture", "os_image": "fixture"},
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
        verdict = collect([artifact(i, reject="foreign" if i > 4 else None) for i in range(1, gate.ROUNDS + 1)])
        self.assertFalse(verdict["passed"])
        self.assertEqual([1, 2, 3, 4], verdict["admitted_rounds"])
        self.assertEqual({name: "unmeasured" for name in gate.GATES}, statuses(verdict))
        self.assertEqual(gate.ROUNDS - 4, len(verdict["unmeasured_rounds"]))
        self.assertEqual([], verdict["errors"])

    def test_five_admitted_rounds_measure_both_absolute_gates(self):
        verdict = collect([artifact(i, reject="foreign" if i > 5 else None) for i in range(1, gate.ROUNDS + 1)])
        self.assertEqual({"page_absolute_us": "pass", "page_relative": "unmeasured",
                          "single_absolute_us": "pass", "single_relative": "unmeasured"},
                         statuses(verdict))

    def test_twenty_admitted_rounds_measure_every_gate(self):
        verdict = collect([artifact(i, reject="foreign" if i > 20 else None) for i in range(1, gate.ROUNDS + 1)])
        self.assertTrue(verdict["passed"], verdict)
        self.assertEqual(list(range(1, 21)), verdict["admitted_rounds"])
        self.assertEqual({name: "pass" for name in gate.GATES}, statuses(verdict))

    def test_rejected_sample_set_excludes_both_workloads_from_a_round(self):
        for rule, value, measured in (("foreign", 11.7, "foreign_cpu"), ("skew", -1.7, "foreign_cpu"),
                                     ("steal", 6.7, "steal")):
            with self.subTest(rule=rule):
                row = artifact(reject=rule)
                summary = gate.summarize(row["sample_sets"], row["host"], "release", CANDIDATE)
                self.assertFalse(summary["admitted"])
                verdict = collect([artifact(i, reject=rule if i >= 20 else None)
                                   for i in range(1, gate.ROUNDS + 1)])
                self.assertFalse(verdict["passed"])
                self.assertEqual([], verdict["errors"])
                self.assertEqual(19, len(verdict["admitted_rounds"]))
                self.assertEqual({"page_absolute_us": "pass", "page_relative": "unmeasured",
                                  "single_absolute_us": "pass", "single_relative": "unmeasured"},
                                 statuses(verdict))
                rejection, = verdict["unmeasured_rounds"][20]
                self.assertEqual((2, "candidate", value, 1.6),
                                 (rejection["sample_set"], rejection["side"], rejection[measured],
                                  rejection["resolution"]))

    def test_high_load_with_zero_foreign_cpu_is_admitted(self):
        window = artifact(high_load=True)["sample_sets"][0]["host_window"]
        observation = gate.observe(window, 4)
        self.assertTrue(observation["admitted"])
        self.assertEqual(0, observation["foreign_cpu"])
        verdict = collect([artifact(i, high_load=True) for i in range(1, gate.ROUNDS + 1)])
        self.assertTrue(verdict["passed"], verdict)
        self.assertEqual(list(range(1, gate.ROUNDS + 1)), verdict["admitted_rounds"])

    def test_process_tree_replay_credits_only_observed_window_cpu(self):
        window = artifact()["sample_sets"][0]["host_window"]
        window["cpu_after"] = "cpu 30 25 40 1020 80 65 75 5 32 24"
        window["process_before"] = [
            process_stat(20, 10, waited=100),
            process_stat(10, 5, pid=124, ppid=123),
            process_stat(8, 2, pid=125, ppid=123, waited=3),
            process_stat(4, 0, pid=126, ppid=124),
        ]
        window["process_after"] = [
            process_stat(23, 12, waited=131),
            process_stat(20, 10, pid=124, ppid=123),
            process_stat(7, 0, pid=126, ppid=124),
            process_stat(40, 5, pid=127, ppid=123, start=3000),
        ]
        # BEAM +5, persistent child +15, grandchild +3, reaped child +18.
        # The new live child has no baseline. The host had 45 busy ticks.
        self.assertEqual(gate.observe(window, 4)["foreign_cpu"], 4.0)
        window["process_after"].append(process_stat(40, 5, pid=128, ppid=1))
        with self.assertRaisesRegex(ValueError, "rooted process tree"):
            gate.observe(window, 4)

    def test_malformed_or_incomplete_round_evidence_fails(self):
        for issue in ("invalid-json", "missing", "duplicate", "order", "missing-window", "counts",
                      "version", "commit", "forged-admission", "invalid-proc", "missing-process",
                      "forged-process", "different-process", "forged-resolution", "skewed-ratio", "runtime-error"):
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
                    last["sample_sets"][0]["host_window"]["load_after"] = HIGH_LOAD
                elif issue == "invalid-proc":
                    last["sample_sets"][0]["host_window"]["cpu_before"] = False
                elif issue == "missing-process":
                    del last["sample_sets"][0]["host_window"]["process_before"]
                elif issue == "forged-process":
                    last["sample_sets"][0]["host_window"]["process_after"] = [process_stat(30, 333)]
                elif issue == "different-process":
                    last["sample_sets"][0]["host_window"]["process_after"] = [process_stat(30, 334, pid=321)]
                elif issue == "forged-resolution":
                    last["sample_sets"][0]["admission"]["resolution"] = 100.0
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
        self.assertEqual(2, len(verdict["host_windows"]))
        output = io.StringIO()
        with redirect_stdout(output):
            gate.print_verdict(verdict)
        self.assertEqual(2, sum(line.startswith("Self-check ") and "foreign CPU 11.6%" in line
                               and "resolution 1.6" in line
                               for line in output.getvalue().splitlines()))
        self.assertFalse(collect([row])["passed"])
        row["sample_sets"].pop()
        self.assertFalse(collect([row], "self-check")["passed"])


if __name__ == "__main__":
    unittest.main()
