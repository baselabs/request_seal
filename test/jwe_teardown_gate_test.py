"""Verify absolute limits, independent derivation and Linux host admission."""
import ast
import copy
import importlib.util
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("jwe_teardown_gate", ROOT / "scripts/jwe_teardown_gate.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class JWETeardownGateTest(unittest.TestCase):
    def observation(self, load=0.5, steal=0, online=2):
        # Real /proc/stat layout, including guest counters (already in user).
        return {"loadavg": f"{load} 0.25 0.10 1/100 42", "load": load, "steal": steal,
                "cpu_before": "cpu  100 0 0 900 0 0 0 0 20 0\ncpu0 1 0 0 9 0 0 0 0 0 0\n",
                "cpu_after": f"cpu  {200 - steal} 0 0 900 0 0 0 {steal} 20 0\n",
                "schedulers_online": online}

    def report(self):
        names = [f"{s}/{t}" for s in ("S1", "S4", "S5", "S7")
                 for t in ("resolvers", "queued", "custody")]
        names += ["S5c", "D/token_scan", "D/expected", "D/name"]
        units = ("separator_and_accounting", "expected_validation_and_serialization",
                 "permitted_name_validation", "final_report", "preflight_exit", "aead")
        scenarios = []
        for name in names:
            online = 1 if name == "S5c" else 2
            scenarios.append({"scenario": name, "times_us": [170_000] * 5,
                              "loads": [0.5] * 5, "steals": [0] * 5,
                              "preflight_exit_us": [200] * 5, "headroom": 1,
                              "host_conditions": [[self.observation(online=online)] for _ in range(5)]})
        return {"scenarios": scenarios,
                "constants": {"n": 10_000, "b_us": 170_000, "k_pf_us": 5_000,
                              "load_attempts": 30, "placement_attempts": 20},
                "host": {"schedulers_online": 2, "logical_cpus": 4, "cpu_model": "Test CPU", "otp": "28"},
                "units_us": {key: [200 if key == "preflight_exit" else 100] * 5 for key in units},
                "units_loads": {key: [0.5] * 5 for key in units},
                "units_steals": {key: [0] * 5 for key in units},
                "units_host_conditions": {key: [[self.observation()] for _ in range(5)] for key in units},
                "s5c_exit_us": [200] * 5, "derived_k_pf_us": 400,
                "headroom": {"derived_k_pf": 400 / 5_000},
                "derivation": {"longest_unit_us": 100, "final_report_us": 100, "exit_upper_bound_us": 200}}

    def test_exact_ceiling_and_missing_or_slow_samples(self):
        report = self.report()
        self.assertTrue(GATE.passes(report))
        for kind in ("missing", "duplicate", "slow", "negative", "load", "kpf", "unit",
                     "byte_exit", "unit_load", "tampered_derived", "steal", "host", "headroom",
                     "bounds"):
            changed = copy.deepcopy(report)
            if kind == "missing":
                changed["scenarios"].pop()
            elif kind == "duplicate":
                changed["scenarios"][-1] = changed["scenarios"][0]
            elif kind == "slow":
                changed["scenarios"][0]["times_us"][0] = 170_001
            elif kind == "negative":
                changed["scenarios"][0]["times_us"][0] = -1
            elif kind == "load":
                changed["scenarios"][12]["loads"][0] = 1.01
            elif kind == "kpf":
                changed["derived_k_pf_us"] = 5_001
            elif kind == "tampered_derived":
                changed["derived_k_pf_us"] = 399
            elif kind == "unit":
                changed["units_us"]["aead"].pop()
            elif kind == "byte_exit":
                changed["scenarios"][-1]["preflight_exit_us"][0] = 201
            elif kind == "unit_load":
                changed["units_loads"]["aead"][0] = 2.01
            elif kind == "steal":
                changed["scenarios"][0]["steals"][0] = 6
            elif kind == "host":
                del changed["host"]["cpu_model"]
            elif kind == "bounds":
                changed["constants"]["b_us"] += 1
            else:
                changed["scenarios"][0]["headroom"] = 0.5
            with self.subTest(kind=kind):
                self.assertFalse(GATE.passes(changed))
        summary = GATE.markdown(report)
        for text in ("170000", "Derived K_pf: 400", "100.000%", "8.000%", "Test CPU", "CPU steal"):
            self.assertIn(text, summary)

    def test_proc_parsing_excludes_guest_and_checks_counter_window(self):
        observation = self.observation(steal=5)
        self.assertEqual(GATE.cpu_times(observation["cpu_before"]), (1000, 0))
        self.assertEqual(GATE.steal_percent(observation["cpu_before"], observation["cpu_after"]), 5)
        self.assertEqual(GATE.load_average(observation["loadavg"]), 0.5)
        self.assertIsNone(GATE.steal_percent(observation["cpu_before"], observation["cpu_before"]))
        with self.assertRaises(ValueError):
            GATE.cpu_times("cpu0 1 2 3 4 5 6 7 8\n")

    def test_steal_rejection_retries_and_never_admits_rejected_measurement(self):
        rejected, accepted = self.observation(steal=6), self.observation(steal=5)
        history = [rejected, accepted]
        self.assertIs(GATE.admit(history, 2, 30), accepted)
        report = self.report()
        row = report["scenarios"][0]
        row["host_conditions"][0] = history
        row["steals"][0] = 5
        self.assertTrue(GATE.passes(report))
        row["steals"][0] = 6
        self.assertFalse(GATE.passes(report))

    def test_shared_host_budget_exhausts_with_every_observed_figure(self):
        history = [self.observation(load=3), self.observation(steal=6), self.observation(steal=7)]
        with self.assertRaisesRegex(ValueError, "host condition exhausted") as context:
            GATE.admit(history, 2, 3)
        for value in ('"load": 3.0', '"steal": 6.0', '"steal": 7.0'):
            self.assertIn(value, str(context.exception))
        self.assertIn(str(context.exception), GATE.markdown({"error": str(context.exception)}))

    def test_constants_are_read_from_bounds_and_gate_measurements_match_production(self):
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        wrapper = (ROOT / "scripts/jwe_teardown_gate.exs").read_text()
        runner = (ROOT / "scripts/jwe_teardown_gate.py").read_text()
        self.assertIn("b_us: Bounds.teardown(@cap)", source)
        self.assertIn("k_pf_us: Bounds.preflight()", source)
        self.assertIn("report.constants.b_us", wrapper)
        self.assertNotIn("170_000", runner + wrapper)
        self.assertNotIn("5_000", runner)
        self.assertIn('constants["b_us"]', runner)
        self.assertIn('constants["k_pf_us"]', runner)
        self.assertEqual(GATE.bounds(), (10_000, 170_000, 5_000))
        for token in ("@samples 5", "@cap 10_000", "@load_attempts 30", "@placement_attempts 20",
                      "/proc/loadavg", "/proc/stat", "/proc/cpuinfo", "cpu_before", "cpu_after",
                      "schedulers_online", "logical_cpus", "steal <= 5", "attempts - 1, seen",
                      "{tag, :cardinality, @cap", "{tag, :row, @cap - 1", "{tag, :handed_off}",
                      "{tag, :preflight, :deadline}", "process_flag(:message_queue_data, :off_heap)"):
            self.assertIn(token, source)
        self.assertNotIn(":gate_final_report", source)
        self.assertNotIn("assert not handed", source)
        self.assertIn("{:retry, :handoff_finished_before_d}", source)
        self.assertIn("Runtime.info(pid, :current_function)", source)
        self.assertNotIn("process_flag(:sensitive, false)", source)

    def test_runner_owns_commands_and_retains_failure_output(self):
        source = (ROOT / "scripts/jwe_teardown_gate.py").read_text()
        tree = ast.parse(source)
        for text in ("processes.run", "args.output.write_text", "GITHUB_STEP_SUMMARY",
                     '"output": (result.stdout', "capture_output=True"):
            self.assertIn(text, source)
        self.assertFalse(any(isinstance(node, ast.Import) and
                             any(alias.name == "subprocess" for alias in node.names)
                             for node in ast.walk(tree)))
