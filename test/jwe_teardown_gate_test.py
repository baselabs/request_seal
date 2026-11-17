"""Keep the release gate's coverage and retained measurements explicit."""
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
    def report(self):
        names = [f"{s}/{t}" for s in ("S1", "S4", "S5", "S7")
                 for t in ("resolvers", "queued", "custody")]
        names += ["S5c", "D/token_scan", "D/expected", "D/name"]
        return {"scenarios": [{"scenario": name, "times_us": [170_000] * 5,
                               "loads": [0.5] * 5, "preflight_exit_us": [200] * 5} for name in names],
                "constants": {"schedulers_online": 2},
                "units_us": {key: [100] * 5 for key in (
                    "separator_and_accounting", "expected_validation_and_serialization",
                    "permitted_name_validation", "final_report", "preflight_exit", "aead")},
                "units_loads": {key: [0.5] * 5 for key in (
                    "separator_and_accounting", "expected_validation_and_serialization",
                    "permitted_name_validation", "final_report", "preflight_exit", "aead")},
                "s5c_exit_us": [200] * 5, "derived_k_pf_us": 5_000}

    def test_exact_ceiling_and_missing_or_slow_samples(self):
        report = self.report()
        self.assertTrue(GATE.passes(report))
        for kind in ("missing", "duplicate", "slow", "negative", "load", "kpf", "unit", "byte_exit", "unit_load"):
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
            elif kind == "unit":
                changed["units_us"]["aead"].pop()
            elif kind == "byte_exit":
                changed["scenarios"][-1]["preflight_exit_us"][0] = 5_001
            else:
                changed["units_loads"]["aead"][0] = 2.01
            with self.subTest(kind=kind):
                self.assertFalse(GATE.passes(changed))
        self.assertIn("170000", GATE.markdown(report))
        self.assertIn("Derived K_pf: 5000", GATE.markdown(report))

    def test_gate_coverage_and_reference_condition(self):
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        for scenario in ["S1", "S4", "S5", "S7", "S5c"]:
            self.assertIn('"' + scenario + '"', source)
        for token in [":resolvers", ":queued", ":custody", ":token_scan", ":expected", ":name",
                      "@samples 5", "@cap 10_000", "@load_attempts 30", "/proc/loadavg",
                      "derived_k_pf_us", "preflight_exit_us", "s5c_exit_us", "1_048_576"]:
            self.assertIn(token, source)
        self.assertIn("Runtime.info(pid, :current_function)", source)
        self.assertNotIn("process_flag(:sensitive, false)", source)

    def test_runner_owns_commands_and_always_retains_an_artifact(self):
        source = (ROOT / "scripts/jwe_teardown_gate.py").read_text()
        tree = ast.parse(source)
        self.assertIn("processes.run", source)
        self.assertIn("args.output.write_text", source)
        self.assertIn("GITHUB_STEP_SUMMARY", source)
        self.assertIn("170_000", source)
        self.assertIn("5_000", source)
        self.assertFalse(any(isinstance(node, ast.Import) and
                             any(alias.name == "subprocess" for alias in node.names)
                             for node in ast.walk(tree)))
