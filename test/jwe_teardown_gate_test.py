"""Verify absolute limits, independent derivation and Linux host admission."""
import ast
import copy
import importlib.util
import os
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("jwe_teardown_gate", ROOT / "scripts/jwe_teardown_gate.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
from host_conditions import metrics  # noqa: E402


def process_stat(user, system):
    return f"123 (beam.smp) S 1 2 3 0 -1 0 0 0 0 0 {user} {system} 0 0 20 0 8 0 1234"


class JWETeardownGateTest(unittest.TestCase):
    def observation(self, load=0.5, steal=0, online=2, offset=0, foreign=0):
        # Real /proc/stat layout, including guest counters (already in user).
        return {"loadavg": f"{load} 0.25 0.10 1/100 42", "load": load, "steal": steal,
                "foreign_cpu": foreign,
                "cpu_before": "cpu " + " ".join(str(value + offset) for value in
                    (100, 0, 0, 900, 0, 0, 0, 0)) + " 20 0\n",
                "cpu_after": "cpu " + " ".join(str(value + offset) for value in
                    (200 - steal, 0, 0, 900, 0, 0, 0, steal)) + " 20 0\n",
                "process_before": [process_stat(10, 10)],
                "process_after": [process_stat(20, 100 - steal - foreign)],
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
                              "placements": ["verified placement"] * 5,
                              "diagnostics": [{"remaining": 0, "missing_end_roles": [],
                                               "live_roles": [], "failures": [],
                                               "birth_roles": {"guard": 1},
                                               "receiver_ends": [{"role": "guard", "count": 1}]}
                                              for _ in range(5)],
                              "host_conditions": [[self.observation(online=online, offset=i * 1000)] for i in range(5)]})
        return {"scenarios": scenarios, "final_report_observer_queue": "off_heap",
                "host_brackets": {
                    "before": {"stat": "cpu 0 0 0 0 0 0 0 0", "loadavg": "0.0 0.0 0.0 1/10 1"},
                    "after": {"stat": "cpu 100000 100000 100000 100000 100000 100000 100000 100000",
                              "loadavg": "0.5 0.5 0.5 1/10 1"}},
                "constants": {"n": 10_000, "b_us": 170_000, "k_pf_us": 5_000,
                              "host_attempts": 30, "placement_attempts": 20,
                              "collection_cap_us": 10_000_000},
                "host": {"schedulers_online": 2, "logical_cpus": os.cpu_count(),
                         "cpu_model": "Test CPU", "otp": "28"},
                "units_us": {key: [200 if key == "preflight_exit" else 100] * 5 for key in units},
                "units_loads": {key: [0.5] * 5 for key in units},
                "units_steals": {key: [0] * 5 for key in units},
                "units_host_conditions": {key: [[self.observation(offset=i * 1000)] for i in range(5)] for key in units},
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
        self.assertEqual(GATE.cpu_counters(observation["cpu_before"]), [100, 0, 0, 900, 0, 0, 0, 0])
        self.assertEqual(metrics(observation), {"load": 0.5, "steal": 5.0, "foreign_cpu": 0.0})
        observation["cpu_after"] = observation["cpu_before"]
        self.assertEqual(metrics(observation), {"load": 0.5, "steal": None, "foreign_cpu": None})
        with self.assertRaises(ValueError):
            GATE.cpu_counters("cpu0 1 2 3 4 5 6 7 8\n")

    def test_failed_samples_retain_the_full_matrix_and_placement_diagnostics(self):
        report = self.report()
        row = report["scenarios"][0]
        row["times_us"][0] = 170_001
        row["headroom"] = 170_001 / 170_000
        row["diagnostics"][0]["live_roles"] = [{"role": "resolver", "function": "blocked"}]
        self.assertFalse(GATE.passes(report))
        summary = GATE.markdown(report)
        for scenario in report["scenarios"]:
            self.assertIn(scenario["scenario"], summary)
            self.assertEqual(len(scenario["times_us"]), 5)
        for text in ("sample 1: 170001 us", "verified placement", '"role": "resolver"'):
            self.assertIn(text, summary)

    def test_incomplete_lifecycles_and_content_failures_fail_even_inside_the_bound(self):
        for field, value in (("remaining", 1), ("missing_end_roles", ["preflight"]),
                             ("live_roles", [{"role": "custody", "function": "blocked"}]),
                             ("failures", ["S5c must fill the D crypto cells"])):
            report = self.report()
            report["scenarios"][0]["diagnostics"][0][field] = value
            with self.subTest(field=field):
                self.assertFalse(GATE.passes(report))
                self.assertIn(str(value[0]) if field == "failures" else field,
                              GATE.markdown(report))
        for field in ("placements", "diagnostics"):
            report = self.report()
            del report["scenarios"][0][field]
            self.assertFalse(GATE.passes(report))
        report = self.report()
        report["constants"]["collection_cap_us"] += 1
        self.assertFalse(GATE.passes(report))

    def test_dedicated_end_receiver_must_cover_the_birth_inventory_exactly(self):
        report = self.report()
        diagnostic = report["scenarios"][0]["diagnostics"][0]
        diagnostic["birth_roles"] = {"guard": 1, "coordinator": 1, "preflight": 1,
                                     "worker": 4, "resolver": 10000, "custody": 10000}
        diagnostic["receiver_ends"] = [{"role": role, "count": count}
                                       for role, count in diagnostic["birth_roles"].items()]
        self.assertTrue(GATE.passes(report))
        for kind in ("missing_role", "missing_process", "extra_role", "duplicate_role",
                     "missing_inventory", "missing_receipts"):
            changed = copy.deepcopy(report)
            ends = changed["scenarios"][0]["diagnostics"][0]["receiver_ends"]
            if kind == "missing_role":
                ends.pop()
            elif kind == "missing_process":
                ends[-1]["count"] -= 1
            elif kind == "extra_role":
                ends.append({"role": "other", "count": 1})
            elif kind == "duplicate_role":
                ends.append(copy.deepcopy(ends[-1]))
            elif kind == "missing_inventory":
                del changed["scenarios"][0]["diagnostics"][0]["birth_roles"]
            else:
                del changed["scenarios"][0]["diagnostics"][0]["receiver_ends"]
            with self.subTest(kind=kind):
                self.assertFalse(GATE.passes(changed))

    def test_steal_rejection_retries_and_never_admits_rejected_measurement(self):
        rejected, accepted = self.observation(steal=6), self.observation(steal=5, offset=100)
        history = [rejected, accepted]
        self.assertIs(GATE.admit(history, 30), accepted)
        report = self.report()
        row = report["scenarios"][0]
        row["host_conditions"][0] = history
        row["steals"][0] = 5
        self.assertTrue(GATE.passes(report))
        row["steals"][0] = 6
        self.assertFalse(GATE.passes(report))

    def test_foreign_cpu_and_skew_consume_retry_attempts(self):
        rejected = self.observation(foreign=11)
        skewed = self.observation(foreign=-1, offset=100)
        accepted = self.observation(foreign=10, offset=200)
        history = [rejected, skewed, accepted]
        self.assertIs(GATE.admit(history, 3), accepted)
        with self.assertRaisesRegex(ValueError, "host condition exhausted"):
            GATE.admit(history, 2)
        report = self.report()
        report["scenarios"][0]["host_conditions"][0] = history
        self.assertTrue(GATE.passes(report))
        rejected["foreign_cpu"] = 0
        self.assertFalse(GATE.passes(report))

    def test_high_load_with_zero_foreign_cpu_is_admitted(self):
        load = os.cpu_count() + 1
        report = self.report()
        for row in report["scenarios"]:
            row["loads"] = [load] * 5
            for i, history in enumerate(row["host_conditions"]):
                history[0].update(self.observation(load=load,
                    online=history[0]["schedulers_online"], offset=i * 1000))
        self.assertTrue(GATE.passes(report))

    def test_shared_host_budget_exhausts_with_every_observed_figure(self):
        history = [self.observation(load=3, foreign=-1), self.observation(steal=6, offset=100),
                   self.observation(steal=7, offset=200)]
        with self.assertRaisesRegex(ValueError, "host condition exhausted") as context:
            GATE.admit(history, 3)
        for value in ('"load": 3.0', '"steal": 6.0', '"steal": 7.0', '"foreign_cpu": -1.0'):
            self.assertIn(value, str(context.exception))
        self.assertIn(str(context.exception), GATE.markdown({"error": str(context.exception)}))

    def test_peer_scheduler_count_identifies_the_workload(self):
        report = self.report()
        self.assertTrue(GATE.passes(report))
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        self.assertIn("Runtime.with_peer(fn -> observe_host_sample(fun) end, schedulers)", source)
        self.assertIn("schedulers_online: System.schedulers_online()", source)
        row = next(row for row in report["scenarios"] if row["scenario"] == "S5c")
        row["host_conditions"][0][0]["schedulers_online"] = 2
        self.assertFalse(GATE.passes(report))

    def test_zero_elapsed_window_consumes_a_host_condition_attempt(self):
        zero, accepted = self.observation(), self.observation(offset=100)
        zero["cpu_after"] = zero["cpu_before"]
        zero["steal"] = None
        zero["foreign_cpu"] = None
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        self.assertIn("steal: if(steal == nil, do: :null, else: steal)", source)
        self.assertIn("foreign_cpu: if(foreign == nil, do: :null, else: foreign)", source)
        self.assertIs(GATE.admit([zero, accepted], 2), accepted)
        with self.assertRaisesRegex(ValueError, "host condition exhausted"):
            GATE.admit([zero, accepted], 1)
        report = self.report()
        report["scenarios"][0]["host_conditions"][0] = [zero, accepted]
        self.assertTrue(GATE.passes(report))

    def test_final_report_requires_the_observers_actual_off_heap_flag(self):
        report = self.report()
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        self.assertRegex(source, r"\[:monitor, \{:message_queue_data, :off_heap\}\]\s*\)")
        self.assertIn("Process.info(observer, :message_queue_data)", source)
        self.assertIn("final_report_observer_queue: observer_queue", source)
        report["final_report_observer_queue"] = "on_heap"
        self.assertFalse(GATE.passes(report))
        del report["final_report_observer_queue"]
        self.assertFalse(GATE.passes(report))

    def test_attempt_counters_must_be_monotonic_and_inside_runner_brackets(self):
        for kind in ("before_bracket", "after_bracket", "backwards_field", "backwards_attempt",
                     "missing_brackets", "backwards_bracket", "invalid_bracket_load", "backwards_sample"):
            report = self.report()
            row = report["scenarios"][0]
            history = row["host_conditions"][0]
            if kind == "before_bracket":
                report["host_brackets"]["before"]["stat"] = "cpu 101 0 0 900 0 0 0 0"
            elif kind == "after_bracket":
                report["host_brackets"]["after"]["stat"] = "cpu 199 0 0 900 0 0 0 0"
            elif kind == "backwards_field":
                # Total still advances and steal stays zero; individual fields regress.
                history[0]["cpu_after"] = "cpu 201 0 0 899 0 0 0 0"
            elif kind == "backwards_attempt":
                history.insert(0, self.observation(steal=6, offset=100))
            elif kind == "backwards_sample":
                row["host_conditions"][1] = [self.observation()]
            elif kind == "missing_brackets":
                del report["host_brackets"]
            elif kind == "backwards_bracket":
                report["host_brackets"]["before"]["stat"] = "cpu 100001 0 0 0 0 0 0 0"
            else:
                report["host_brackets"]["after"]["loadavg"] = "nan"
            with self.subTest(kind=kind):
                self.assertFalse(GATE.passes(report))
        report = self.report()
        history = report["units_host_conditions"]["aead"][0]
        history[0]["cpu_after"] = "cpu 100001 0 0 900 0 0 0 0"
        history[0]["steal"] = 0.0
        self.assertFalse(GATE.passes(report))

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
        for token in ("@samples 5", "@cap 10_000", "@host_attempts 30", "@placement_attempts 20",
                      "/proc/loadavg", "/proc/cpuinfo", "cpu_before", "cpu_after",
                      "process_before", "process_after", "HostConditions.admitted?",
                      "schedulers_online", "logical_cpus", "attempts - 1, seen",
                      "{tag, :cardinality, @cap", "{tag, :row, @cap - 1", "{tag, :handed_off}",
                      "{tag, :preflight, :deadline}", "process_flag(:message_queue_data, :off_heap)"):
            self.assertIn(token, source)
        host = (ROOT / "test/support/host_conditions.ex").read_text()
        for token in ("/proc/stat", "/proc/self/stat", "steal <= 5", "foreign <= 10"):
            self.assertIn(token, host)
        self.assertNotIn(":gate_final_report", source)
        self.assertNotIn("assert not handed", source)
        self.assertIn("{:retry, :handoff_finished_before_d}", source)
        self.assertIn("Runtime.in_codec_unit?(pid, functions)", source)
        runtime = (ROOT / "test/support/jwe_open_runtime.ex").read_text()
        self.assertIn("info(pid, :current_stacktrace)", runtime)
        self.assertIn("{Codec, function, _, _} -> function in functions", runtime)
        self.assertNotIn("process_flag(:sensitive, false)", source)

    def test_entry_loading_and_both_scan_times_remain_visible_without_warmup(self):
        report = self.report()
        report["unit_setup"] = [
            {"module": "Elixir.RequestSeal.JOSE.JWE.Codec", "loaded_before": False, "load_us": 1600},
            {"module": "Elixir.RequestSeal.JOSE.JWE.Worker", "loaded_before": False, "load_us": 2300}]
        details = [{"compact_us": 80, "json_us": 100} for _ in range(5)]
        report["units_details"] = {"separator_and_accounting": details}
        summary = GATE.markdown(report)
        for value in ("loaded_before", "1600", "2300", "compact_us", "json_us"):
            self.assertIn(value, summary)
        self.assertEqual(summary.count('"compact_us"'), 5)
        self.assertTrue(GATE.passes(report))
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        setup = source[source.index("  def prepare_units do"):source.index("  def units do")]
        self.assertIn("for module <- [Codec, Worker] do", setup)
        self.assertIn(":code.is_loaded(module)", setup)
        self.assertIn(":code.ensure_loaded(module)", setup)
        for operation in ("Codec.split(", "Worker.authenticate(", "measure(", "host_sample("):
            self.assertNotIn(operation, setup)
        self.assertIn("setup = prepare_units()", source)
        self.assertIn("{:measured, max(compact, json), %{compact_us: compact, json_us: json}}", source)
        self.assertIn("reason: end_reason(reason)", source)
        self.assertIn("coordinator_phases: Enum.reverse(phases)", source)

    def test_worker_metrics_are_reported_without_becoming_pass_conditions(self):
        report = self.report()
        worker = {"worker": "<worker>", "at_u": {"heap_words": 90000, "reductions": 15000},
                  "at_end": {"heap_words": 120000, "reductions": 25000},
                  "end_snapshot": "after_teardown", "end_snapshot_age_us": 6000,
                  "gc_scope": "vm_shared_interval", "gc_count_delta": 999999,
                  "gc_words_reclaimed_delta": 999999999999}
        report["scenarios"][0]["diagnostics"][0]["workers"] = [worker]
        self.assertTrue(GATE.passes(report))
        summary = GATE.markdown(report)
        for field in worker:
            self.assertIn(field, summary)
        worker["at_u"] = None
        worker["at_end"] = None
        self.assertTrue(GATE.passes(report))
        self.assertIn('"at_u": null', GATE.markdown(report))
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        for text in ("Process.info(pid, :garbage_collection_info)",
                     ":erlang.statistics(:garbage_collection)", "end_snapshot_age_us",
                     "gc_scope: :vm_shared_interval", "end_snapshot: :after_teardown"):
            self.assertIn(text, source)

    def test_worker_diagnostics_do_not_run_a_sampler_inside_teardown(self):
        source = (ROOT / "test/support/jwe_teardown_gate.ex").read_text()
        helper = source.split("defmodule RequestSeal.Test.JWEWorkerDiagnostics do", 1)[1]
        self.assertNotRegex(helper, r"\b(?:spawn|spawn_link|spawn_monitor|send_after|sleep)\s*\(",
                            "diagnostics must not launch a sampler during measured teardown")
        sample = source[source.index("  def sample(trigger, topology)"):source.index("  defp resolution_stamp")]
        self.assertLess(sample.index("JWEWorkerDiagnostics.start(s)"), sample.index("{anchor, s, placement}"))
        self.assertLess(sample.index("measured = measurement("), sample.index("JWEWorkerDiagnostics.collect("))

    def test_runner_owns_commands_and_retains_failure_output(self):
        source = (ROOT / "scripts/jwe_teardown_gate.py").read_text()
        tree = ast.parse(source)
        for text in ("processes.run", "args.output.write_text", "GITHUB_STEP_SUMMARY",
                     '"output": (result.stdout', "capture_output=True"):
            self.assertIn(text, source)
        self.assertLess(source.index("before = host_snapshot()"), source.index("result = processes.run("))
        self.assertLess(source.index("result = processes.run("), source.index("after = host_snapshot()"))
        self.assertIn('report["host_brackets"] = brackets', source)
        self.assertIn('Path("/proc/stat").read_text()', source)
        self.assertIn('Path("/proc/loadavg").read_text()', source)
        self.assertFalse(any(isinstance(node, ast.Import) and
                             any(alias.name == "subprocess" for alias in node.names)
                             for node in ast.walk(tree)))
