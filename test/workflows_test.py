"""Hold the qualification contract: one run per kci/<sha> candidate, judged by `qualified`."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify  # noqa: E402
from workflow_yaml import load as load_workflow  # noqa: E402

WORKFLOWS = ROOT / ".github/workflows"
PROOFS = {"process-ownership-macos", "toolchain", "verify", "mutations", "teardown"}


def text(name):
    return (WORKFLOWS / name).read_text()


def workflows():
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def triggers(source):
    return load_workflow(source)["on"]


def jobs(source):
    return load_workflow(source)["jobs"]


def fields(value):
    """Walk structural fields without interpreting block scalar contents as YAML."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from fields(child)
    elif isinstance(value, list):
        for child in value:
            yield from fields(child)


def step_identity(step):
    return step["uses"].split("@", 1)[0] if "uses" in step else step["run"]


def proof_condition_errors(source, ci_source):
    proofs = jobs(source)
    conditions = {}
    errors = []
    for job, body in proofs.items():
        if "if" in body:
            errors.append(f"{job}: job condition is forbidden")
        for step in body["steps"]:
            if "if" in step:
                identity = (job, step_identity(step))
                conditions.setdefault(identity, []).append(step["if"])
    conditions = {identity: sorted(bound) for identity, bound in conditions.items()}
    expected = {
        ("verify", "actions/cache"): ["matrix.lane == 'latest'"],
        ("verify", "mix test --warnings-as-errors"): ["matrix.lane == 'floor'", "matrix.lane == 'mid'"],
        ("verify", "python3 scripts/check_optional_clients.py"): ["matrix.lane == 'floor'"],
        ("verify", "python3 scripts/check.py"): ["matrix.lane == 'latest'"],
        ("teardown", "actions/upload-artifact"): ["always()"],
    }
    if conditions != expected:
        errors.append("proof conditions must bind exactly to the declared job and step")
    for workflow in (load_workflow(source), load_workflow(ci_source)):
        if any(key == "continue-on-error" for key, _ in fields(workflow)):
            errors.append("continue-on-error is forbidden")
    return errors


def proof_jobs(conclusion="success", **changes):
    """A run's job listing as the Actions API reports it, every proof succeeding by default."""
    names = sorted(qualify.expected_jobs((ROOT / ".tool-versions").read_text()))
    listing = [{"name": name, "status": "completed", "conclusion": conclusion} for name in names]
    listing.append({"name": "qualified", "status": "in_progress", "conclusion": None})
    for name, job in changes.items():
        listing = [entry for entry in listing if entry["name"] != name]
        listing += job
    return listing


@contextlib.contextmanager
def actions_api(listing, page_size=3):
    """A real local HTTP server answering the run-jobs endpoint, paged like the API."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            requests.append({"path": url.path, "query": query, "authorization": self.headers["Authorization"]})
            page = int(query["page"][0])
            body = json.dumps({"total_count": len(listing),
                               "jobs": listing[(page - 1) * page_size:page * page_size]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *arguments):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def verdict(api, proofs_result="success"):
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    environment.update(GITHUB_API_URL=api, GITHUB_REPOSITORY="baselabs/request_seal", GITHUB_RUN_ID="7",
                       GH_TOKEN="run-token", PROOFS_RESULT=proofs_result, NO_PROXY="127.0.0.1")
    return subprocess.run([sys.executable, "-B", str(ROOT / "scripts/qualify.py")], env=environment,
                          capture_output=True, text=True, timeout=60)


class QualificationTest(unittest.TestCase):
    def test_workflows_use_one_extension_and_every_scan_covers_both(self):
        self.assertEqual([], [path.name for path in WORKFLOWS.iterdir() if path.suffix != ".yml"])
        check = (ROOT / "scripts/check.py").read_text()
        self.assertIn('workflows.glob("*.yml"), *workflows.glob("*.yaml")', check)

    def test_only_candidate_pushes_start_the_qualification_run(self):
        self.assertEqual({"push": {"branches": ["kci/**"]}}, triggers(text("ci.yml")))

    def test_proofs_are_defined_once_and_called_by_the_candidate_and_contribution_runs(self):
        self.assertEqual({"workflow_call": ""}, triggers(text("proofs.yml")))
        self.assertEqual(PROOFS, set(jobs(text("proofs.yml"))))
        self.assertEqual(PROOFS, {*qualify.JOBS, qualify.LANE_JOB})
        self.assertEqual("verify (${{ matrix.lane }})", jobs(text("proofs.yml"))["verify"]["name"])
        for name, caller in (("ci.yml", "proofs"), ("contributions.yml", "contribution")):
            callers = {job: body for job, body in jobs(text(name)).items() if "uses" in body}
            self.assertEqual({caller: {"uses": "./.github/workflows/proofs.yml"}}, callers, name)
        self.assertEqual(qualify.CALLER, "proofs")
        for workflow in workflows():
            if workflow.name not in {"ci.yml", "contributions.yml"}:
                self.assertFalse(any("proofs.yml" in str(value) for key, value in fields(load_workflow(workflow.read_text()))
                                     if key == "uses"), workflow.name)

    def test_outside_pull_requests_run_separately_without_secrets(self):
        self.assertEqual({"pull_request": ""}, triggers(text("contributions.yml")))
        for workflow in workflows():
            if workflow.name != "contributions.yml":
                self.assertNotIn("pull_request", triggers(workflow.read_text()), workflow.name)
        for name in ("proofs.yml", "ci.yml", "contributions.yml"):
            workflow = load_workflow(text(name))
            self.assertEqual({"contents": "read"}, workflow["permissions"], name)
            for key, value in fields(workflow):
                self.assertNotEqual("secrets", key, name)
                if isinstance(value, str):
                    self.assertNotRegex(value, r"\$\{\{[^}]*\bsecrets\.", name)
                if key == "permissions":
                    self.assertNotIn("write", value.values(), name)
        self.assertNotIn("qualified", jobs(text("contributions.yml")))

    def test_qualified_reads_every_job_conclusion_of_its_own_run(self):
        ci = jobs(text("ci.yml"))
        self.assertEqual(["proofs", "qualified"], list(ci))
        self.assertEqual(
            {"name": "qualified", "if": "always()", "needs": ["proofs"],
             "runs-on": "ubuntu-24.04", "timeout-minutes": "5",
             "permissions": {"actions": "read", "contents": "read"},
             "steps": [
                 {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                  "with": {"persist-credentials": "false"}},
                 {"name": "Require every proof job in this run to have succeeded",
                  "env": {"GH_TOKEN": "${{ github.token }}", "PROOFS_RESULT": "${{ needs.proofs.result }}"},
                  "run": "python3 scripts/qualify.py"},
             ]},
            ci["qualified"],
        )
        for workflow in workflows():
            if workflow.name != "ci.yml":
                defined = jobs(workflow.read_text())
                self.assertNotIn("qualified", defined, workflow.name)
                self.assertNotIn("qualified", [job.get("name") for job in defined.values()], workflow.name)

    def test_inventory_is_every_proof_and_one_verify_leg_per_lane(self):
        self.assertEqual(
            {"proofs / process-ownership-macos", "proofs / toolchain", "proofs / mutations", "proofs / teardown",
             "proofs / verify (floor)", "proofs / verify (mid)", "proofs / verify (latest)"},
            qualify.expected_jobs((ROOT / ".tool-versions").read_text()),
        )

    def test_verdict_refuses_every_outcome_but_each_proof_succeeding_once(self):
        expected = qualify.expected_jobs((ROOT / ".tool-versions").read_text())
        leg = "proofs / verify (mid)"
        self.assertEqual([], qualify.refusals("success", proof_jobs(), expected))
        for label, proofs_result, listing, reason in (
            ("aggregate failure", "failure", proof_jobs(), "proofs: aggregate result failure"),
            ("aggregate absent", "", proof_jobs(), "proofs: aggregate result absent"),
            ("leg cancelled before a runner", "success",
             proof_jobs(**{leg: [{"name": leg, "status": "completed", "conclusion": "cancelled"}]}),
             f"{leg}: completed/cancelled"),
            ("inner job skipped", "success",
             proof_jobs(**{"proofs / teardown": [{"name": "proofs / teardown", "status": "completed",
                                                  "conclusion": "skipped"}]}),
             "proofs / teardown: completed/skipped"),
            ("leg missing", "success", proof_jobs(**{leg: []}), f"{leg}: missing"),
            ("leg still running", "success",
             proof_jobs(**{leg: [{"name": leg, "status": "in_progress", "conclusion": None}]}),
             f"{leg}: in_progress/None"),
            ("leg twice", "success",
             proof_jobs(**{leg: [{"name": leg, "status": "completed", "conclusion": "success"}] * 2}),
             f"{leg}: 2 executions"),
            ("unknown job", "success",
             proof_jobs(**{"proofs / extra": [{"name": "proofs / extra", "status": "completed",
                                               "conclusion": "success"}]}),
             "proofs / extra: not a qualification job"),
            ("neutral", "success", proof_jobs("neutral"), "proofs / toolchain: completed/neutral"),
        ):
            with self.subTest(label):
                self.assertIn(reason, qualify.refusals(proofs_result, listing, expected))

    def test_verdict_pages_the_real_endpoint_and_exits_by_outcome(self):
        with actions_api(proof_jobs()) as (api, requests):
            qualified = verdict(api)
        self.assertEqual(0, qualified.returncode, qualified.stdout + qualified.stderr)
        self.assertIn("Qualified: ", qualified.stdout)
        self.assertEqual(3, len(requests))
        for page, request in enumerate(requests, 1):
            self.assertEqual("/repos/baselabs/request_seal/actions/runs/7/jobs", request["path"])
            self.assertEqual({"filter": ["latest"], "per_page": ["100"], "page": [str(page)]}, request["query"])
            self.assertEqual("Bearer run-token", request["authorization"])
        leg = "proofs / verify (latest)"
        with actions_api(proof_jobs(**{leg: [{"name": leg, "status": "completed", "conclusion": "cancelled"}]})) as (api, _):
            refused = verdict(api)
        self.assertEqual(1, refused.returncode)
        self.assertIn(f"{leg}: completed/cancelled", refused.stdout)
        with actions_api(proof_jobs()) as (api, _):
            refused = verdict(api, proofs_result="cancelled")
        self.assertEqual(1, refused.returncode)
        self.assertIn("proofs: aggregate result cancelled", refused.stdout)

    def test_every_job_is_bounded(self):
        for workflow in workflows():
            for job, body in jobs(workflow.read_text()).items():
                with self.subTest(workflow=workflow.name, job=job):
                    # A job that calls a reusable workflow takes no timeout; its jobs carry their own.
                    if "uses" not in body:
                        self.assertTrue(body["timeout-minutes"].isdigit())
                        self.assertGreater(int(body["timeout-minutes"]), 0)

    def test_proof_steps_run_unconditionally_except_the_declared_lane_and_evidence_steps(self):
        self.assertEqual([], proof_condition_errors(text("proofs.yml"), text("ci.yml")))
        process = jobs(text("proofs.yml"))["process-ownership-macos"]
        tests = [step for step in process["steps"] if "run" in step]
        self.assertEqual([{"run": "python3 -B -m unittest discover -s test -p processes_test.py"}], tests)

    def test_condition_bindings_reject_relocation_and_extra_conditions(self):
        original, ci = text("proofs.yml"), text("ci.yml")
        relocated = original.replace("      - if: matrix.lane == 'latest'\n        uses: actions/cache@",
                                     "      - uses: actions/cache@", 1).replace(
            "        run: python3 scripts/mutations.py",
            "        if: matrix.lane == 'latest'\n        run: python3 scripts/mutations.py", 1)
        for changed in (
            relocated,
            original.replace("  mutations:\n", "  mutations:\n    if: false\n"),
            original.replace("  verify:\n", "  verify:\n    continue-on-error: true\n"),
            original.replace("        run: python3 scripts/mutations.py",
                             "        continue-on-error: true\n        run: python3 scripts/mutations.py"),
            original.replace("      - run: python3 -B -m unittest discover -s test -p processes_test.py",
                             "      - if: false\n        run: python3 -B -m unittest discover -s test -p processes_test.py"),
            original.replace("        run: python3 scripts/mutations.py",
                             "        if: false\n        run: python3 scripts/mutations.py"),
            original.replace('        run: python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"',
                             '        if: false\n        run: python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"'),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(original, changed)
                self.assertTrue(proof_condition_errors(changed, ci))
        self.assertTrue(proof_condition_errors(original, ci.replace(
            "  qualified:\n", "  qualified:\n    continue-on-error: true\n")))

    def test_mutations_and_teardown_are_candidate_jobs_with_kept_evidence(self):
        proofs = jobs(text("proofs.yml"))
        for job, command in (("mutations", "python3 scripts/mutations.py"),
                             ("teardown", 'python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"')):
            with self.subTest(job=job):
                self.assertEqual("toolchain", proofs[job]["needs"])
                steps = proofs[job]["steps"]
                commands = [step["run"] for step in steps if "run" in step]
                self.assertEqual(1, commands.count(command))
                self.assertNotIn("if", next(step for step in steps if step.get("run") == command))
                self.assertEqual("test", proofs[job]["env"]["MIX_ENV"])
                self.assertIn("mix deps.get --check-locked", commands)
                # These proofs run without services or caches.
                self.assertNotIn("services", proofs[job])
                self.assertFalse(any(step_identity(step).split("/")[:2] == ["actions", "cache"] for step in steps))
        uploads = [step for step in proofs["teardown"]["steps"] if step_identity(step) == "actions/upload-artifact"]
        self.assertEqual(1, len(uploads))
        self.assertEqual({"uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
                          "if": "always()", "with": {"name": "jwe-teardown", "if-no-files-found": "error",
                                                       "path": "${{ runner.temp }}/jwe-teardown.json"}}, uploads[0])
        for workflow in workflows():
            if workflow.name != "proofs.yml":
                commands = [step.get("run", "") for body in jobs(workflow.read_text()).values()
                            for step in body.get("steps", [])]
                for command in commands:
                    self.assertNotIn("scripts/mutations.py", command, workflow.name)
                    self.assertNotIn("jwe_teardown_gate", command, workflow.name)


if __name__ == "__main__":
    unittest.main()
