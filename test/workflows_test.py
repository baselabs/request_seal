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

WORKFLOWS = ROOT / ".github/workflows"
PROOFS = {"process-ownership-macos", "toolchain", "verify", "mutations", "teardown"}


def text(name):
    return (WORKFLOWS / name).read_text()


def workflows():
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def uncommented(source):
    return "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in source.splitlines()) + "\n"


def triggers(source):
    """The `on:` block, up to the next top-level key."""
    return re.search(r"(?ms)^on:\n(.*?)^\S", uncommented(source))[1]


def jobs(source):
    body = uncommented(source).partition("\njobs:\n")[2]
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\n", body))
    return {
        header[1]: body[header.end():following.start() if following else len(body)]
        for header, following in zip(headers, headers[1:] + [None])
    }


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
        self.assertEqual("  push:\n    branches: ['kci/**']\n", triggers(text("ci.yml")))

    def test_proofs_are_defined_once_and_called_by_the_candidate_and_contribution_runs(self):
        self.assertEqual("  workflow_call:\n", triggers(text("proofs.yml")))
        self.assertEqual(PROOFS, set(jobs(text("proofs.yml"))))
        self.assertEqual(PROOFS, {*qualify.JOBS, qualify.LANE_JOB})
        self.assertIn("    name: verify (${{ matrix.lane }})\n", jobs(text("proofs.yml"))["verify"])
        for name, caller in (("ci.yml", "proofs"), ("contributions.yml", "contribution")):
            callers = {job: body for job, body in jobs(text(name)).items() if "\n    uses: " in "\n" + body}
            self.assertEqual({caller: "    uses: ./.github/workflows/proofs.yml\n"}, callers, name)
        self.assertEqual(qualify.CALLER, "proofs")
        for workflow in workflows():
            if workflow.name not in {"ci.yml", "contributions.yml"}:
                self.assertNotIn("proofs.yml", workflow.read_text(), workflow.name)

    def test_outside_pull_requests_run_separately_without_secrets(self):
        self.assertEqual("  pull_request:\n", triggers(text("contributions.yml")))
        for workflow in workflows():
            if workflow.name != "contributions.yml":
                self.assertNotIn("pull_request", triggers(workflow.read_text()), workflow.name)
        for name in ("proofs.yml", "ci.yml", "contributions.yml"):
            source = text(name)
            self.assertNotRegex(source, r"(?m)\$\{\{[^}]*\bsecrets\.|^\s+secrets:", name)
            self.assertRegex(source, r"(?m)^permissions:\n  contents: read\n(?!  )", name)
            self.assertNotRegex(source, r"(?m)^\s+\w[\w-]*: write$", name)
        self.assertNotIn("qualified", text("contributions.yml"))

    def test_qualified_reads_every_job_conclusion_of_its_own_run(self):
        ci = jobs(text("ci.yml"))
        self.assertEqual(["proofs", "qualified"], list(ci))
        self.assertEqual(
            "    name: qualified\n"
            "    if: always()\n"
            "    needs: [proofs]\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 5\n"
            "    permissions:\n"
            "      actions: read\n"
            "      contents: read\n"
            "    steps:\n"
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "      - name: Require every proof job in this run to have succeeded\n"
            "        env:\n"
            "          GH_TOKEN: ${{ github.token }}\n"
            "          PROOFS_RESULT: ${{ needs.proofs.result }}\n"
            "        run: python3 scripts/qualify.py\n",
            ci["qualified"],
        )
        for workflow in workflows():
            if workflow.name != "ci.yml":
                self.assertNotRegex(workflow.read_text(), r"(?m)^\s+(name: )?qualified:?\s*$", workflow.name)

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
                    if not body.startswith("    uses: ./"):
                        self.assertRegex(body, r"(?m)^    timeout-minutes: \d+$")

    def test_proof_steps_run_unconditionally_except_the_declared_lane_and_evidence_steps(self):
        conditions = re.findall(r"(?m)^\s+(?:- )?if:\s*(.+?)\s*$", uncommented(text("proofs.yml")))
        self.assertEqual(sorted([
            "matrix.lane == 'latest'", "matrix.lane == 'floor'", "matrix.lane == 'mid'",
            "matrix.lane == 'floor'", "matrix.lane == 'latest'", "always()",
        ]), sorted(conditions))
        self.assertNotRegex(uncommented(text("proofs.yml")), r"continue-on-error")

    def test_mutations_and_teardown_are_candidate_jobs_with_kept_evidence(self):
        proofs = jobs(text("proofs.yml"))
        for job, command in (("mutations", "python3 scripts/mutations.py"),
                             ("teardown", 'python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"')):
            with self.subTest(job=job):
                self.assertIn("    needs: toolchain\n", proofs[job])
                self.assertIn(f"        run: {command}\n", proofs[job])
                self.assertIn("      MIX_ENV: test\n", proofs[job])
                self.assertIn("mix deps.get --check-locked", proofs[job])
                # Neither job caches dependencies (verify caches none), and mutations proves it
                # needs no database by running without one.
                self.assertNotRegex(proofs[job], r"actions/cache@|\bservices\b|\bimage\s*:")
        upload = proofs["teardown"].partition("actions/upload-artifact@")[2]
        self.assertIn("        if: always()\n", upload)
        self.assertIn("          name: jwe-teardown\n", upload)
        self.assertIn("          if-no-files-found: error\n", upload)
        self.assertIn("          path: ${{ runner.temp }}/jwe-teardown.json\n", upload)
        for workflow in workflows():
            if workflow.name != "proofs.yml":
                source = workflow.read_text()
                self.assertNotIn("scripts/mutations.py", source, workflow.name)
                self.assertNotIn("jwe_teardown_gate", source, workflow.name)


if __name__ == "__main__":
    unittest.main()
