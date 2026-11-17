"""Hold the qualification contract: one run per kci/<sha> candidate, joined in `qualified`."""
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PROOFS = {"process-ownership-macos", "toolchain", "verify", "mutations", "teardown"}


def text(name):
    return (WORKFLOWS / name).read_text()


def triggers(source):
    """The `on:` block, up to the next top-level key."""
    return re.search(r"(?ms)^on:\n(.*?)^\S", source)[1]


def jobs(source):
    body = source.partition("\njobs:\n")[2]
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\n", body))
    return {
        header[1]: body[header.end():following.start() if following else len(body)]
        for header, following in zip(headers, headers[1:] + [None])
    }


class QualificationTest(unittest.TestCase):
    def test_only_candidate_pushes_start_the_qualification_run(self):
        self.assertEqual("  push:\n    branches: ['kci/**']\n", triggers(text("ci.yml")))

    def test_proofs_are_defined_once_and_called_by_the_candidate_and_contribution_runs(self):
        self.assertEqual("  workflow_call:\n", triggers(text("proofs.yml")))
        self.assertEqual(PROOFS, set(jobs(text("proofs.yml"))))
        for name, caller in (("ci.yml", "proofs"), ("contributions.yml", "contribution")):
            callers = {job: body for job, body in jobs(text(name)).items() if "\n    uses: " in "\n" + body}
            self.assertEqual({caller: "    uses: ./.github/workflows/proofs.yml\n"}, callers, name)
        for workflow in WORKFLOWS.glob("*.yml"):
            if workflow.name not in {"ci.yml", "contributions.yml"}:
                self.assertNotIn("proofs.yml", workflow.read_text(), workflow.name)

    def test_outside_pull_requests_run_separately_without_secrets(self):
        self.assertEqual("  pull_request:\n", triggers(text("contributions.yml")))
        for workflow in WORKFLOWS.glob("*.yml"):
            if workflow.name != "contributions.yml":
                self.assertNotIn("pull_request", triggers(workflow.read_text()), workflow.name)
        for name in ("proofs.yml", "ci.yml", "contributions.yml"):
            source = text(name)
            self.assertNotRegex(source, r"(?m)\$\{\{[^}]*\bsecrets\.|^\s+secrets:", name)
            self.assertRegex(source, r"(?m)^permissions:\n  contents: read\n(?!  )", name)
            self.assertNotRegex(source, r"(?m)^\s+\w[\w-]*: write$", name)
        self.assertNotIn("qualified", text("contributions.yml"))

    def test_qualified_joins_every_job_and_is_named_only_in_the_candidate_run(self):
        ci = jobs(text("ci.yml"))
        self.assertEqual(["proofs", "qualified"], list(ci))
        qualified = ci["qualified"]
        self.assertIn("    name: qualified\n", qualified)
        self.assertIn("    if: always()\n", qualified)
        self.assertIn("    needs: [proofs]\n", qualified)
        for workflow in WORKFLOWS.glob("*.yml"):
            if workflow.name != "ci.yml":
                self.assertNotRegex(workflow.read_text(), r"(?m)^\s+(name: )?qualified:?\s*$", workflow.name)

    def test_qualified_refuses_any_result_but_success(self):
        script = re.search(r"(?ms)<<'PY'\n(.*?)^\s*PY\n", jobs(text("ci.yml"))["qualified"])[1]
        script = textwrap.dedent(script)

        def run(needs):
            environment = {key: value for key, value in os.environ.items() if key != "NEEDS"}
            environment["NEEDS"] = needs
            return subprocess.run([sys.executable, "-I", "-c", script], env=environment,
                                  capture_output=True, text=True, timeout=30)

        self.assertEqual(0, run('{"proofs": {"result": "success", "outputs": {}}}').returncode)
        for result in ("failure", "cancelled", "skipped"):
            with self.subTest(result=result):
                refused = run('{"proofs": {"result": "%s", "outputs": {}}}' % result)
                self.assertEqual(1, refused.returncode)
                self.assertIn("Qualification refused: proofs", refused.stdout)
        self.assertEqual(1, run("{}").returncode)

    def test_every_job_is_bounded(self):
        for workflow in WORKFLOWS.glob("*.yml"):
            for job, body in jobs(workflow.read_text()).items():
                with self.subTest(workflow=workflow.name, job=job):
                    # A job that calls a reusable workflow takes no timeout; its jobs carry their own.
                    if not body.startswith("    uses: ./"):
                        self.assertRegex(body, r"(?m)^    timeout-minutes: \d+$")

    def test_mutations_and_teardown_are_candidate_jobs_with_kept_evidence(self):
        proofs = jobs(text("proofs.yml"))
        for job, command in (("mutations", "python3 scripts/mutations.py"),
                             ("teardown", 'python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"')):
            with self.subTest(job=job):
                self.assertIn("    needs: toolchain\n", proofs[job])
                self.assertIn(f"        run: {command}\n", proofs[job])
                self.assertIn("      MIX_ENV: test\n", proofs[job])
                self.assertIn("mix deps.get --check-locked", proofs[job])
        upload = proofs["teardown"].partition("actions/upload-artifact@")[2]
        self.assertIn("        if: always()\n", upload)
        self.assertIn("          name: jwe-teardown\n", upload)
        self.assertIn("          if-no-files-found: error\n", upload)
        self.assertIn("          path: ${{ runner.temp }}/jwe-teardown.json\n", upload)
        for workflow in WORKFLOWS.glob("*.yml"):
            if workflow.name != "proofs.yml":
                source = workflow.read_text()
                self.assertNotIn("scripts/mutations.py", source, workflow.name)
                self.assertNotIn("jwe_teardown_gate", source, workflow.name)


if __name__ == "__main__":
    unittest.main()
