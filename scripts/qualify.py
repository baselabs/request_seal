#!/usr/bin/env python3
"""Decide a kci/<sha> candidate's qualification from its run's own job conclusions.

The `qualified` job runs this last. It reads every job of the workflow run from the Actions
API (the latest execution of each job) and requires exactly the proof inventory below, one
execution each, completed with conclusion `success`. The aggregate `needs` result is not
enough on its own: it names only direct dependencies, so a skipped inner job or a matrix leg
cancelled before it ran can leave a reusable workflow's result green."""
import argparse
import json
import os
from pathlib import Path
import sys
from urllib.request import Request, urlopen

import toolchain

ROOT = Path(__file__).resolve().parents[1]
CALLER = "proofs"
VERDICT = "qualified"
# Every job in .github/workflows/proofs.yml; verify runs once per toolchain lane.
JOBS = ("process-ownership-macos", "toolchain", "mutations", "teardown")
LANE_JOB = "verify"


def expected_jobs(tool_versions):
    """Check names of the proofs as the candidate run reports them."""
    lanes = [lane["lane"] for lane in toolchain.toolchain(tool_versions)["matrix"]["include"]]
    names = [*JOBS, *(f"{LANE_JOB} ({lane})" for lane in lanes)]
    return {f"{CALLER} / {name}" for name in names}


def refusals(proofs_result, jobs, expected):
    """Every reason the run does not qualify; empty only when each proof ran and succeeded."""
    refused = [] if proofs_result == "success" else [f"{CALLER}: aggregate result {proofs_result or 'absent'}"]
    seen = {}
    for job in jobs:
        if job.get("name") != VERDICT:
            seen.setdefault(job.get("name"), []).append(job)
    refused += [f"{name}: missing" for name in sorted(expected - seen.keys())]
    refused += [f"{name}: not a qualification job" for name in sorted(map(str, seen.keys() - expected))]
    for name in sorted(expected & seen.keys()):
        executions = seen[name]
        if len(executions) != 1:
            refused.append(f"{name}: {len(executions)} executions")
        elif (executions[0].get("status"), executions[0].get("conclusion")) != ("completed", "success"):
            refused.append(f"{name}: {executions[0].get('status')}/{executions[0].get('conclusion')}")
    return refused


def run_jobs(api, repository, run_id, token):
    """All jobs of the run, latest execution of each, across every page."""
    jobs = []
    for page in range(1, 11):
        request = Request(
            f"{api}/repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "RequestSeal-qualify",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urlopen(request, timeout=30) as response:
            body = json.load(response)
        jobs += body["jobs"]
        if not body["jobs"] or len(jobs) >= body["total_count"]:
            return jobs
    raise ValueError("Run lists more jobs than a qualification run can hold")


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    environment = os.environ
    expected = expected_jobs((ROOT / ".tool-versions").read_text())
    jobs = run_jobs(environment["GITHUB_API_URL"], environment["GITHUB_REPOSITORY"],
                    environment["GITHUB_RUN_ID"], environment["GH_TOKEN"])
    refused = refusals(environment.get("PROOFS_RESULT", ""), jobs, expected)
    if refused:
        print("Qualification refused:\n  " + "\n  ".join(refused))
        return 1
    print("Qualified: " + ", ".join(sorted(expected)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
