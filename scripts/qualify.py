#!/usr/bin/env python3
"""Decide a kci/<sha> candidate's qualification from its run's own job conclusions.

The `qualified` job runs this last. It reads every job of the workflow run from the Actions
API (the latest execution of each job) and requires exactly the proof inventory below, one
execution each, completed with conclusion `success`. The aggregate `needs` result is not
enough on its own: it names only direct dependencies, and the matrix job has several
executions. Both direct results and every actual lane conclusion must succeed."""
import argparse
import json
import os
import sys
from urllib.request import Request, urlopen

VERDICT = "qualified"
# Every proof job in .github/workflows/ci.yml; verify runs once per toolchain lane.
JOBS = ("process-ownership-macos", "toolchain", "mutations", "teardown", "release-gate-self-check")
LANE_JOB = "verify"


def verification_matrix(outputs):
    """Label this repository's compatibility proofs from the shared reader's outputs."""
    lanes = json.loads(outputs["beam_lanes"])
    if not isinstance(lanes, list) or len(lanes) != 2:
        raise ValueError("Qualification requires two compatibility lanes and the default")
    default = {"elixir": outputs["elixir"], "otp": outputs["otp"]}
    if len({lane["elixir"].split("-otp-", 1)[0] for lane in [*lanes, default]}) != 3:
        raise ValueError("Qualification requires three distinct Elixir releases")
    lanes.sort(key=lambda lane: tuple(map(int, lane["elixir"].split("-otp-", 1)[0].split("."))))
    return {"include": [dict(lane=name, **pair) for name, pair in zip(("floor", "mid"), lanes)] + [
        dict(lane="latest", **default),
    ]}


def expected_jobs(matrix):
    """Check names of the proofs as the candidate run reports them."""
    lanes = [lane["lane"] for lane in json.loads(matrix)["include"]]
    if sorted(lanes) != ["floor", "latest", "mid"]:
        raise ValueError("Qualification requires exactly the floor, mid, and latest proofs")
    names = [*JOBS, *(f"{LANE_JOB} ({lane})" for lane in lanes)]
    return set(names)


def refusals(proofs_result, jobs, expected):
    """Every reason the run does not qualify; empty only when each proof ran and succeeded."""
    direct = {*JOBS, LANE_JOB}
    refused = []
    if not isinstance(proofs_result, dict) or set(proofs_result) != direct:
        refused.append("needs: missing or unexpected direct dependency")
    else:
        for name, body in sorted(proofs_result.items()):
            result = body.get("result") if isinstance(body, dict) else None
            if result != "success":
                refused.append(f"{name}: aggregate result {result or 'absent'}")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", action="store_true", help="Label the shared reader's runtime lanes")
    args = parser.parse_args()
    environment = os.environ
    if args.matrix:
        matrix = verification_matrix(json.loads(environment["TOOLCHAIN_OUTPUTS"]))
        print("matrix=" + json.dumps(matrix, separators=(",", ":")))
        return 0
    expected = expected_jobs(environment["VERIFY_MATRIX"])
    jobs = run_jobs(environment["GITHUB_API_URL"], environment["GITHUB_REPOSITORY"],
                    environment["GITHUB_RUN_ID"], environment["GH_TOKEN"])
    refused = refusals(json.loads(environment.get("PROOFS_RESULTS", "null")), jobs, expected)
    if refused:
        print("Qualification refused:\n  " + "\n  ".join(refused))
        return 1
    print("Qualified: " + ", ".join(sorted(expected)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
