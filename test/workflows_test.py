"""Hold the qualification contract: one run per kci/<sha> candidate, judged by `qualified`."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify  # noqa: E402
from workflow_yaml import load as load_workflow  # noqa: E402
from jwe_release_gates import ROUNDS  # noqa: E402

WORKFLOWS = ROOT / ".github/workflows"
PROOFS = {"process-ownership-macos", "toolchain", "verify", "mutations",
          "release-gate-self-check"}
VERIFY_MATRIX = json.dumps({"include": [{"lane": lane} for lane in ("floor", "mid", "latest")]})


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
    return step["uses"].split("@", 1)[0] if "uses" in step else step.get("name", step["run"])


def proof_condition_errors(source, ci_source):
    proofs = {name: body for name, body in jobs(source).items() if name != "qualified"}
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
        ("verify", "actions/cache/restore"): [
            "matrix.lane != 'mid'", "matrix.lane == 'latest'", "matrix.lane == 'latest'",
        ],
        ("verify", "mix test --warnings-as-errors"): ["matrix.lane == 'floor'", "matrix.lane == 'mid'"],
        ("verify", "python3 scripts/check_optional_clients.py"): ["matrix.lane == 'floor'"],
        ("verify", "python3 scripts/check.py"): ["matrix.lane == 'latest'"],
        ("verify", "Remove disposable PostgreSQL"): ["always()"],
        ("release-gate-self-check", "actions/upload-artifact"): ["always()"],
    }
    if conditions != expected:
        errors.append("proof conditions must bind exactly to the declared job and step")
    for workflow in (load_workflow(source), load_workflow(ci_source)):
        if any(key == "continue-on-error" for key, _ in fields(workflow)):
            errors.append("continue-on-error is forbidden")
    return errors


def proof_jobs(conclusion="success", **changes):
    """A run's job listing as the Actions API reports it, every proof succeeding by default."""
    names = sorted(qualify.expected_jobs(VERIFY_MATRIX))
    listing = [{"name": name, "status": "completed", "conclusion": conclusion} for name in names]
    listing.append({"name": "qualified", "status": "in_progress", "conclusion": None})
    for name, job in changes.items():
        listing = [entry for entry in listing if entry["name"] != name]
        listing += job
    return listing


def direct_results(result="success"):
    return {name: {"result": result} for name in PROOFS}


class QualificationTest(unittest.TestCase):
    def test_workflows_use_one_extension_and_every_scan_covers_both(self):
        self.assertEqual([], [path.name for path in WORKFLOWS.iterdir() if path.suffix != ".yml"])
        check = (ROOT / "scripts/check.py").read_text()
        self.assertIn('workflows.glob("*.yml"), *workflows.glob("*.yaml")', check)

    def test_only_candidate_pushes_start_the_qualification_run(self):
        self.assertEqual({"push": {"branches": ["kci/**"]}}, triggers(text("ci.yml")))

    def test_proofs_are_defined_once_in_the_candidate_run(self):
        ci = jobs(text("ci.yml"))
        self.assertEqual(PROOFS | {"qualified"}, set(ci))
        self.assertEqual(PROOFS, {*qualify.JOBS, qualify.LANE_JOB})
        self.assertEqual("verify (${{ matrix.lane }})", ci["verify"]["name"])
        self.assertEqual({"ci.yml", "cache-warmer.yml", "publish.yml"}, {p.name for p in workflows()})
        self.assertFalse(any("uses" in body for body in ci.values()))

    def test_every_job_installs_and_checks_the_readers_exact_python_pin(self):
        pins = (ROOT / ".tool-versions").read_text()
        self.assertRegex(pins, r"(?m)^python \d+\.\d+\.\d+$")
        action = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
        pin = re.search(r"(?m)^python (\d+\.\d+\.\d+)$", pins)[1]
        probe = 'scripts/toolchain.sh --installed "python=$EXPECTED_PYTHON"'
        for path in workflows():
            source = path.read_text()
            self.assertIn(action + " # v5.6.0", source)
            self.assertNotIn("version-file", source, path.name)
            for job, body in jobs(source).items():
                with self.subTest(workflow=path.name, job=job):
                    steps = body["steps"]
                    readers = [step for step in steps if step.get("id") == "pins"]
                    output = "steps.pins" if readers else "needs.toolchain"
                    expected = "${{ " + output + ".outputs.python }}"
                    setups = [step for step in steps if step.get("uses", "").startswith("actions/setup-python@")]
                    self.assertEqual(1, len(setups))
                    setup = setups[0]
                    self.assertEqual(action, setup["uses"])
                    self.assertEqual({"python-version": expected}, setup["with"])
                    self.assertNotIn("if", setup)
                    refusal = steps[steps.index(setup) + 1]
                    self.assertEqual("Refuse a differing installed Python", refusal["name"])
                    self.assertNotIn("if", refusal)
                    self.assertEqual({"EXPECTED_PYTHON": expected}, refusal["env"])
                    self.assertEqual(probe, refusal["run"])
                    self.assertFalse(any("python3" in step.get("run", "")
                                         for step in steps[:steps.index(setup)]))
                    if readers:
                        self.assertLess(steps.index(readers[0]), steps.index(setup))
                    else:
                        needs = body["needs"]
                        self.assertIn("toolchain", [needs] if isinstance(needs, str) else needs)
        for expected, status in ((pin, 0), ("0.0.0", 1)):
            result = subprocess.run(["scripts/toolchain.sh", "--installed", f"python={expected}"],
                                    cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(status, result.returncode, result.stderr)
        ci = jobs(text("ci.yml"))
        self.assertEqual("${{ steps.pins.outputs.python }}", ci["toolchain"]["outputs"]["python"])

    def test_no_pull_request_or_tag_executes_a_workflow(self):
        for path in workflows():
            events = triggers(path.read_text())
            self.assertNotIn("pull_request", events)
            self.assertNotIn("pull_request_target", events)
            if "push" in events:
                self.assertNotIn("tags", events["push"])
                self.assertIn("branches", events["push"])
        ci = load_workflow(text("ci.yml"))
        self.assertEqual({"contents": "read"}, ci["permissions"])
        self.assertNotIn("secrets.", text("ci.yml"))

    def test_qualified_reads_every_job_conclusion_of_its_own_run(self):
        ci = jobs(text("ci.yml"))
        verdict = ci["qualified"]
        self.assertEqual("qualified", list(ci)[-1])
        self.assertNotIn("name", verdict)
        self.assertEqual("always()", verdict["if"])
        self.assertEqual(set(ci) - {"qualified"}, set(verdict["needs"]))
        self.assertEqual({"actions": "read", "contents": "read"}, verdict["permissions"])
        self.assertEqual({"GH_TOKEN": "${{ github.token }}", "PROOFS_RESULTS": "${{ toJSON(needs) }}",
                          "VERIFY_MATRIX": "${{ needs.toolchain.outputs.matrix }}"},
                         verdict["steps"][-1]["env"])
        self.assertEqual("python3 scripts/qualify.py", verdict["steps"][-1]["run"])
        for path in workflows():
            if path.name != "ci.yml":
                self.assertNotIn("qualified", jobs(path.read_text()))

    def test_inventory_is_every_proof_and_one_verify_leg_per_lane(self):
        self.assertEqual(
            {"process-ownership-macos", "toolchain", "mutations",
             "release-gate-self-check", "verify (floor)", "verify (mid)", "verify (latest)"},
            qualify.expected_jobs(VERIFY_MATRIX),
        )

    def test_inventory_refuses_missing_duplicated_or_unrecognized_lanes(self):
        for lanes in ([], ["floor", "mid"], ["floor", "floor", "latest"], ["floor", "mid", "extra"]):
            with self.subTest(lanes=lanes), self.assertRaises(ValueError):
                qualify.expected_jobs(json.dumps({"include": [{"lane": lane} for lane in lanes]}))
        source = (ROOT / "scripts/qualify.py").read_text()
        self.assertNotIn(".tool-versions", source)
        self.assertNotIn("import toolchain", source)

    def test_verdict_refuses_every_outcome_but_each_proof_succeeding_once(self):
        expected = qualify.expected_jobs(VERIFY_MATRIX)
        leg = "verify (mid)"
        self.assertEqual([], qualify.refusals(direct_results(), proof_jobs(), expected))
        for label, proofs_result, listing, reason in (
            ("aggregate failure", direct_results("failure"), proof_jobs(), "toolchain: aggregate result failure"),
            ("aggregate absent", None, proof_jobs(), "needs: missing or unexpected direct dependency"),
            ("leg cancelled before a runner", direct_results(),
             proof_jobs(**{leg: [{"name": leg, "status": "completed", "conclusion": "cancelled"}]}),
             f"{leg}: completed/cancelled"),
            ("inner job skipped", direct_results(),
             proof_jobs(mutations=[{"name": "mutations", "status": "completed",
                                    "conclusion": "skipped"}]),
             "mutations: completed/skipped"),
            ("leg missing", direct_results(), proof_jobs(**{leg: []}), f"{leg}: missing"),
            ("leg still running", direct_results(),
             proof_jobs(**{leg: [{"name": leg, "status": "in_progress", "conclusion": None}]}),
             f"{leg}: in_progress/None"),
            ("leg twice", direct_results(),
             proof_jobs(**{leg: [{"name": leg, "status": "completed", "conclusion": "success"}] * 2}),
             f"{leg}: 2 executions"),
            ("unknown job", direct_results(),
             proof_jobs(**{"extra": [{"name": "extra", "status": "completed",
                                               "conclusion": "success"}]}),
             "extra: not a qualification job"),
            ("neutral", direct_results(), proof_jobs("neutral"), "toolchain: completed/neutral"),
        ):
            with self.subTest(label):
                self.assertIn(reason, qualify.refusals(proofs_result, listing, expected))

    def test_every_direct_dependency_must_exist_and_succeed(self):
        expected = qualify.expected_jobs(VERIFY_MATRIX)
        for name in PROOFS:
            for result in ("failure", "cancelled", "skipped", "neutral", None):
                changed = direct_results()
                changed[name] = {"result": result}
                self.assertTrue(qualify.refusals(changed, proof_jobs(), expected))
            changed = direct_results()
            del changed[name]
            self.assertTrue(qualify.refusals(changed, proof_jobs(), expected))
        for changed in ({}, [], "success", {**direct_results(), "extra": {"result": "success"}}):
            self.assertTrue(qualify.refusals(changed, proof_jobs(), expected))

    def test_every_job_is_bounded(self):
        for workflow in workflows():
            for job, body in jobs(workflow.read_text()).items():
                with self.subTest(workflow=workflow.name, job=job):
                    value = body["timeout-minutes"]
                    limits = [int(value)] if value.isdigit() else list(map(int, re.findall(r"\b\d+\b", value)))
                    self.assertTrue(limits)
                    self.assertTrue(all(5 <= limit <= 90 for limit in limits))
                    self.assertRegex(workflow.read_text(), r"timeout-minutes:.*(?:#.*(?:run|green)|\$\{\{)")

    def test_cold_measurements_replace_the_restored_estimate(self):
        ci = text("ci.yml")
        self.assertIn("run 44295770186 cold 11m02s/25m27s", ci)
        self.assertIn("latest's PLT restore missed", ci)
        self.assertEqual("${{ matrix.lane == 'latest' && 51 || matrix.lane == 'floor' && 29 || 23 }}",
                         jobs(ci)["verify"]["timeout-minutes"])
        self.assertIn("run 44299761657: cold 4m54s", text("cache-warmer.yml"))
        self.assertIn("run 44295770186: cold 22m51s", text("publish.yml"))

    def test_only_packed_archive_consumers_resolve_fresh_and_all_projects_audit_both_feeds(self):
        fresh = set()
        audits = {}
        for path in (ROOT / "scripts").glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.List):
                    continue
                command = [part.value if isinstance(part, ast.Constant) else None for part in node.elts]
                if command[:2] == ["mix", "deps.get"] and "--check-locked" not in command:
                    owner = next((function.name for function in tree.body
                                  if isinstance(function, ast.FunctionDef) and node in ast.walk(function)), None)
                    fresh.add((path.name, owner))
            audits[path.name] = tree
        self.assertEqual({("check_optional_clients.py", "check"),
                          ("check_optional_clients.py", "check_client_floors")}, fresh)
        for name, owner in (("check.py", "notebooks"), ("check.py", "__main__"),
                            ("check_jose_libraries.py", "main")):
            tree = audits[name]
            scope = next(node for node in tree.body if isinstance(node, ast.If)) if owner == "__main__" else next(
                node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == owner)
            commands = [ast.literal_eval(node) for node in ast.walk(scope)
                        if isinstance(node, ast.List) and all(isinstance(part, ast.Constant) for part in node.elts)]
            for audit in ("hex.audit", "deps.audit"):
                self.assertIn(["mix", audit], commands, (name, owner))
        notebook = (ROOT / "tools/notebooks/check.exs").read_text()
        self.assertIn('System.fetch_env!("REQUESTSEAL_PACKED_SOURCE")', notebook)
        self.assertIn('not File.exists?(Path.join(packed_source, "mix.lock"))', notebook)
        self.assertIn('local_source!(source, root, nil, packed_source)', notebook)
        self.assertIn('inspect({:request_seal, [path: packed_source || root]})', notebook)
        manifest = json.loads((ROOT / "scripts/jose_libraries/package.json").read_text())
        self.assertRegex(manifest["packageManager"], r"^npm@\d+\.\d+\.\d+$")
        self.assertIn('["npm", "ci",', (ROOT / "scripts/check_jose_libraries.py").read_text())
        consumer = (ROOT / "test/ash_consumer_test.exs").read_text()
        self.assertEqual(2, consumer.count('["deps.get", "--check-locked"]'))

    def test_proof_steps_run_unconditionally_except_the_declared_lane_and_evidence_steps(self):
        self.assertEqual([], proof_condition_errors(text("ci.yml"), text("ci.yml")))
        process = jobs(text("ci.yml"))["process-ownership-macos"]
        self.assertEqual("toolchain", process["needs"])
        tests = [step for step in process["steps"] if "run" in step
                 and step.get("name") != "Refuse a differing installed Python"]
        self.assertEqual([{"run": "python3 -B -m unittest discover -s test -p processes_test.py"}], tests)

    def test_condition_bindings_reject_relocation_and_extra_conditions(self):
        original, ci = text("ci.yml"), text("ci.yml")
        relocated = original.replace("      - name: Restore Dialyzer PLT\n        if: matrix.lane == 'latest'\n",
                                     "      - name: Restore Dialyzer PLT\n", 1).replace(
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
            original.replace("        run: |\n          python3 scripts/jwe_release_gates.py round",
                             "        if: false\n        run: |\n          python3 scripts/jwe_release_gates.py round"),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(original, changed)
                self.assertTrue(proof_condition_errors(changed, ci))
        self.assertTrue(proof_condition_errors(original, ci.replace(
            "  qualified:\n", "  qualified:\n    continue-on-error: true\n")))

    def test_mutations_are_a_candidate_proof_and_teardown_is_a_publication_gate(self):
        proofs = jobs(text("ci.yml"))
        pub = jobs(text("publish.yml"))
        self.assertNotIn("teardown", proofs)
        self.assertEqual({"release-gate-verdict", "teardown"}, set(pub["publish"]["needs"]))
        self.assertNotIn("environment", pub["teardown"])
        self.assertEqual(pub["publish"]["if"], pub["teardown"]["if"])
        self.assertEqual("${{ github.sha }}", pub["teardown"]["steps"][1]["with"]["ref"])
        self.assertEqual("toolchain", proofs["mutations"]["needs"])
        for job, command in (
            (proofs["mutations"], "python3 scripts/mutations.py"),
            (pub["teardown"], 'python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"'),
        ):
            steps = job["steps"]
            commands = [step["run"] for step in steps if "run" in step]
            self.assertEqual(1, commands.count(command))
            step = next(step for step in steps if step.get("run") == command)
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)
            self.assertNotIn("continue-on-error", job)
            self.assertEqual("test", job["env"]["MIX_ENV"])
            self.assertIn("mix deps.get --check-locked", commands[:commands.index(command)])
            self.assertNotIn("services", job)
        uploads = [step for step in pub["teardown"]["steps"] if step_identity(step) == "actions/upload-artifact"]
        self.assertEqual(1, len(uploads))
        self.assertEqual({"uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
                          "if": "always()", "with": {"name": "jwe-teardown", "if-no-files-found": "error",
                                                       "retention-days": "7",
                                                       "path": "${{ runner.temp }}/jwe-teardown.json"}}, uploads[0])
        for workflow in workflows():
            for name, job in jobs(workflow.read_text()).items():
                for step in job["steps"]:
                    command = step.get("run", "")
                    if "scripts/mutations.py" in command:
                        self.assertEqual(("ci.yml", "mutations"), (workflow.name, name))
                    if "scripts/jwe_teardown_gate.py" in command:
                        self.assertEqual(("publish.yml", "teardown"), (workflow.name, name))

    def test_only_publication_requires_all_full_performance_rounds(self):
        ci = jobs(text("ci.yml"))
        pub = jobs(text("publish.yml"))
        self.assertNotIn("release-gate-round", ci)
        self.assertNotIn("release-gate-verdict", ci)
        self_check = next(step["run"] for step in ci["release-gate-self-check"]["steps"]
                          if step.get("name") == "Run both versions and validate the retained evidence")
        for command in ("round --id 1", "collect"):
            self.assertIn(f"jwe_release_gates.py {command} --self-check", self_check)
        rounds, verdict = pub["release-gate-round"], pub["release-gate-verdict"]
        self.assertEqual([str(i) for i in range(1, ROUNDS + 1)], rounds["strategy"]["matrix"]["round"])
        self.assertEqual("false", rounds["strategy"]["fail-fast"])
        self.assertEqual("release-gate-round", verdict["needs"])
        self.assertIn("release-gate-verdict", pub["publish"]["needs"])
        self.assertNotIn("--build-directory", str(rounds["steps"]))
        for job in (rounds, verdict):
            self.assertEqual("ubuntu-24.04", job["runs-on"])
            self.assertNotIn("environment", job)
            self.assertIn("github.actor", job["if"])
            self.assertIn("github.triggering_actor", job["if"])
            self.assertEqual('test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"', job["steps"][0]["run"])
            self.assertNotIn("--self-check", str(job["steps"]))

    def test_every_upload_sets_retention_for_its_reader(self):
        # CI rule: 1 day for an artifact a later job of the same run
        # downloads, 7 days for anything read after the run.
        found = 0
        for workflow in workflows():
            steps = [step for body in jobs(workflow.read_text()).values() for step in body.get("steps", [])]
            downloaded = {step.get("with", {}).get("name") for step in steps
                          if step_identity(step) == "actions/download-artifact"}
            for step in steps:
                if step_identity(step) == "actions/upload-artifact":
                    found += 1
                    with self.subTest(workflow=workflow.name, name=step["with"].get("name")):
                        expected = "1" if step["with"].get("name") in downloaded else "7"
                        self.assertEqual(expected, step["with"].get("retention-days"))
        self.assertGreater(found, 0)

    def test_only_the_default_branch_warmer_saves_caches(self):
        warmer = load_workflow(text("cache-warmer.yml"))
        self.assertEqual({"push": {"branches": ["main"]}, "schedule": [{"cron": "19 6 * * *"}],
                          "workflow_dispatch": ""}, warmer["on"])
        self.assertNotIn("secrets.", text("cache-warmer.yml"))
        for name, job in warmer["jobs"].items():
            self.assertNotIn("environment", job)
            self.assertEqual('test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"', job["steps"][0]["run"], name)
        for path in workflows():
            for body in jobs(path.read_text()).values():
                for step in body["steps"]:
                    action = step.get("uses", "").split("@", 1)[0]
                    self.assertNotEqual("actions/cache", action)
                    if action == "actions/cache/save":
                        self.assertEqual("cache-warmer.yml", path.name)
                    if action.startswith("actions/cache/"):
                        self.assertEqual(action + "@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", step["uses"])
                        self.assertNotIn("restore-keys", step["with"])
                    if action.startswith("actions/setup-"):
                        self.assertNotIn("cache", step.get("with", {}))
                    if action == "actions/setup-node":
                        self.assertEqual("false", step["with"]["package-manager-cache"])

    def test_qualification_restores_the_exact_caches_the_warmer_saves(self):
        def restores(job):
            return [step for step in job["steps"] if step_identity(step) == "actions/cache/restore"]

        def template(lane, pins, environment):
            expr = lambda value: "$" + "{{ " + value + " }}"
            lock = expr("hashFiles('mix.lock')")
            config = expr("hashFiles('mix.exs', 'config/**/*.exs')")
            return (f"mix-{lane}-{expr(pins + '.elixir')}-{expr(pins + '.otp')}-{environment}-"
                    f"{expr('runner.os')}-{expr('runner.arch')}-{lock}-{config}")

        warmer = jobs(text("cache-warmer.yml"))
        ci = jobs(text("ci.yml"))
        mix_lookups = restores(warmer["mix"])
        mix, plt, restore_for_plt = mix_lookups
        benchmark, = restores(warmer["benchmark"])
        self.assertEqual("${{ fromJSON(needs.toolchain.outputs.matrix) }}", warmer["mix"]["strategy"]["matrix"])
        self.assertEqual("${{ matrix.mix_env }}", warmer["mix"]["env"]["MIX_ENV"])
        self.assertIn('python3 scripts/qualify.py --matrix --cache-environments',
                      warmer["toolchain"]["steps"][-1]["run"])
        self.assertEqual(template("${{ matrix.lane }}", "matrix", "${{ matrix.mix_env }}"), mix["with"]["key"])
        self.assertEqual(mix["with"]["key"], restore_for_plt["with"]["key"])
        self.assertEqual(mix["with"]["path"], restore_for_plt["with"]["path"])
        self.assertEqual("matrix.lane == 'latest' && matrix.mix_env == 'dev'", plt["if"])

        for job, lookups in ((warmer["mix"], (mix, plt)), (warmer["benchmark"], (benchmark,))):
            saves = [step for step in job["steps"] if step_identity(step) == "actions/cache/save"]
            self.assertEqual(len(lookups), len(saves))
            for lookup, save in zip(lookups, saves):
                identifier = lookup["id"]
                self.assertEqual("true", lookup["with"]["lookup-only"])
                self.assertEqual(lookup["with"]["path"], save["with"]["path"])
                self.assertEqual("${{ steps." + identifier + ".outputs.cache-primary-key }}", save["with"]["key"])
                self.assertIn(f"steps.{identifier}.outputs.cache-hit != 'true'", save["if"])
        root_steps = warmer["mix"]["steps"]
        commands = [step.get("run", "") for step in root_steps]
        compile_deps = commands.index("mix deps.compile")
        build_plt = commands.index("mix dialyzer --plt")
        save_deps = next(root_steps.index(step) for step in root_steps
                         if step_identity(step) == "actions/cache/save")
        self.assertLess(compile_deps, save_deps)
        self.assertLess(save_deps, build_plt)
        warm_bench = next(step["run"] for step in warmer["benchmark"]["steps"]
                          if "mix deps.compile" in step.get("run", ""))
        self.assertIn("mix deps.compile --skip-local-deps", warm_bench)

        verify_test, verify_dev, verify_prod, verify_plt = restores(ci["verify"])
        self.assertNotIn("if", verify_test)
        self.assertEqual("matrix.lane != 'mid'", verify_dev["if"])
        self.assertEqual("matrix.lane == 'latest'", verify_prod["if"])
        self.assertEqual("matrix.lane == 'latest'", verify_plt["if"])
        for env, restore in zip(("test", "dev", "prod"), (verify_test, verify_dev, verify_prod)):
            self.assertEqual(template("${{ matrix.lane }}", "matrix", env), restore["with"]["key"])
            self.assertEqual(f"deps\n_build/{env}\n", restore["with"]["path"])
        mutation, = restores(ci["mutations"])
        self.assertEqual(verify_test["with"]["path"], mutation["with"]["path"])
        self.assertEqual(template("latest", "needs.toolchain.outputs", "test"), mutation["with"]["key"])
        self.assertNotIn("if", mutation)
        self.assertEqual("dialyzer-plt-" + verify_dev["with"]["key"], verify_plt["with"]["key"])
        self.assertEqual(verify_plt["with"], {key: plt["with"][key] for key in ("key", "path")})
        self_check = ci["release-gate-self-check"]
        restored_benchmark, = restores(self_check)
        self.assertEqual({key: benchmark["with"][key] for key in ("key", "path")}, restored_benchmark["with"])
        self.assertIn(template("latest", "needs.toolchain.outputs", "prod"), restored_benchmark["with"]["key"])
        steps = self_check["steps"]
        run = next(step for step in steps if "scripts/jwe_release_gates.py round" in step.get("run", ""))
        self.assertLess(steps.index(restored_benchmark), steps.index(run))
        self.assertIn('--build-directory "$RUNNER_TEMP/release-gate-build"', run["run"])


if __name__ == "__main__":
    unittest.main()
