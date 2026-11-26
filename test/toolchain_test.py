"""Source-only contracts for the unchanged reader and every workflow consumer."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify
from workflow_yaml import load as load_workflow


def workflow_sources():
    workflows = ROOT / ".github/workflows"
    return {path.name: path.read_text() for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])}


def container_errors(name, source):
    """Workflow-managed containers cannot bypass the explicit platform startup."""
    try:
        workflow = load_workflow(source)
    except ValueError as error:
        return [f"{name}: workflow YAML: {error}"]
    errors = []
    if "services" in workflow:
        errors.append(f"{name}: services outside a job")
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return errors + [f"{name}: jobs must be mappings"]
    for job, body in jobs.items():
        if not isinstance(body, dict):
            errors.append(f"{name}: invalid job {job}")
            continue
        if "container" in body:
            errors.append(f"{name}: job container")
        if "services" in body:
            errors.append(f"{name}: services in {job}")
    return errors


class ToolchainTest(unittest.TestCase):
    def test_reader_is_the_unchanged_executable_shared_file(self):
        reader = ROOT / "scripts/toolchain.sh"
        self.assertEqual("25bbfa023b7f031256428b498fe300fcc460988fea81277072355e4c0d933764",
                         hashlib.sha256(reader.read_bytes()).hexdigest())
        self.assertEqual(0o111, reader.stat().st_mode & 0o111)

    def test_workflows_only_read_versions_through_the_shared_reader(self):
        runtime_fields = {"erlef/setup-beam": ("elixir-version", "otp-version"),
                          "actions/setup-node": ("node-version",),
                          "actions/setup-python": ("python-version",)}
        for name, source in workflow_sources().items():
            self.assertIn('scripts/toolchain.sh >> "$GITHUB_OUTPUT"', source)
            self.assertNotIn("version-file:", source)
            if name == "publish.yml":
                upload = load_workflow(source)["jobs"]["upload"]["steps"]
                reader = next(step["run"] for step in upload if step.get("id") == "pins")
                self.assertIn('git show HEAD:.tool-versions > "$RUNNER_TEMP/publication/.tool-versions"', reader)
                self.assertIn('"$RUNNER_TEMP/publication/scripts/toolchain.sh" "$RUNNER_TEMP/publication/.tool-versions"', reader)
                self.assertEqual(reader.count(".tool-versions"), source.count(".tool-versions"))
            else:
                self.assertNotIn(".tool-versions", source)
            self.assertNotRegex(source, r"(?:sh|bash) +scripts/toolchain\.sh")
            for body in load_workflow(source)["jobs"].values():
                for step in body["steps"]:
                    action = step.get("uses", "").split("@", 1)[0]
                    for field in runtime_fields.get(action, ()):
                        self.assertRegex(step["with"][field],
                                         r"^\$\{\{ (?:matrix\.(?:elixir|otp)|"
                                         r"(?:needs\.toolchain|steps\.pins)\.outputs\.\w+) \}\}$", name)
        ci = load_workflow(workflow_sources()["ci.yml"])["jobs"]
        reader = next(step for step in ci["toolchain"]["steps"] if step.get("id") == "pins")
        self.assertEqual('scripts/toolchain.sh >> "$GITHUB_OUTPUT"', reader["run"])
        self.assertTrue(any(step.get("run") == "scripts/toolchain.sh --self-test"
                            for step in ci["toolchain"]["steps"]))
        matrix = next(step for step in ci["toolchain"]["steps"] if step.get("id") == "matrix")
        self.assertEqual({"TOOLCHAIN_OUTPUTS": "${{ toJSON(steps.pins.outputs) }}"}, matrix["env"])
        self.assertEqual('python3 scripts/qualify.py --matrix >> "$GITHUB_OUTPUT"', matrix["run"])
        self.assertEqual("${{ fromJSON(needs.toolchain.outputs.matrix) }}", ci["verify"]["strategy"]["matrix"])

    def test_every_setup_refuses_different_installed_versions_before_project_code(self):
        for name, source in workflow_sources().items():
            for job, body in load_workflow(source)["jobs"].items():
                steps = body["steps"]
                for index, setup in enumerate(steps):
                    action = setup.get("uses", "").split("@", 1)[0]
                    if action == "erlef/setup-beam":
                        self.assertEqual("strict", setup["with"]["version-type"])
                        refusal = next(step for step in steps[index + 1:]
                                       if step.get("name") == "Refuse a differing installed runtime")
                        expected = {"ELIXIR": setup["with"]["elixir-version"],
                                    "OTP": setup["with"]["otp-version"]}
                        command = 'scripts/toolchain.sh --installed "elixir=$ELIXIR" "erlang=$OTP"'
                        node = next((step for step in steps if step.get("uses", "").startswith("actions/setup-node@")), None)
                        if node:
                            expected["NODEJS"] = node["with"]["node-version"]
                            command += ' "nodejs=$NODEJS"'
                            self.assertLess(steps.index(node), steps.index(refusal))
                        self.assertEqual(expected, refusal["env"], (name, job))
                        self.assertEqual(command, refusal["run"], (name, job))
                        self.assertEqual(setup.get("if"), refusal.get("if"))
                        self.assertFalse(any("mix " in step.get("run", "") for step in steps[index:steps.index(refusal)]))

    def test_qualification_labels_only_shared_output_pairs_and_keeps_build_suffixes(self):
        outputs = {"elixir": "9.3.1-otp-93", "otp": "93.2.1", "beam_lanes": json.dumps([
            {"elixir": "9.2.1-otp-92", "otp": "92.2.1"},
            {"elixir": "9.1.1-otp-91", "otp": "91.2.1"},
        ])}
        expected = {"include": [
            {"lane": "floor", "elixir": "9.1.1-otp-91", "otp": "91.2.1"},
            {"lane": "mid", "elixir": "9.2.1-otp-92", "otp": "92.2.1"},
            {"lane": "latest", "elixir": outputs["elixir"], "otp": outputs["otp"]},
        ]}
        self.assertEqual(expected, qualify.verification_matrix(outputs))
        outputs["beam_lanes"] = json.dumps(list(reversed(json.loads(outputs["beam_lanes"]))))
        self.assertEqual(expected, qualify.verification_matrix(outputs))
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/qualify.py"), "--matrix"],
                                env={"PATH": "/usr/bin:/bin", "TOOLCHAIN_OUTPUTS": json.dumps(outputs)},
                                check=True, capture_output=True, text=True, timeout=30)
        key, value = result.stdout.strip().split("=", 1)
        self.assertEqual("matrix", key)
        self.assertEqual(expected, json.loads(value))
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/qualify.py"),
                                 "--matrix", "--cache-environments"],
                                env={"PATH": "/usr/bin:/bin", "TOOLCHAIN_OUTPUTS": json.dumps(outputs)},
                                check=True, capture_output=True, text=True, timeout=30)
        key, value = result.stdout.strip().split("=", 1)
        self.assertEqual("matrix", key)
        floor, mid, latest = expected["include"]
        self.assertEqual({"include": [
            dict(floor, mix_env="test"), dict(floor, mix_env="dev"), dict(mid, mix_env="test"),
            dict(latest, mix_env="test"), dict(latest, mix_env="dev"), dict(latest, mix_env="prod"),
        ]}, json.loads(value))
        for lanes in ([], [{}], [{}, {}, {}], {}):
            with self.subTest(lanes=lanes), self.assertRaises(ValueError):
                qualify.verification_matrix({**outputs, "beam_lanes": json.dumps(lanes)})
        pair = json.loads(outputs["beam_lanes"])[0]
        for lanes in ([pair, pair], [pair, {"elixir": outputs["elixir"], "otp": outputs["otp"]}]):
            with self.subTest(duplicates=lanes), self.assertRaisesRegex(ValueError, "distinct"):
                qualify.verification_matrix({**outputs, "beam_lanes": json.dumps(lanes)})

    def test_platform_reference_is_one_complete_digest_pinned_line(self):
        source = (ROOT / ".github/postgres.ref").read_text()
        self.assertRegex(source, r"\Aghcr\.io/baselabs/postgres[:]18\.[0-9]+-inputs-[0-9a-f]{64}"
                                r"@sha256:[0-9a-f]{64}\n\Z")
        self.assertFalse((ROOT / ".github/service-images").exists())

    def test_workflow_containers_cannot_bypass_platform_startup(self):
        sources = workflow_sources()
        for name, text in sources.items():
            self.assertEqual([], container_errors(name, text))
        proofs = sources["ci.yml"]
        for changed, name in (
            (proofs.replace("  mutations:\n", "  mutations:\n    container: sidecar:latest\n"), "ci.yml"),
            (proofs.replace("  mutations:\n", "  mutations:\n    'container': sidecar:latest\n"), "ci.yml"),
            (proofs.replace("  mutations:\n", "  mutations: {container: sidecar:latest}\n"), "ci.yml"),
            ("jobs:\n  mutations: {container: sidecar:latest}\n", "ci.yml"),
            ("jobs:\n  verify:\n    services:\n      sidecar: {image: sidecar:latest}\n", "ci.yml"),
            (proofs.replace("  release-gate-self-check:\n",
                            "  release-gate-self-check:\n    services:\n      postgres:\n        image: "
                            + "${{ inputs.engine }}\n"), "ci.yml"),
            (proofs.replace("  verify:\n", "  verify:\n    services:\n      postgres:\n        image: "
                            + "${{ inputs.engine }}\n"), "ci.yml"),
            (sources["ci.yml"].replace("  qualified:\n", "  qualified:\n    services: {}\n"), "ci.yml"),
            (proofs.replace("jobs:\n", "services:\n  sidecar:\n    image: sidecar:latest\njobs:\n"),
             "ci.yml"),
            ("jobs:\n  release:\n    services:\n      postgres:\n        image: ${{ inputs.engine }}\n", "publish.yml"),
        ):
            with self.subTest(name=name, changed=changed):
                self.assertNotEqual(proofs, changed)
                self.assertTrue(container_errors(name, changed))
        commented = proofs.replace("  mutations:\n", "  mutations:\n    # container: sidecar:latest\n")
        self.assertEqual([], container_errors("ci.yml", commented))
        for field, source, line in (
            ("container", "jobs:\n  mutations:\n    'container': sidecar:latest\n", 3),
            ("image", "jobs:\n  verify:\n    services:\n      sidecar:\n        'image': sidecar:latest\n", 5),
        ):
            with self.subTest(quoted=field):
                self.assertIn(f"workflow YAML: <line {line}>:", container_errors("ci.yml", source)[0])



if __name__ == "__main__":
    unittest.main()
