"""Exercise toolchain pairing and GitHub outputs against the checked-in pins."""
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from workflow_yaml import load as load_workflow

spec = importlib.util.spec_from_file_location("toolchain", ROOT / "scripts/toolchain.py")
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


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
    def test_lanes_sort_paired_pins_without_copying_versions(self):
        source = (ROOT / ".tool-versions").read_text()
        configuration = pins.toolchain(source)
        entries = dict(line.split(maxsplit=1) for line in source.splitlines() if line.strip())
        pairs = list(zip(entries["elixir"].split(), entries["erlang"].split()))
        lanes = configuration["matrix"]["include"]
        self.assertEqual(["floor", "mid", "latest"], [lane["lane"] for lane in lanes])
        for lane, (elixir, otp) in zip(lanes, reversed(pairs)):
            self.assertEqual(elixir.split("-otp-")[0], lane["elixir"])
            self.assertEqual(otp, lane["otp"])
        reordered = "\n".join(
            name + " " + " ".join(reversed(versions.split())) for name, versions in entries.items()
        )
        self.assertEqual(configuration, pins.toolchain(reordered))
        self.assertEqual(entries["nodejs"], configuration["node"])
        self.assertEqual(lanes[-1]["elixir"], configuration["elixir"])
        self.assertEqual(lanes[-1]["otp"], configuration["otp"])

    def test_rejects_missing_ambiguous_or_incompatible_pins(self):
        source = (ROOT / ".tool-versions").read_text()
        lines = source.splitlines()
        elixir = lines[0].split()[1:]
        otp = lines[1].split()[1:]
        for changed in (
            "\n".join(lines[:-1]),
            source + "\nnodejs 1.2.3\n",
            source.replace(elixir[0], elixir[1]),
            source.replace(otp[0], otp[-1]),
            source.replace(elixir[0], "latest"),
            source.replace(lines[2], "nodejs lts"),
            source.replace(lines[2], lines[2] + " 1.2.3"),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                pins.toolchain(changed)

    def test_cli_writes_consumable_github_outputs(self):
        with tempfile.TemporaryDirectory(prefix="requestseal-toolchain-") as directory:
            output = Path(directory) / "outputs"
            subprocess.run(
                [sys.executable, "-I", "-B", str(ROOT / "scripts/toolchain.py"), "--github-output", str(output)],
                check=True, timeout=30,
            )
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            expected = pins.toolchain((ROOT / ".tool-versions").read_text())
            self.assertEqual(expected["matrix"], json.loads(values.pop("matrix")))
            self.assertEqual({key: value for key, value in expected.items() if key != "matrix"}, values)

    def test_workflows_read_pins_instead_of_copying_them(self):
        configuration = pins.toolchain((ROOT / ".tool-versions").read_text())
        versions = [configuration["node"]] + [
            value for lane in configuration["matrix"]["include"] for key, value in lane.items() if key != "lane"
        ]
        for name, source in workflow_sources().items():
            if "erlef/setup-beam@" in source or "actions/setup-node@" in source:
                self.assertIn('scripts/toolchain.py --github-output "$GITHUB_OUTPUT"', source)
            for version in versions:
                self.assertNotIn(version, source, name)
        proofs = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("fromJSON(needs.toolchain.outputs.matrix)", proofs)
        self.assertIn("node-version: ${{ needs.toolchain.outputs.node }}", proofs)

    def test_installed_runtime_refuses_every_release_difference(self):
        configuration = pins.toolchain((ROOT / ".tool-versions").read_text())
        for lane in configuration["matrix"]["include"]:
            expected = [lane["elixir"], lane["otp"]]
            self.assertEqual([], pins.installed_errors(*expected, expected))
            for changed in ([], expected[:1], expected + ["extra"],
                            [expected[0], expected[1].split(".")[0]],
                            [expected[0] + ".1", expected[1]],
                            [expected[0], expected[1] + ".1"]):
                self.assertTrue(pins.installed_errors(*expected, changed))
        for name, source in workflow_sources().items():
            for body in load_workflow(source)["jobs"].values():
                beam = [step for step in body["steps"] if step.get("uses", "").startswith("erlef/setup-beam@")]
                if beam:
                    self.assertTrue(all(step["with"]["version-type"] == "strict" for step in beam), name)
                    self.assertTrue(any("scripts/toolchain.py --verify-installed" in step.get("run", "")
                                        for step in body["steps"]), name)

    def test_platform_reference_is_one_complete_digest_pinned_line(self):
        source = (ROOT / ".github/postgres.ref").read_text()
        self.assertRegex(source, r"\Aghcr\.io/baselabs/postgres[:]18\.[0-9]+-inputs-[0-9a-f]{64}"
                                r"@sha256:[0-9a-f]{64}\n\Z")
        self.assertFalse((ROOT / ".github/service-images").exists())
        self.assertFalse(hasattr(pins, "service_images"))

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
            (proofs.replace("  teardown:\n", "  teardown:\n    services:\n      postgres:\n        image: "
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

    def test_notebook_tooling_requires_the_latest_lane_minor_without_reading_outside_files(self):
        configuration = pins.toolchain((ROOT / ".tool-versions").read_text())
        major, minor = configuration["elixir"].split(".")[:2]
        source = (ROOT / "tools/notebooks/mix.exs").read_text()
        self.assertEqual([f"~> {major}.{minor}"], re.findall(r'^\s*elixir: "([^"]+)",$', source, re.M))
        # Dependency updaters copy only this directory; the project must load from it alone.
        self.assertNotRegex(source, r"File\.|Path\.expand|__DIR__|\.\./")

    def test_no_tracked_source_copies_an_exact_pin(self):
        configuration = pins.toolchain((ROOT / ".tool-versions").read_text())
        versions = {configuration["node"]} | {
            value for lane in configuration["matrix"]["include"] for key, value in lane.items() if key != "lane"
        }
        # Records state the toolchain a past result was produced on; locks are resolver output.
        records = ("CHANGELOG.md", "docs/adr/", "PROVENANCE.md", "mix.lock", "corpus/")
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True, timeout=30,
        ).stdout.splitlines()
        sources = [path for path in tracked if path != ".tool-versions" and not any(
            path.startswith(record) or path.endswith(record) for record in records
        )]
        self.assertIn("tools/notebooks/mix.exs", sources)
        engine = (ROOT / ".github/postgres.ref").read_text().strip()
        image_literals = re.compile(r"(?:ghcr\.io/baselabs/)?postgres(?:[:@](?!//)[A-Za-z0-9_.-]+)"
                                    r"(?:@sha256:[0-9a-f]+)?")
        for path in sources:
            try:
                source = (ROOT / path).read_text()
            except (UnicodeDecodeError, FileNotFoundError):
                continue
            for version in versions:
                self.assertNotRegex(source, r"(?<![\d.])" + re.escape(version) + r"(?![\d.])", path)
            if path != ".github/postgres.ref":
                self.assertNotIn(engine, source, path)
                self.assertNotIn(engine.split("@sha256:")[1], source, path)
            if path.startswith((".github/workflows/", "test/")):
                self.assertEqual([], [ref for ref in image_literals.findall(source)
                                      if not ref.endswith(":current")], path)


if __name__ == "__main__":
    unittest.main()
