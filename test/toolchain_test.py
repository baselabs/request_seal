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
spec = importlib.util.spec_from_file_location("toolchain", ROOT / "scripts/toolchain.py")
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


SERVICE_IMAGE = "${{ needs.toolchain.outputs.postgres_image }}"


def workflow_sources():
    workflows = ROOT / ".github/workflows"
    return {path.name: path.read_text() for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])}


def container_errors(name, source):
    """Every image a workflow starts must be the reader's output, and only proofs/verify starts one.

    Comments are removed first; block (`image: x`) and flow (`{image: x}`) mappings both count,
    and a job container in either form is refused outright."""
    source = "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in source.splitlines())
    errors = [f"{name}: image {image}" for image in
              re.findall(r"\bimage\s*:\s*(\$\{\{[^}]*\}\}|[^\s,}]+)", source) if image != SERVICE_IMAGE]
    errors += [f"{name}: job container" for _ in re.findall(r"\bcontainer\s*:", source)]
    jobs = source.partition("\njobs:\n")[2]
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):", jobs))
    for header, following in zip(headers, headers[1:] + [None]):
        body = jobs[header.end():following.start() if following else len(jobs)]
        if re.search(r"\bservices\s*:", body) and (name, header[1]) != ("proofs.yml", "verify"):
            errors.append(f"{name}: services in {header[1]}")
    if re.search(r"\bservices\s*:", source.partition("\njobs:\n")[0]):
        errors.append(f"{name}: services outside a job")
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
                [sys.executable, str(ROOT / "scripts/toolchain.py"), "--github-output", str(output)],
                check=True, timeout=30,
            )
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            expected = pins.toolchain((ROOT / ".tool-versions").read_text())
            expected |= pins.service_images((ROOT / ".github/service-images").read_text())
            self.assertRegex(values["postgres_image"], r"^postgres@sha256:[0-9a-f]{64}$")
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
        proofs = (ROOT / ".github/workflows/proofs.yml").read_text()
        self.assertIn("fromJSON(needs.toolchain.outputs.matrix)", proofs)
        self.assertIn("node-version: ${{ needs.toolchain.outputs.node }}", proofs)

    def test_service_images_are_digest_pinned_with_one_home(self):
        source = (ROOT / ".github/service-images").read_text()
        image = pins.service_images(source)["postgres_image"]
        digest = image.split("@sha256:", 1)[1]
        for changed in (
            source.replace(image, "postgres:18"),
            source.replace(image, image[:-1]),
            source.replace(image, "postgres@sha256:" + digest.upper()),
            source.replace(image, "other@sha256:" + digest),
            source + image.join(("postgres=", "\n")),
            source + "redis=redis@sha256:" + digest + "\n",
            source.replace("postgres=", "postgres "),
            "# no services\n",
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                pins.service_images(changed)
        # Every workflow takes a service image from the reader's output, never a literal.
        sources = workflow_sources()
        for name, text in sources.items():
            self.assertNotIn(digest, text, name)
            self.assertEqual([], container_errors(name, text))
        proofs = sources["proofs.yml"]
        self.assertIn("        image: " + SERVICE_IMAGE + "\n", proofs)
        verify = "    services:\n      postgres:\n        image: " + SERVICE_IMAGE
        for changed, name in (
            (proofs.replace(SERVICE_IMAGE, "postgres:18"), "proofs.yml"),
            (proofs.replace(SERVICE_IMAGE, '"postgres:18"'), "proofs.yml"),
            (proofs.replace(verify, "    services: {postgres: {image: postgres:18}}"), "proofs.yml"),
            (proofs.replace(verify, '    services: {postgres: {image: "' + image + '"}}'), "proofs.yml"),
            (proofs.replace("  mutations:\n", "  mutations:\n    container: postgres:18\n"), "proofs.yml"),
            (proofs.replace("  mutations:\n", "  mutations:\n    container: {image: " + SERVICE_IMAGE + "}\n"),
             "proofs.yml"),
            (proofs.replace("  teardown:\n", "  teardown:\n    services:\n      postgres:\n        image: "
                            + SERVICE_IMAGE + "\n"), "proofs.yml"),
            (sources["ci.yml"].replace("  qualified:\n", "  qualified:\n    services: {}\n"), "ci.yml"),
            (proofs.replace(verify, verify), "contributions.yml"),
        ):
            with self.subTest(name=name, changed=changed):
                self.assertTrue(container_errors(name, changed))
        commented = proofs.replace("  mutations:\n", "  mutations:\n    # container: postgres:18\n")
        self.assertEqual([], container_errors("proofs.yml", commented))
        self.assertIn("postgres_image: ${{ steps.pins.outputs.postgres_image }}",
                      (ROOT / ".github/workflows/proofs.yml").read_text())

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
        for path in sources:
            try:
                source = (ROOT / path).read_text()
            except (UnicodeDecodeError, FileNotFoundError):
                continue
            for version in versions:
                self.assertNotRegex(source, r"(?<![\d.])" + re.escape(version) + r"(?![\d.])", path)


if __name__ == "__main__":
    unittest.main()
