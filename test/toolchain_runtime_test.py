"""Hosted checks that execute the shared reader against the repository's runtime pins."""
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify


def configuration():
    output = subprocess.run(
        [str(ROOT / "scripts/toolchain.sh")], cwd=ROOT, check=True,
        capture_output=True, text=True, timeout=30,
    ).stdout
    outputs = dict(line.split("=", 1) for line in output.splitlines())
    return {**outputs, "matrix": qualify.verification_matrix(outputs)}


class ToolchainRuntimeTest(unittest.TestCase):
    def test_notebook_tooling_requires_the_latest_lane_minor_without_reading_outside_files(self):
        pins = configuration()
        major, minor = pins["elixir"].split(".")[:2]
        source = (ROOT / "tools/notebooks/mix.exs").read_text()
        self.assertEqual([f"~> {major}.{minor}"], re.findall(r'^\s*elixir: "([^"]+)",$', source, re.M))
        # Dependency updaters copy only this directory; the project must load from it alone.
        self.assertNotRegex(source, r"File\.|Path\.expand|__DIR__|\.\./")

    def test_no_tracked_source_copies_an_exact_pin(self):
        pins = configuration()
        versions = {pins["nodejs"]} | {
            value for lane in pins["matrix"]["include"] for key, value in lane.items() if key != "lane"
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
        # A name after "/" or ":" is URL userinfo (postgres://user:password@host), not an image.
        image_literals = re.compile(r"(?<![/:\w])(?:ghcr\.io/baselabs/)?postgres(?:[:@](?!//)[A-Za-z0-9_.-]+)"
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
