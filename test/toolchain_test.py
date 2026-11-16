"""Exercise toolchain pairing and GitHub outputs against the checked-in pins."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("toolchain", ROOT / "scripts/toolchain.py")
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


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
            self.assertEqual(expected["matrix"], json.loads(values.pop("matrix")))
            self.assertEqual({key: value for key, value in expected.items() if key != "matrix"}, values)

    def test_workflows_read_pins_instead_of_copying_them(self):
        configuration = pins.toolchain((ROOT / ".tool-versions").read_text())
        versions = [configuration["node"]] + [
            value for lane in configuration["matrix"]["include"] for key, value in lane.items() if key != "lane"
        ]
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            source = path.read_text()
            if "erlef/setup-beam@" in source or "actions/setup-node@" in source:
                self.assertIn('scripts/toolchain.py --github-output "$GITHUB_OUTPUT"', source)
            for version in versions:
                self.assertNotIn(version, source, str(path))
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("fromJSON(needs.toolchain.outputs.matrix)", ci)
        self.assertIn("node-version: ${{ needs.toolchain.outputs.node }}", ci)


if __name__ == "__main__":
    unittest.main()
