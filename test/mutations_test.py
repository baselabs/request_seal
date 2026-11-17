"""Reject stale, missing, or ambiguous JWE mutation proofs."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import processes


class MutationsTest(unittest.TestCase):
    def test_manifest_and_patches_agree_and_apply(self):
        directory = ROOT / "test/mutations/jwe_open"
        entries = json.loads((directory / "manifest.json").read_text())["mutations"]
        names = [entry["patch"] for entry in entries]
        self.assertTrue(names)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {path.name for path in directory.glob("*.patch")})
        for entry in entries:
            with self.subTest(patch=entry["patch"]):
                self.assertTrue(entry["failure"].strip())
                self.assertNotIn("/", entry["patch"])
                test_file = ROOT / entry["file"]
                self.assertIn('test "' + entry["test"] + '"', test_file.read_text())
                self.assertRegex(entry["selection"], r"^line:\d+$")
                line = int(entry["selection"].split(":")[1])
                self.assertIn('test "' + entry["test"] + '"', test_file.read_text().splitlines()[line - 1])
                result = processes.run(["git", "apply", "--check", directory / entry["patch"]],
                    cwd=ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    processes.install_signal_handlers()
    unittest.main()
