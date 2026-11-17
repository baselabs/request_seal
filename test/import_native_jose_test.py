"""Native regeneration removes renamed cases and refreshes the closed inventory."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import processes


class ImportNativeJOSETest(unittest.TestCase):
    def test_renamed_vector_has_no_orphan_or_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "test/support").mkdir(parents=True)
            for name in ("import_native_jose.py", "import_ecdh_vectors.py", "corpus_json.py"):
                shutil.copy2(ROOT / "scripts" / name, root / "scripts" / name)
            shutil.copytree(ROOT / "corpus", root / "corpus")
            shutil.copy2(ROOT / ".gitleaks.toml", root / ".gitleaks.toml")
            command = [sys.executable, root / "scripts/import_native_jose.py"]
            processes.run(command, cwd=root, capture_output=True, text=True)
            baseline = (root / "corpus/index.json").read_bytes()
            original = root / "corpus/cases/jwe/native-r6-expected.json"
            renamed = original.with_name("native-renamed-vector.json")
            original.rename(renamed)
            # Refresh real inventory tooling after a rename, then regenerate.
            processes.run([sys.executable, "-B", "-c",
                           "import sys; sys.path.insert(0, 'scripts'); "
                           "from import_ecdh_vectors import refresh; refresh()"],
                          cwd=root, capture_output=True, text=True)
            config = root / ".gitleaks.toml"
            retained = "\n[[allowlists]]\ndescription = 'Retain this block'\npaths = ['unrelated']\n"
            config.write_text(config.read_text().replace("native-r6-expected", "native-renamed-vector") + retained)
            processes.run(command, cwd=root, capture_output=True, text=True)
            self.assertFalse(renamed.exists())
            self.assertTrue(original.exists())
            self.assertEqual((root / "corpus/index.json").read_bytes(), baseline)
            index = json.loads(baseline)
            self.assertFalse(any("native-renamed-vector" in row["path"] for row in index["files"]))
            self.assertNotIn("native-renamed-vector", config.read_text())
            self.assertIn(retained.strip(), config.read_text())
            pin = (root / "test/support/conformance_pin.ex").read_text()
            self.assertIn(hashlib.sha256(baseline).hexdigest(), pin)
            for sums in (root / "corpus").rglob("SHA256SUMS"):
                for line in sums.read_text().splitlines():
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256((sums.parent / name).read_bytes()).hexdigest(), digest)
            self.assertEqual(list(root.rglob("__pycache__")), [])
