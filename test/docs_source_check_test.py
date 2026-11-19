"""The local documentation path checks source only and never invokes Mix."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('docs_source', ROOT / 'scripts/check_docs.py')
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)


class DocsSourceCheckTest(unittest.TestCase):
    def test_real_source_inventory_disclosure_and_fence_pairs(self):
        approved, errors = docs.check_source(ROOT)
        self.assertIn('README.md', approved)
        self.assertEqual([], errors)

    def test_literal_source_configuration_refuses_dynamic_and_duplicate_documents(self):
        original = (ROOT / 'mix.exs').read_text()
        with tempfile.TemporaryDirectory(prefix='.docs-source-', dir=ROOT) as directory:
            root = Path(directory)
            (root / 'lib').mkdir()
            for changed, diagnostic in [
                (original.replace('"README.md",', '"README.md", "README.md",', 1), 'duplicate'),
                (original.replace('"README.md",', 'System.get_env("DOC"),', 1), 'literal paths'),
                (original.replace('files: ["lib/**/*.ex", "mix.exs" | @public_documents]',
                                  'files: ["docs"]'), 'explicit package'),
            ]:
                self.assertNotEqual(original, changed)
                (root / 'mix.exs').write_text(changed)
                with self.assertRaisesRegex(ValueError, diagnostic):
                    docs.source_configuration(root)

    def test_a_new_unexecuted_guide_fence_is_rejected(self):
        guide = 'docs/guides/web-bot-auth.md'
        original = (ROOT / guide).read_text()
        self.assertEqual([], docs.fence_errors(ROOT, guide, original))
        self.assertTrue(docs.fence_errors(ROOT, guide, original + '\n```elixir\n:unchecked\n```\n'))


if __name__ == '__main__':
    unittest.main()
