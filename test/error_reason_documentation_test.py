"""Source-only error vocabulary guards and their non-vacuous rejection tests."""
from pathlib import Path
import importlib.util
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('error_reasons', ROOT / 'scripts/check_error_reasons.py')
reasons = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reasons)


class ErrorReasonDocumentationTest(unittest.TestCase):
    def test_all_source_vocabularies_match_types_and_guide(self):
        errors, emitted = reasons.check(ROOT)
        self.assertEqual([], errors)
        self.assertEqual(set(reasons.KINDS), set(emitted))
        self.assertTrue(all(emitted.values()))

    def test_custody_sign_and_verify_document_assignment_and_input_errors(self):
        custody = (ROOT / 'lib/request_seal/custody.ex').read_text()
        shared = {'issued_for_mismatch', 'key_mismatch', 'unsupported_operation', 'invalid_data'}
        admissions = {'gate_malformed_base', 'gate_coverage', 'gate_window', 'gate_denied',
                      'gate_unavailable', 'gate_mismatch', 'gate_spent', 'gate_store_failed',
                      'gate_unrecorded'}
        for headline, required in [
            ('Sign exact bounded bytes', shared | admissions),
            ('Verify exact bytes', shared | {'no_public_key'}),
        ]:
            with self.subTest(headline=headline):
                function_doc = custody.split(headline, 1)[1].split('"""', 1)[0]
                returns = function_doc.split('## Returns', 1)[1].split('## Examples', 1)[0]
                for reason in required:
                    self.assertIn(f'`:{reason}`', returns)

    def test_literals_helper_arguments_and_throws_are_emissions_but_docs_are_not(self):
        source = '''
        defmodule Example do
          @moduledoc """reason: :not_emitted"""
          @doc """fail(:not_emitted_either)"""
          def run(value) do
            ensure(value, :from_ensure)
            fail(:from_fail)
            throw({:signature_base, :from_throw})
            {:error, %Error{reason: :from_struct}}
          end
        end
        '''
        self.assertEqual({'signature_base': {'from_ensure', 'from_fail', 'from_throw', 'from_struct'}},
                         dict(reasons.source_reasons(source, 'signature_base')))

    def test_foreign_struct_reasons_do_not_enter_the_library_vocabulary(self):
        emitted = reasons.source_reasons('def run(), do: %DBConnection.ConnectionError{reason: :queue_timeout}',
                                         'replay')
        self.assertFalse(any(emitted.values()))

    def test_scope_reject_and_gate_callback_track_literal_and_unknown_flows(self):
        for path, kind, source in [
            ("lib/request_seal/plug/scope.ex", "adapter",
             "reject(:literal)\nreject(selected)"),
            ("lib/request_seal/custody/gate.ex", "custody",
             "callback(context, fn -> port.() end, :literal)\ncallback(context, clock, selected)"),
        ]:
            with self.subTest(path=path):
                flows = []
                self.assertEqual({kind: {"literal"}},
                                 dict(reasons.source_reasons(source, kind, path, flows)))
                self.assertEqual([{"file": path, "line": 2, "expression": "selected", "kind": kind}],
                                 flows)

    def test_new_reason_removed_emission_duplicate_type_stale_docs_and_unlisted_flow_fail(self):
        with tempfile.TemporaryDirectory(prefix='.reason-check-', dir=ROOT) as directory:
            root = Path(directory)
            shutil.copytree(ROOT / 'lib', root / 'lib')
            (root / 'docs/guides').mkdir(parents=True)
            shutil.copyfile(ROOT / 'docs/guides/errors.md', root / 'docs/guides/errors.md')
            (root / 'test/fixtures').mkdir(parents=True)
            shutil.copyfile(ROOT / 'test/fixtures/error_reason_flows.json',
                            root / 'test/fixtures/error_reason_flows.json')
            source = root / 'lib/request_seal/digest.ex'
            original = source.read_text()
            mutations = [
                (source, original.replace('ensure(total <= state.max_bytes, :limit)',
                                          'ensure(total <= state.max_bytes, :new_reason)', 1),
                 'emitted :new_reason missing from type'),
                (source, original.replace('ensure(:crypto.hash_equals(bytes, expected_bytes), :mismatch)',
                                          'ensure(:crypto.hash_equals(bytes, expected_bytes), :limit)'),
                 'type documents unemitted :mismatch'),
                (source, original.replace('ensure(total <= state.max_bytes, :limit)',
                                          'ensure(total <= state.max_bytes, selected_reason)', 1),
                 'Unlisted variable reason flow'),
            ]
            type_path = root / 'lib/request_seal/digest/error.ex'
            mutations.append((type_path, type_path.read_text().replace('| :mismatch', '| :mismatch | :mismatch'),
                              'type repeats :mismatch'))
            guide = root / 'docs/guides/errors.md'
            mutations.append((guide, guide.read_text().replace('### RequestSeal.Digest.Error\n',
                                                               '### RequestSeal.Digest.Error\n\n`:not_emitted`\n'),
                              'guide documents unemitted :not_emitted'))
            for path, changed, diagnostic in mutations:
                before = path.read_text()
                self.assertNotEqual(before, changed)
                try:
                    path.write_text(changed)
                    errors, _ = reasons.check(root)
                    self.assertTrue(any(diagnostic in error for error in errors), errors)
                finally:
                    path.write_text(before)


if __name__ == '__main__':
    unittest.main()
