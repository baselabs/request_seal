"""The workflow policy's strict YAML subset fails closed before inspecting jobs."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check as gate
from workflow_yaml import load


class WorkflowYamlTest(unittest.TestCase):
    def refused(self, source, line):
        with self.assertRaisesRegex(ValueError, rf"^<line {line}>: .+"):
            load(source)

    def test_quoted_complex_and_merge_keys_are_refused(self):
        for body in ("'uses': x", '"uses": x', "? uses\n: x", "<<: *defaults", "bad.key: x"):
            with self.subTest(body=body):
                self.refused("jobs:\n  " + body.replace("\n", "\n  ") + "\n", 2)
        for body in ("'uses': x", '"uses": x', "? uses", "<<: *defaults"):
            with self.subTest(item=body):
                self.refused("steps:\n  - " + body + "\n", 2)

    def test_flow_mappings_are_refused_in_every_value_position(self):
        for source in ("jobs: {verify: x}\n", "steps:\n  - {uses: x}\n",
                       "images: [{image: x}]\n", "run: x { y }\n", "run: x }\n",
                       "items: [[x]]\n"):
            with self.subTest(source=source):
                self.refused(source, 2 if source.startswith("steps:") else 1)

    def test_duplicate_keys_are_refused_in_each_mapping(self):
        for source, line in (("name: first\nname: second\n", 2),
                             ("jobs:\n  verify: x\n  verify: y\n", 3),
                             ("steps:\n  - uses: x\n    uses: y\n", 3)):
            with self.subTest(source=source):
                self.refused(source, line)

    def test_anchors_aliases_and_tags_are_refused(self):
        for token in ("&defaults", "*defaults", "!tag", "!!str"):
            for source in (f"name: {token} x\n", f"steps:\n  - {token}\n", f"items: [{token}]\n"):
                with self.subTest(source=source):
                    self.refused(source, 2 if source.startswith("steps:") else 1)

    def test_tabs_document_markers_and_unsupported_syntax_are_refused(self):
        for source, line in (
            ("name: ok\n\tjobs: x\n", 2), ("name: a\tb\n", 1), ("# comment\t\n", 1),
            ("---\nname: x\n", 1), ("name: x\n...\n", 2), ("name: x\n--- # next\n", 2),
            ("name:value\n", 1), ("name:# comment\n", 1), ("  name: x\n", 1),
            ("name: ok\n  continuation\n", 2), ("name: x: value\n", 1),
            ("name: |+\n  x\n", 1), ("name: >2\n  x\n", 1), ("name: |-2\n  x\n", 1),
            ("name: @reserved\n", 1), ("name: `reserved\n", 1), ("%YAML 1.2\n", 1),
            ("- scalar\n", 1), ("name: [unclosed\n", 1), ("name: [a,,b]\n", 1),
            ("name: 'unclosed\n", 1), ('name: "bad\\r"\n', 1), ('name: "bad\\u0020"\n', 1),
            ("name: 'x' extra\n", 1), ("name: [a] extra\n", 1), ("name: [a # comment]\n", 1),
            ("name: ${{ unclosed\n", 1), ("name: x\u2028y\n", 1),
            ("name: |\n    first\n   bad margin\n", 3),
        ):
            with self.subTest(source=source):
                self.refused(source, line)

    def test_comments_are_quote_aware(self):
        self.assertEqual({"name": "a # b", "run": "x", "single": "a # 'b", "adjacent": "x#y"}, load(
            '# full-line\nname: "a # b" # suffix\nrun: x # c\nsingle: \'a # \'\'b\' # tail\nadjacent: x#y\n'))

    def test_expressions_keep_braces_colons_quotes_and_hashes(self):
        expression = "${{ format('{0}: # {1}', 'it''s', matrix.lane) }}"
        self.assertEqual({"name": expression + "-suffix"}, load("name: " + expression + "-suffix # tail\n"))

    def test_scalar_types_quotes_empty_values_and_flow_sequences(self):
        self.assertEqual({"on": "true", "count": "123", "off": "null", "empty": "", "comment": "",
                          "single": "it's", "double": 'a\\b"c\n\t',
                          "items": ["a", "b # c", "d", "${{ format('{0}: {1}', 'x', 'y') }}"], "none": []}, load(
            'on: true\ncount: 123\noff: null\nempty:\ncomment: # empty\n'
            "single: 'it''s'\ndouble: \"a\\\\b\\\"c\\n\\t\"\n"
            "items: [a, 'b # c', \"d\", ${{ format('{0}: {1}', 'x', 'y') }}] # tail\nnone: []\n"))
        self.assertEqual({}, load("# empty document\n"))

    def test_nested_mappings_and_sequences(self):
        self.assertEqual({"jobs": {"verify": {"steps": [
            {"uses": "x", "with": {"key": "value"}}, {"run": "y"}], "needs": ["a", "b"]}}}, load(
            "jobs:\n  verify:\n    steps:\n      - uses: x\n        with:\n          key: value\n"
            "      - run: y\n    needs:\n      - a\n      - b\n"))

    def test_block_contents_are_literal_and_never_scanned_as_structure(self):
        content = "uses: x\n{ & * ! #\n'quoted': *anchor\n\tmore\n"
        source = "run: |\n" + "".join("  " + line + "\n" for line in content.splitlines()) + "name: next\n"
        self.assertEqual({"run": content, "name": "next"}, load(source))
        self.assertEqual({"run": "a\n\nb", "next": "x"}, load("run: |- # literal\n  a\n\n  b\n\nnext: x\n"))
        self.assertEqual({"run": "a"}, load("run: |\n  a"))
        self.assertEqual({"run": ""}, load("run: |\n\n"))

    def test_folded_blocks_preserve_paragraphs_and_more_indented_lines(self):
        self.assertEqual({"run": "a b\nc\n  indented\nd\n"}, load(
            "run: >\n  a\n  b\n\n  c\n    indented\n  d\n\n"))
        self.assertEqual({"run": "a b"}, load("run: >-\n  a\n  b\n"))
        self.assertEqual({"run": "a\n\n  indented\n\nb\n"}, load(
            "run: >\n  a\n\n    indented\n\n  b\n"))
        self.assertEqual({"run": "\na\n\nb"}, load("run: >\n\n  a\n\n\n  b"))

    def test_all_real_workflows_load_with_known_values(self):
        sources = {name: load((ROOT / ".github/workflows" / name).read_text()) for name in
                   ("ci.yml", "contributions.yml", "proofs.yml", "release.yml")}
        self.assertEqual(["kci/**"], sources["ci.yml"]["on"]["push"]["branches"])
        self.assertEqual({"pull_request": ""}, sources["contributions.yml"]["on"])
        verify = sources["proofs.yml"]["jobs"]["verify"]
        self.assertEqual("verify (${{ matrix.lane }})", verify["name"])
        self.assertEqual(["5432/tcp"], verify["services"]["postgres"]["ports"])
        self.assertEqual("--health-cmd \"pg_isready -U postgres\" --health-interval 5s --health-timeout 5s --health-retries 20",
                         verify["services"]["postgres"]["options"])
        self.assertEqual(["v*"], sources["release.yml"]["on"]["push"]["tags"])
        self.assertIn('gh release create "$GITHUB_REF_NAME"', sources["release.yml"]["jobs"]["publish"]["steps"][-1]["run"])


class ActionPolicyTest(unittest.TestCase):
    def workflow(self, steps):
        return "jobs:\n  verify:\n    steps:\n" + steps

    def test_every_step_use_is_checked_independently_of_required_actions(self):
        pinned = "owner/repo/path@" + "a" * 40
        self.assertEqual([], gate.ci_action_errors(self.workflow("      - uses: " + pinned + "\n"), set()))
        for action in ("other/action@v1", "./.github/workflows/proofs.yml", "repo@" + "a" * 40,
                       "docker://image@" + "a" * 40, "owner/repo@" + "a" * 39):
            with self.subTest(action=action):
                self.assertTrue(gate.ci_action_errors(self.workflow(
                    "      - uses: " + pinned + "\n      - uses: " + action + "\n"), set()))

    def test_reusable_calls_are_local_and_never_escape_the_workflow_directory(self):
        for call in ("./.github/workflows/proofs.yml", "./.github/workflows/a-b_1.yml"):
            self.assertEqual([], gate.ci_action_errors("jobs:\n  call:\n    uses: " + call + "\n", set()))
        for call in ("./.github/workflows/../proofs.yml", "./.github/workflows/a..b.yml",
                     "./.github/workflows/proofs.yaml", "owner/repo@" + "a" * 40):
            with self.subTest(call=call):
                self.assertTrue(gate.ci_action_errors("jobs:\n  call:\n    uses: " + call + "\n", set()))
        self.assertEqual([], gate.ci_action_errors("jobs:\n  call:\n    uses: ./.github/workflows/proofs.yml\n",
                                                  {"./.github/workflows/proofs.yml"}))

    def test_syntax_bypasses_produce_line_numbered_errors(self):
        for steps in ("      - 'uses': other/action@v1\n", "      - {uses: other/action@v1}\n",
                      "      - &step\n        uses: other/action@v1\n      - *step\n",
                      "      - *step\n", "      - <<: *step\n"):
            with self.subTest(steps=steps):
                errors = gate.ci_action_errors(self.workflow(steps), set())
                self.assertTrue(errors)
                self.assertIn("CI workflow YAML: <line 4>:", errors[0])

    def test_comments_and_block_content_are_not_action_references(self):
        self.assertEqual([], gate.ci_action_errors(self.workflow(
            "      # - uses: other/action@v1\n      - uses: owner/repo@" + "a" * 40 + " # pinned\n"
            "      - run: |\n          uses: other/action@v1\n          { & * ! #\n"), {"owner/repo"}))


if __name__ == "__main__":
    unittest.main()
