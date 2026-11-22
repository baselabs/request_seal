"""The workflow policy's strict YAML subset fails closed before inspecting jobs."""
from pathlib import Path
import shlex
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
        # Another parser breaks lines at a lone CR, NEL, LS or PS; inside block content that
        # would end the block and expose `uses:` as a step key, so each is refused there too.
        for brk in ("\r", "\x85", "\u2028", "\u2029"):
            with self.subTest(line_break=repr(brk)):
                self.refused("jobs:\n  a:\n    steps:\n      - run: |\n          echo" + brk
                             + "      uses: other/action@v1\n", 5)
        self.assertEqual({"run": "a\n"}, load("run: |\r\n  a\r\n"))

    def test_folded_blocks_preserve_paragraphs_and_more_indented_lines(self):
        self.assertEqual({"run": "a b\nc\n  indented\nd\n"}, load(
            "run: >\n  a\n  b\n\n  c\n    indented\n  d\n\n"))
        self.assertEqual({"run": "a b"}, load("run: >-\n  a\n  b\n"))
        self.assertEqual({"run": "a\n\n  indented\n\nb\n"}, load(
            "run: >\n  a\n\n    indented\n\n  b\n"))
        self.assertEqual({"run": "\na\n\nb"}, load("run: >\n\n  a\n\n\n  b"))

    def test_all_real_workflows_load_with_known_values(self):
        sources = {name: load((ROOT / ".github/workflows" / name).read_text()) for name in
                   ("ci.yml", "cache-warmer.yml", "publish.yml")}
        self.assertEqual(["kci/**"], sources["ci.yml"]["on"]["push"]["branches"])
        self.assertEqual({"workflow_dispatch": ""}, sources["publish.yml"]["on"])
        verify = sources["ci.yml"]["jobs"]["verify"]
        self.assertEqual("verify (${{ matrix.lane }})", verify["name"])
        self.assertNotIn("services", verify)
        self.assertEqual("ubuntu-24.04", verify["runs-on"])


class PlatformPostgresTest(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / ".github/workflows/ci.yml").read_text()
        self.workflow = load(self.source)
        self.verify = self.workflow["jobs"]["verify"]
        self.steps = self.verify["steps"]

    def step(self, name):
        matches = [step for step in self.steps if step.get("name") == name]
        self.assertEqual(1, len(matches), name)
        return matches[0]

    def test_anonymous_current_digest_check_is_the_platform_step_verbatim(self):
        # The platform engine's public-repository form, with only the copy path changed.
        expected = r'''engine="$(cat .github/postgres.ref)"
[[ "$engine" =~ ^ghcr\.io/baselabs/postgres:[0-9]+\.[0-9]+-inputs-[0-9a-f]{64}@sha256:[0-9a-f]{64}$ ]]
current_digest="$(python3 - <<'PY'
import json, re, urllib.request
host, path = 'ghcr.io', 'baselabs/postgres'
with urllib.request.urlopen(f'https://{host}/token?scope=repository:{path}:pull', timeout=30) as response:
    token = json.load(response)['token']
request = urllib.request.Request(f'https://{host}/v2/{path}/manifests/current', method='HEAD', headers={
    'Authorization': 'Bearer ' + token,
    'Accept': ', '.join(('application/vnd.oci.image.index.v1+json', 'application/vnd.oci.image.manifest.v1+json',
                         'application/vnd.docker.distribution.manifest.list.v2+json',
                         'application/vnd.docker.distribution.manifest.v2+json'))})
with urllib.request.urlopen(request, timeout=30) as response:
    digest = response.headers.get('Docker-Content-Digest', '')
if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
    raise SystemExit('ghcr.io/baselabs/postgres:current: registry named no digest')
print(digest)
PY
)"
if [ "${engine##*@}" != "$current_digest" ]; then
  echo 'checked PostgreSQL digest differs from ghcr.io/baselabs/postgres:current' >&2; exit 1
fi
docker pull "$engine"
'''
        self.assertEqual({"name": "Check the public platform engine and pull its digest",
                          "shell": "bash", "run": expected},
                         self.step("Check the public platform engine and pull its digest"))

    def test_startup_uses_pulled_engine_disposable_scratch_and_tcp_readiness(self):
        check = self.step("Check the public platform engine and pull its digest")
        start = self.step("Start disposable PostgreSQL")
        self.assertNotIn("if", start)
        self.assertLess(self.steps.index(check), self.steps.index(start))
        script = start["run"]
        self.assertIn('engine="$(cat .github/postgres.ref)"\n', script)
        command = script[script.index("docker run"):script.index("\nready=false")]
        self.assertEqual([
            "docker", "run", "--detach", "--pull=never", "--name", "$REQUESTSEAL_TEST_PG_SERVER",
            "--publish", "127.0.0.1:$TEST_PG_PORT:5432", "--tmpfs", "/var/lib/pg:uid=26,gid=26,mode=0750",
            "--tmpfs", "/tmp", "--env", "TEST_PG_USER", "--env", "TEST_PG_PASSWORD",
            "--env", "TEST_PG_DATABASE", "--entrypoint", "baselabs-test-postgres", "$engine",
        ], shlex.split(command.replace("\\\n", "")))
        self.assertIn("for ((attempt=0; attempt<60; attempt++)); do\n", script)
        self.assertIn('docker exec "$REQUESTSEAL_TEST_PG_SERVER" pg_isready -h 127.0.0.1 '
                      '-U "$TEST_PG_USER" -d "$TEST_PG_DATABASE"', script)
        self.assertIn("    ready=true\n    break\n", script)
        self.assertIn("  sleep 1\n", script)
        self.assertIn('if [ "$ready" != true ]; then\n  docker logs "$REQUESTSEAL_TEST_PG_SERVER"\n', script)
        self.assertIn("  exit 1\nfi\n", script)
        consumers = [step for step in self.steps if step.get("run") in (
            "mix test --warnings-as-errors", "python3 scripts/check_optional_clients.py", "python3 scripts/check.py")]
        self.assertEqual(4, len(consumers))
        self.assertTrue(all(self.steps.index(start) < self.steps.index(step) for step in consumers))
        self.assertTrue(all("REQUESTSEAL_REPLAY_PG_URL" not in step.get("env", {}) for step in consumers))

    def test_fixture_password_and_contributor_url_are_workflow_environment_only(self):
        self.assertEqual({"run": {"shell": "bash"}}, self.workflow["defaults"])
        self.assertIn("# Throwaway fixture values, never credentials for an external service.", self.source)
        self.assertEqual({"TEST_PG_USER": "postgres", "TEST_PG_PASSWORD": "postgres",
                          "TEST_PG_DATABASE": "requestseal_test", "TEST_PG_PORT": "18841"}, self.workflow["env"])
        self.assertEqual("rs-${{ github.run_id }}-${{ github.run_attempt }}-${{ strategy.job-index }}",
                         self.verify["env"]["REQUESTSEAL_TEST_PG_SERVER"])
        env = self.workflow["env"]
        self.assertEqual(f"postgres://{env['TEST_PG_USER']}:{env['TEST_PG_PASSWORD']}"
                         f"@127.0.0.1:{env['TEST_PG_PORT']}/{env['TEST_PG_DATABASE']}",
                         self.verify["env"]["REQUESTSEAL_REPLAY_PG_URL"])
        # GitHub offers no env context in job-level env; such a workflow never starts.
        for name, job in self.workflow["jobs"].items():
            for key, value in (job.get("env") or {}).items():
                self.assertNotIn("${{ env.", str(value), f"{name}.env.{key}")
        for step in self.steps:
            self.assertNotIn("$TEST_PG_PASSWORD", step.get("run", ""))
            self.assertNotIn("REQUESTSEAL_REPLAY_PG_URL=", step.get("run", ""))

    def test_unconditional_log_then_removal_follows_every_consumer(self):
        stop = self.step("Remove disposable PostgreSQL")
        self.assertEqual("always()", stop["if"])
        self.assertEqual(self.steps[-1], stop)
        self.assertEqual('if docker container inspect "$REQUESTSEAL_TEST_PG_SERVER" > /dev/null 2>&1; then\n'
                         '  docker logs "$REQUESTSEAL_TEST_PG_SERVER"\n'
                         '  docker rm -f -v "$REQUESTSEAL_TEST_PG_SERVER"\nfi\n', stop["run"])
        self.assertFalse(any("failure()" in str(step.get("if", "")) for step in self.steps))

class ActionPolicyTest(unittest.TestCase):
    def workflow(self, steps):
        return "jobs:\n  verify:\n    steps:\n" + steps

    def test_every_step_use_is_checked_independently_of_required_actions(self):
        pinned = "owner/repo/path@" + "a" * 40
        self.assertEqual([], gate.ci_action_errors(self.workflow("      - uses: " + pinned + "\n"), set()))
        for action in ("other/action@v1", "./.github/workflows/sample.yml", "repo@" + "a" * 40,
                       "docker://image@" + "a" * 40, "owner/repo@" + "a" * 39, "owner/repo@" + "A" * 40):
            with self.subTest(action=action):
                self.assertTrue(gate.ci_action_errors(self.workflow(
                    "      - uses: " + pinned + "\n      - uses: " + action + "\n"), set()))

    def test_reusable_calls_are_local_and_never_escape_the_workflow_directory(self):
        for call in ("./.github/workflows/sample.yml", "./.github/workflows/a-b_1.yml"):
            self.assertEqual([], gate.ci_action_errors("jobs:\n  call:\n    uses: " + call + "\n", set()))
        for call in ("./.github/workflows/../sample.yml", "./.github/workflows/a..b.yml",
                     "./.github/workflows/sample.yaml", "owner/repo@" + "a" * 40):
            with self.subTest(call=call):
                self.assertTrue(gate.ci_action_errors("jobs:\n  call:\n    uses: " + call + "\n", set()))
        self.assertEqual([], gate.ci_action_errors("jobs:\n  call:\n    uses: ./.github/workflows/sample.yml\n",
                                                  {"./.github/workflows/sample.yml"}))

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
