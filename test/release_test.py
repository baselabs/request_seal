"""Release safety checks against real Git repositories and artifact metadata."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import check as gate
import check_docs as docs


class ReleaseIdentityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release-test@example.invalid")
        (self.root / "corpus").mkdir()
        self.identity("2.3.4")
        self.git("add", "mix.exs", "corpus/index.json")
        self.git("commit", "--quiet", "-m", "Release identity fixture")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True)

    def identity(self, version):
        (self.root / "mix.exs").write_text(f'@version "{version}"\nversion: @version,\n')
        (self.root / "corpus/index.json").write_text(json.dumps({"elixir_release": "v" + version}))

    def verify(self, event="workflow_dispatch", ref="refs/heads/main"):
        return release.verify_identity(self.root, event, ref)

    def test_dispatch_before_tag_and_tag_push_support_annotated_tags(self):
        self.assertEqual("2.3.4", self.verify())
        self.git("tag", "-a", "v2.3.4", "-m", "Release fixture")
        self.assertEqual("2.3.4", self.verify())
        self.assertEqual("2.3.4", self.verify("push", "refs/tags/v2.3.4"))

    def test_lightweight_tag_identity(self):
        self.git("tag", "v2.3.4")
        self.assertEqual("2.3.4", self.verify("push", "refs/tags/v2.3.4"))

    def test_tag_at_another_commit_refuses_dispatch_and_push(self):
        self.git("tag", "v2.3.4")
        self.git("commit", "--quiet", "--allow-empty", "-m", "Another commit")
        for event, ref in (("workflow_dispatch", "refs/heads/release"), ("push", "refs/tags/v2.3.4")):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, "checked-out commit"):
                self.verify(event, ref)

    def test_push_requires_the_matching_existing_tag(self):
        for ref in ("refs/tags/v2.3.5", "refs/heads/v2.3.4", "refs/tags/v2.3.4"):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "release tag"):
                self.verify("push", ref)

    def test_every_prerelease_is_refused(self):
        for version in ("2.3.4-dev", "2.3.4-dev.2", "2.3.4-rc.1", "2.3.4-0"):
            self.identity(version)
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "pre-release"):
                self.verify()

    def test_stale_corpus_and_unexpected_event_are_refused(self):
        (self.root / "corpus/index.json").write_text('{"elixir_release":"v2.3.3"}')
        with self.assertRaisesRegex(ValueError, "elixir_release"):
            self.verify()
        self.identity("2.3.4")
        with self.assertRaisesRegex(ValueError, "workflow_dispatch"):
            self.verify("pull_request")

    def test_version_requires_one_semantic_attribute_and_no_inline_literal(self):
        for source in ('version: "2.3.4"', '@version "2.3.4"\n@version "2.3.5"\nversion: @version', '@version "2.3"\nversion: @version'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                release.package_version(source)
        for version in ("02.3.4", "2.03.4", "2.3.04", "2.3.4-01", "2.3.4-", "v2.3.4"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.parse_version(version)

    def test_install_and_corpus_identity_support_development_snapshots(self):
        for version, expected in (("0.7.4-dev", "~> 0.7.4"), ("2.3.4-dev", "~> 2.3"), ("3.2.1", "~> 3.2")):
            self.assertEqual(expected, release.install_requirement(version))
            self.identity(version)
            sources = {path: (self.root / path).read_text() for path in ("mix.exs", "corpus/index.json")}
            self.assertEqual([], gate.corpus_release_errors(sources))

    def test_dynamic_runbook_install_requires_the_shared_derivation(self):
        source = ('export REQUIREMENT=$(python3 scripts/release.py --install-requirement)\n'
                  'Mix.install([{:request_seal, System.fetch_env!("REQUIREMENT")}])')
        self.assertEqual([], docs.release_errors("docs/operations/releases.md", source, "2.0.0-dev"))
        self.assertTrue(docs.release_errors("README.md", source, "2.0.0-dev"))
        self.assertTrue(docs.release_errors("docs/operations/releases.md", source.split("\n", 1)[1], "2.0.0-dev"))

    def test_changelog_preserves_released_installs_but_checks_unreleased_installs(self):
        history = '\n## 1.2.3\n{:request_seal, "~> 1.2"}\n'
        current = '# Changelog\n\n## Unreleased 2.0.0\n{:request_seal, "~> 2.0"}\n'
        self.assertEqual([], docs.release_errors("CHANGELOG.md", current + history, "2.0.0-dev"))
        self.assertTrue(docs.release_errors("CHANGELOG.md", current.replace("~> 2.0", "~> 1.2") + history, "2.0.0-dev"))


class ReleaseWorkflowTest(unittest.TestCase):
    def test_release_actions_use_immutable_commits(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        required = {"actions/checkout", "erlef/setup-beam", "actions/setup-python",
                    "actions/upload-artifact", "actions/download-artifact", "actions/attest"}
        self.assertEqual([], gate.ci_action_errors(workflow, required))
        for action in required:
            import re
            changed = re.sub(re.escape(action) + r"@[0-9a-f]{40}", action + "@v4", workflow)
            with self.subTest(action=action):
                self.assertTrue(gate.ci_action_errors(changed, required))

    def test_write_permissions_and_attestations_are_confined_to_tag_job(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        verify, publish = workflow.split("\n  publish:\n")
        self.assertIn("workflow_dispatch:\n", verify)
        self.assertNotIn("inputs:", verify)
        self.assertNotIn(": write", verify)
        self.assertNotIn("uses: actions/attest@", verify)
        self.assertIn("if: github.event_name == 'push'", publish)
        self.assertIn("needs: verify", publish)
        for permission in ("contents", "id-token", "attestations", "artifact-metadata"):
            self.assertIn(permission + ": write", publish)
        self.assertIn("sbom-path: sbom.cdx.json", publish)

    def test_sbom_normalization_removes_only_volatile_fields_and_sorts_graph(self):
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
               "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"name": "request_seal"}},
               "components": [{"bom-ref": "z", "name": "telemetry"}, {"bom-ref": "a", "name": "plug"}],
               "dependencies": [{"ref": "z", "dependsOn": ["z", "a"]}, {"ref": "a"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.cdx.json"
            path.write_text(json.dumps(bom))
            release.normalize_sbom(path)
            first = path.read_bytes()
            normalized = json.loads(first)
            self.assertNotIn("serialNumber", normalized)
            self.assertNotIn("timestamp", normalized["metadata"])
            self.assertEqual(bom["metadata"]["component"], normalized["metadata"]["component"])
            self.assertEqual(["a", "z"], [c["bom-ref"] for c in normalized["components"]])
            release.normalize_sbom(path)
            self.assertEqual(first, path.read_bytes())
            path.write_text(json.dumps({**bom, "specVersion": "1.5"}))
            with self.assertRaisesRegex(ValueError, "CycloneDX 1.6"):
                release.normalize_sbom(path)


if __name__ == "__main__":
    unittest.main()
