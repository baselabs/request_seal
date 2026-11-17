"""Disclosure checks against actual repository content and real filesystem/Git inputs."""
from pathlib import Path
import importlib.util
import re
import subprocess
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("check_docs", ROOT / "scripts/check_docs.py")
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)
gate_spec = importlib.util.spec_from_file_location("check_gate", ROOT / "scripts/check.py")
gate = importlib.util.module_from_spec(gate_spec)
gate_spec.loader.exec_module(gate)


class PublicDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "README.md").read_text()
        cls.paths = docs.public_paths(ROOT)

    def errors(self, mutation=""):
        return docs.content_errors(ROOT, "README.md", self.source + mutation, self.paths)

    def test_corpus_provenance_is_source_documentation_only(self):
        path = "corpus/sources/rfc9421/PROVENANCE.md"
        self.assertIn(path, docs.SOURCE_DOCUMENTS)
        configuration = docs.public_configuration(ROOT)
        self.assertNotIn(path, configuration["documents"])
        self.assertNotIn(path, configuration["files"])
        text = (ROOT / path).read_text()
        self.assertEqual([], docs.content_errors(ROOT, path, text, self.paths))
        self.assertTrue(docs.content_errors(ROOT, path, text + "\nfile:///home/person/key", self.paths))

    def test_decision_records_are_source_documentation_only(self):
        configuration = docs.public_configuration(ROOT)
        records = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "docs/adr").glob("*.md"))
        for path in records:
            self.assertIn(path, docs.SOURCE_DOCUMENTS)
            self.assertNotIn(path, configuration["documents"])
            self.assertNotIn(path, configuration["files"])
            text = (ROOT / path).read_text()
            self.assertEqual([], docs.content_errors(ROOT, path, text, self.paths), path)

    def test_current_readme_is_public(self):
        self.assertEqual([], self.errors())

    def test_consumer_verification_guide_ships_and_maintainer_runbook_stays_source_only(self):
        guide = "docs/guides/verifying-releases.md"
        runbook = "docs/operations/releases.md"
        configuration = docs.public_configuration(ROOT)
        self.assertIn(runbook, docs.SOURCE_DOCUMENTS)
        self.assertNotIn(guide, docs.SOURCE_DOCUMENTS)
        for inventory in ("documents", "files"):
            self.assertIn(guide, configuration[inventory])
            self.assertNotIn(runbook, configuration[inventory])
        source = (ROOT / guide).read_text()
        for command in ("sha256sum --check corpus.sha256", "gh attestation verify",
                        "--predicate-type https://slsa.dev/provenance/v1",
                        "--predicate-type https://cyclonedx.org/bom",
                        'mix hex.package fetch request_seal "$VERSION"', 'cmp "$assets_dir/request_seal-$VERSION.tar"'):
            self.assertIn(command, source)
        commands = [line.strip() for line in source.replace("\\\n", " ").splitlines()
                    if line.strip().startswith("gh attestation verify ")]
        self.assertEqual(2, len(commands))
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("--signer-workflow baselabs/request_seal/.github/workflows/release.yml", command)
                self.assertIn('--source-ref "refs/tags/v$VERSION"', command)
                self.assertIn("--deny-self-hosted-runners", command)
        self.assertNotIn("HEX_API_KEY", source)
        self.assertNotIn("gh attestation verify", (ROOT / runbook).read_text())
        self.assertIn("../guides/verifying-releases.md", (ROOT / runbook).read_text())
        self.assertIn("(docs/guides/verifying-releases.md)", (ROOT / "CHANGELOG.md").read_text())

    def test_git_installs_are_rejected_in_public_text(self):
        for install in (
            '{:request_seal, git: "https://github.com/baselabs/request_seal.git"}',
            '{:request_seal,\n git: "git@github.com:baselabs/request_seal.git"}',
            '{:request_seal, github: "baselabs/request_seal"}',
            'github: "request_seal"',
            'github: :request_seal',
        ):
            with self.subTest(install=install):
                self.assertTrue(any("Hex install" in e for e in self.errors("\n" + install)))

    def test_unpublished_repository_wording_is_rejected(self):
        for wording in (
            "The repository is private until the first Hex release.",
            "The repository is currently private.",
            "Access to the private repository is required.",
            "RequestSeal is not yet published on Hex.",
            "RequestSeal is not published on Hex yet.",
            "A Hex release is coming.",
            "The Git dependency requires access.",
        ):
            with self.subTest(wording=wording):
                self.assertTrue(any("release wording" in e for e in self.errors("\n" + wording)))

    def test_install_requirement_tracks_the_package_version(self):
        for version in ("0.1.0", "0.2.3"):
            install = '{:request_seal, "~> ' + version + '"}'
            self.assertEqual([], docs.release_errors("README.md", install, version))
            for requirement in ("~> 0.1", "~> 0.1.0-dev", "== " + version, "~> 0.9.9"):
                with self.subTest(version=version, requirement=requirement):
                    source = install.replace("~> " + version, requirement)
                    self.assertTrue(any("install requirement" in e for e in docs.release_errors("README.md", source, version)))
        for version, documented in (("1.2.3", "~> 1.2"), ("2.0.1", "~> 2.0"), ("2.0.0-dev", "~> 2.0")):
            install = '{:request_seal, "' + documented + '"}'
            self.assertEqual([], docs.release_errors("README.md", install, version))
            for requirement in ("~> " + version, "~> 1", "== " + version, ">= " + version):
                with self.subTest(version=version, requirement=requirement):
                    source = install.replace(documented, requirement)
                    self.assertTrue(any("install requirement" in e for e in docs.release_errors("README.md", source, version)))
        for source in ('{:request_seal, path: "../request_seal"}', '{:request_seal, github: "baselabs/request_seal"}'):
            self.assertTrue(docs.release_errors("livebooks/environment.livemd", source, "0.1.0"))

    def test_release_checks_keep_public_links_and_key_custody_text(self):
        source = '\n'.join((
            'source_url: "https://github.com/baselabs/request_seal"',
            'Keep private keys in caller-owned custody.',
            'Verify the private security-reporting channel.',
            '{:request_seal,\n "~> 0.1.0", optional: true}',
            '{:other_package, git: "https://github.com/example/other.git"}',
        ))
        self.assertEqual([], docs.release_errors("mix.exs", source, "0.1.0"))

    def test_actual_package_configuration_and_file_mutations(self):
        configuration = docs.public_configuration(ROOT)
        self.assertRegex(configuration["version"], r"^\d+\.\d+\.\d+(?:-[\w.-]+)?$")
        self.assertEqual([], docs.package_errors(ROOT, configuration))
        for path in ("test/fixtures/web_bot_auth/PROVENANCE.md", ".env", ".kimosabe/release-files.txt", "scripts/check.py"):
            with self.subTest(path=path):
                changed = dict(configuration)
                changed["files"] = configuration["files"] | {path}
                changed["patterns"] = configuration["patterns"] + [path]
                self.assertTrue(docs.package_errors(ROOT, changed))
        changed = dict(configuration)
        changed["files"] = configuration["files"] - {"lib/request_seal.ex"}
        self.assertTrue(any("required package file" in e for e in docs.package_errors(ROOT, changed)))
        changed = dict(configuration)
        path = "test/fixtures/web_bot_auth/PROVENANCE.md"
        changed["documents"] = configuration["documents"] | {path}
        changed["files"] = configuration["files"] | {path}
        changed["patterns"] = configuration["patterns"] + [path]
        self.assertTrue(any("outside the package allowlist" in e for e in docs.package_errors(ROOT, changed)))

    def test_package_source_is_checked_for_install_references(self):
        source = (ROOT / "lib/request_seal.ex").read_text()
        self.assertEqual([], docs.release_errors("lib/request_seal.ex", source, "0.1.0"))
        for mutation in ('{:request_seal, "~> 0.0.1"}', 'github: "baselabs/request_seal"', 'RequestSeal is not yet published.'):
            self.assertTrue(docs.release_errors("lib/request_seal.ex", source + "\n" + mutation, "0.1.0"))


    def test_private_inline_target(self):
        self.assertTrue(any("private" in e for e in self.errors("\n[notes](.private/record.md)\n")))

    def test_encoded_private_target(self):
        self.assertTrue(any("private" in e for e in self.errors("\n[notes](%2eprivate/record.md)\n")))

    def test_reference_and_html_targets(self):
        for mutation in ('\n[notes]: .private/record.md\n', '\n<a href=".private/record.md">notes</a>\n', '\n<a href=.private/record.md>notes</a>\n', '\n<img src=.private/image.png>\n'):
            with self.subTest(mutation=mutation):
                self.assertTrue(any("private" in e for e in self.errors(mutation)))

    def test_machine_path_and_internal_process(self):
        self.assertTrue(any("machine" in e for e in self.errors("\n/home/example/private\n")))
        self.assertTrue(any("internal process" in e for e in self.errors("\nInternal review authorization granted.\n")))

    def test_fenced_unclosed_html_cannot_hide_later_links(self):
        for prefix in ("\n```html\n<script>\n```\n", "\n```html\n<!--\n```\n"):
            with self.subTest(prefix=prefix):
                mutation = prefix + '\n<a href=".private/record.md">notes</a>\n'
                self.assertTrue(any("private" in e for e in self.errors(mutation)))

    def test_html_entity_private_target(self):
        self.assertTrue(any("private" in e for e in self.errors('\n<a href="&#46;private/record.md">notes</a>\n')))


    def test_fences_require_exact_executed_copies_in_their_own_test(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test/guides").mkdir(parents=True)
            source = '```elixir\nvalue = 1\ntrue = value > 0\n```\n'
            example_code = 'value = 1\ntrue = value > 0\n'
            for document, test in (("README.md", "test/readme_test.exs"), ("docs/guides/example.md", "test/guides/example_test.exs")):
                with self.subTest(document=document):
                    self.assertTrue(docs.fence_errors(root, document, source))
                    example = EvaluatedFenceTest().paired(example_code, document)
                    (root / test).write_text(example)
                    self.assertEqual([], docs.fence_errors(root, document, source))
                    self.assertTrue(docs.fence_errors(root, document, source.replace("value = 1", "value = 2")))
                    (root / test).write_text(example.replace("value = 1", "value = 2"))
                    self.assertTrue(docs.fence_errors(root, document, source))

    def test_fence_extraction_preserves_bytes_and_ignores_other_languages(self):
        self.assertEqual(["x = 1\n\n"], docs.elixir_fences('```sh\nx = 2\n```\n```elixir\nx = 1\n\n```\n'))
        self.assertEqual(["x = 1\n"], docs.elixir_fences('~~~elixir\nx = 1\n~~~\n'))
        self.assertEqual(["  x = 1\n"], docs.elixir_fences('  ```elixir\n  x = 1\n  ```\n'))
        self.assertEqual([], docs.elixir_fences('````text\n```elixir\nx = 1\n```\n````\n'))
        with self.assertRaisesRegex(ValueError, "unclosed"):
            docs.elixir_fences('```elixir\nx = 1\n')

    def test_copy_comparison_preserves_line_endings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test").mkdir()
            (root / "test/readme_test.exs").write_bytes(b"value = 1\n")
            self.assertTrue(docs.fence_errors(root, "README.md", "```elixir\r\nvalue = 1\r\n```\r\n"))
            (root / "test/readme_test.exs").write_bytes(b"value = 1\r\n")
            self.assertTrue(docs.fence_errors(root, "README.md", "```elixir\nvalue = 1\n```\n"))

    def test_unapproved_file_and_symlink_use_real_git_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
            (root / "README.md").write_text(self.source)
            (root / "Notes.md").write_text(self.source)
            approved = {"README.md"}
            errors = docs.inventory_errors(root, approved, docs.public_paths(root))
            self.assertEqual(["Notes.md: document is not approved for publication"], errors)
            (root / "Notes.md").unlink()
            (root / ".private").mkdir()
            (root / ".private/record.md").write_text(self.source)
            (root / "README.md").unlink()
            (root / "README.md").symlink_to(root / ".private/record.md")
            errors = docs.inventory_errors(root, approved, docs.public_paths(root))
            self.assertTrue(any("symlink" in e for e in errors))

    def test_removed_unapproved_document_does_not_publish_but_required_one_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(self.source)
            removed = root / "Removed.md"
            removed.write_text(self.source)
            paths = {"README.md", "Removed.md"}
            self.assertEqual(
                ["Removed.md: document is not approved for publication"],
                docs.inventory_errors(root, {"README.md"}, paths),
            )
            removed.unlink()
            self.assertEqual([], docs.inventory_errors(root, {"README.md"}, paths))
            self.assertEqual(
                ["Removed.md: approved document is missing from public source"],
                docs.inventory_errors(root, paths, paths),
            )

    def test_unsafe_approved_path_is_rejected(self):
        for relative in (".private/record.md", "docs/../README.md", "/README.md"):
            with self.subTest(relative=relative):
                errors = docs.inventory_errors(ROOT, {"README.md", relative}, self.paths)
                self.assertTrue(any("unsafe path" in e for e in errors))

    def test_symlink_alias_is_not_a_public_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(self.source)
            (root / "alias.md").symlink_to(root / "README.md")
            errors = docs.content_errors(root, "README.md", self.source + "\n[alias](alias.md)\n", {"README.md"})
            self.assertTrue(any("unpublished content" in e for e in errors))
            errors = docs.content_errors(root, "README.md", self.source + "\n[alias](alias.md)\n", {"README.md", "alias.md"})
            self.assertTrue(any("symlink" in e for e in errors))

    def test_published_document_cannot_link_a_repository_only_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(self.source)
            (root / "runbook.md").write_text("# Runbook\n")
            linked = self.source + "\n[runbook](runbook.md)\n"
            tracked = {"README.md", "runbook.md"}
            errors = docs.content_errors(root, "README.md", linked, tracked, published={"README.md"})
            self.assertTrue(any("repository-only document" in e for e in errors))
            self.assertEqual([], [e for e in docs.content_errors(root, "README.md", linked, tracked,
                                                                 published={"README.md", "runbook.md"})
                                  if "repository-only" in e])

    def test_exdoc_inventory_uses_relative_actual_files(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            (output / "readme.html").write_text(self.source)
            inventory = output / ".build"
            inventory.write_text(str(output / "readme.html") + "\n")
            gate.normalize_exdoc_inventory(output)
            self.assertEqual("readme.html\n", inventory.read_text())

    def test_epub_inventory_accepts_project_relative_actual_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            (output / "readme.html").write_text(self.source)
            inventory = output / ".build.epub"
            import os
            inventory.write_text(os.path.relpath(output / "readme.html", ROOT) + "\n")
            gate.normalize_exdoc_inventory(output)
            self.assertEqual("readme.html\n", inventory.read_text())

    def test_exdoc_inventory_rejects_outside_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            inventory = output / ".build"
            inventory.write_text(str(ROOT / "README.md") + "\n")
            with self.assertRaises(ValueError):
                gate.normalize_exdoc_inventory(output)

    def test_unapproved_library_text_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
            (root / "README.md").write_text(self.source)
            (root / "lib").mkdir()
            (root / "lib/internal-plan.txt").write_text(self.source)
            errors = docs.inventory_errors(root, {"README.md"}, docs.public_paths(root))
            self.assertEqual(["lib/internal-plan.txt: document is not approved for publication"], errors)

    def test_epub_inventory_uses_the_explicit_project_root(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            output = project / "doc"
            output.mkdir()
            (output / "readme.html").write_text(self.source)
            inventory = output / ".build.epub"
            inventory.write_text("doc/readme.html\n")
            gate.normalize_exdoc_inventory(output, project_root=project)
            self.assertEqual("readme.html\n", inventory.read_text())

    def test_empty_inventory_is_rejected(self):
        self.assertEqual(["public documentation inventory must include README.md"], docs.inventory_errors(ROOT, set(), self.paths))


class NotebookProcessTest(unittest.TestCase):
    def execute(self, source, **options):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "notebook.exs"
            script.write_text(source)
            return gate.execute_notebook(script, "COMPLETED_TEST", **options)

    def test_actual_child_completes_and_rejects_early_success(self):
        self.assertIn("COMPLETED_TEST", self.execute('IO.puts("COMPLETED_TEST")')[0])
        with self.assertRaisesRegex(ValueError, "did not complete"):
            self.execute('System.halt(0)')

    def test_actual_child_runs_outside_the_repository_project(self):
        # A Mix.install with a path dependency must not land inside this
        # repository's Mix project: the project's environment gates
        # dependencies the notebook never declared.
        output, _ = self.execute('IO.puts(File.cwd!()); IO.puts("COMPLETED_TEST")')
        self.assertNotEqual(str(ROOT), output.splitlines()[0])

    def test_actual_child_failure_output_is_retained(self):
        with self.assertRaisesRegex(ValueError, "diagnostic before early exit"):
            self.execute('IO.puts("diagnostic before early exit"); System.halt(0)')
        with self.assertRaisesRegex(TimeoutError, "diagnostic before deadline"):
            # Allow VM boot under CPU load to finish and print before the deadline.
            self.execute('IO.puts("diagnostic before deadline"); Process.sleep(:infinity)', timeout=20)

    def test_actual_child_failure_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "failed"):
            self.execute('raise "deliberate execution failure"')

    def test_actual_child_deadline_is_enforced(self):
        with self.assertRaises(TimeoutError):
            self.execute('Process.sleep(:infinity)', timeout=1)

    def test_cleanup_reaps_an_exited_child_without_masking_its_result(self):
        process = subprocess.Popen(
            ["elixir", "-e", 'IO.puts("COMPLETED_TEST")'],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            self.assertEqual(b"COMPLETED_TEST\n", process.stdout.read())
            self.assertIsNone(process.returncode, "the exited child is still unreaped")
            gate.stop_group(process)
            self.assertEqual(0, process.returncode)
        finally:
            process.wait(timeout=10)
            process.stdout.close()

    def test_actual_child_output_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "output limit"):
            self.execute('IO.puts(String.duplicate("x", 4096))', maximum_output=1024)


class BuildContractsTest(unittest.TestCase):
    def test_published_dependency_floors_derive_from_mix(self):
        spec = importlib.util.spec_from_file_location("optional_clients", ROOT / "scripts/check_optional_clients.py")
        clients = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(clients)
        _, runtime_path = clients.running_toolchain()
        dependencies = clients.dependency_metadata(runtime_path)
        published = {name: dependency for name, dependency in dependencies.items() if dependency["published"]}
        self.assertEqual("0.24.0", published["finch"]["floor"])
        self.assertEqual("0.7.4", published["req"]["floor"])
        self.assertEqual("1.4.2", published["telemetry"]["floor"])
        self.assertEqual("3.37.4", published["ash"]["floor"])
        self.assertEqual("1.20.3", published["plug"]["floor"])
        self.assertEqual("0.22.4", published["postgrex"]["floor"])
        if "ash_onetime" in published:
            self.assertEqual("1.9.2", published["ash_onetime"]["floor"])
            self.assertEqual("3.0.0", published["ash_hooks"]["floor"])
        self.assertFalse(dependencies["phoenix"]["published"])
        self.assertFalse(dependencies["dialyxir"]["published"])
        for name in published:
            files = clients.floor_files([name])
            self.assertTrue(any(path.endswith("_test.exs") for path in files))
            for path in files:
                self.assertTrue((ROOT / path).exists(), path)
        with self.assertRaisesRegex(ValueError, "need floor coverage"):
            clients.floor_files(["unmapped_dependency"])

    def test_floor_consumer_unlocks_moved_floors_and_their_dependents(self):
        spec = importlib.util.spec_from_file_location("optional_clients", ROOT / "scripts/check_optional_clients.py")
        clients = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(clients)
        lock = {
            "ash": {"version": "3.37.6", "dependencies": ["ecto", "telemetry"]},
            "ash_sql": {"version": "0.8.9", "dependencies": ["ash", "ecto"]},
            "ash_postgres": {"version": "2.16.0", "dependencies": ["ash", "ash_sql", "ecto"]},
            "migrator": {"version": "1.0.0", "dependencies": ["ash_postgres"]},
            "ecto": {"version": "3.14.0", "dependencies": ["telemetry"]},
            "telemetry": {"version": "1.4.2", "dependencies": []},
            "plug": {"version": "1.20.3", "dependencies": ["telemetry"]},
            "bandit": {"version": "1.15.0", "dependencies": ["plug", "telemetry"]},
        }
        floors = {"ash": "3.37.4", "plug": "1.20.3", "telemetry": "1.4.2", "ash_hooks": "3.0.0"}
        self.assertEqual(["ash", "ash_postgres", "ash_sql", "migrator"], clients.floor_unlocks(lock, floors))
        self.assertEqual([], clients.floor_unlocks(lock, {"plug": "1.20.3", "telemetry": "1.4.2"}))
        self.assertEqual(
            ["ash", "ash_postgres", "ash_sql", "bandit", "ecto", "migrator", "plug", "telemetry"],
            clients.floor_unlocks(lock, {"telemetry": "1.4.1"}),
        )
        _, runtime_path = clients.running_toolchain()
        graph = clients.lock_graph(runtime_path)
        self.assertIn("ash", graph["ash_postgres"]["dependencies"])
        self.assertEqual([], graph["telemetry"]["dependencies"])

    def test_actual_action_refs_reject_mutable_tags_and_missing_checkout(self):
        original = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual([], gate.ci_action_errors(original))
        import re
        checkout = re.search(r"actions/checkout@[0-9a-f]{40}", original).group()
        for changed in (original.replace(checkout, "actions/checkout@v4"), original.replace(checkout, "other/action@" + "a" * 40)):
            with self.subTest(changed=changed):
                self.assertTrue(gate.ci_action_errors(changed))


class EvaluatedFenceTest(unittest.TestCase):
    def check_pair(self, document, source, paired):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ('test/readme_test.exs' if document == 'README.md' else 'test/docs/' + document.removesuffix('.md').replace('/', '_').replace('-', '_') + '_test.exs')
            target.parent.mkdir(parents=True)
            target.write_text(paired)
            return docs.fence_errors(root, document, source)

    def paired(self, code, document='README.md', count=1):
        return 'alias RequestSeal.DocsExamples, as: E\n' + "binding = E.eval(~S'''\n" + code + "''', binding, \"" + document + '\", 1)\n' + f'E.assert_fences("{document}", {count})\n'

    def test_a_comments_duplicates_and_nested_copies_are_not_execution(self):
        source = '```elixir\nx = 1\n```\n'
        valid = self.paired('x = 1\n')
        self.assertEqual([], self.check_pair('README.md', source, valid))
        self.assertTrue(self.check_pair('README.md', source, '# x = 1\n'))
        self.assertTrue(self.check_pair('README.md', source * 2, valid))
        self.assertTrue(self.check_pair('README.md', source, "other = ~S'''\n" + valid + "'''\n"))
        self.assertTrue(self.check_pair('README.md', source, valid + valid))

    def test_b_alternate_fences_cannot_escape(self):
        for opening, closing in [('```elixir title=example', '```'), ('```elixir,iex', '```'), ('    ```elixir', '    ```'), ('> ```elixir', '> ```'), ('- ```elixir', '  ```'), ('  1. ```elixir', '     ```')]:
            with self.subTest(opening=opening):
                self.assertTrue(self.check_pair('README.md', opening + '\nx = 1\n' + closing + '\n', ''))

    def test_c_approved_design_reference_and_operations_cannot_escape(self):
        for document in ['docs/design/example.md', 'docs/reference/example.md', 'docs/operations/example.md']:
            with self.subTest(document=document):
                source = '```elixir\nx = 1\n```\n'
                self.assertTrue(self.check_pair(document, source, ''))
                self.assertEqual([], self.check_pair(document, source, self.paired('x = 1\n', document)))

class CorpusReleasePinTest(unittest.TestCase):
    def test_actual_corpus_release_matches_the_package_version(self):
        sources = {path: (ROOT / path).read_text() for path in ("mix.exs", "corpus/index.json", "CHANGELOG.md")}
        self.assertEqual([], gate.corpus_release_errors(sources))

    def test_stale_or_missing_corpus_release_is_rejected(self):
        mix = '@version "0.5.0"\nversion: @version,'
        for index in ['{"elixir_release":"v0.4.1"}', '{"elixir_release":"0.5.0"}', '{}', "not json"]:
            with self.subTest(index=index):
                errors = gate.corpus_release_errors({"mix.exs": mix, "corpus/index.json": index})
                self.assertTrue(any("elixir_release" in error for error in errors))
        self.assertEqual([], gate.corpus_release_errors({
            "mix.exs": mix + '\nsource_url: "https://github.com/example/library",\n',
            "corpus/index.json": '{"elixir_release":"v0.5.0"}',
            "CHANGELOG.md": '## 0.5.0 - 2026-11-17\n\n- Released.\n',
        }))

    def test_generated_doc_links_resolve_to_a_file_and_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "Mod.html").write_text('<h2 id="same?/2">same?/2</h2><a href="#same?/2">self</a>')
            (output / "api-reference.html").write_text(
                '<a href="Mod.html#same?/2">ok</a><a href="https://example.org/#x">external</a>'
            )
            self.assertEqual([], gate.doc_link_errors(output))
            (output / "api-reference.html").write_text(
                '<a href="#same?/2">summary</a><a href="Gone.html">gone</a><a href="Mod.html#nope">nope</a>'
            )
            self.assertEqual(
                [
                    "api-reference.html: #same?/2 has no target",
                    "api-reference.html: Gone.html has no target",
                    "api-reference.html: Mod.html#nope has no target",
                ],
                gate.doc_link_errors(output),
            )

if __name__ == "__main__":
    unittest.main()
