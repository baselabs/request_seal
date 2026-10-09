"""Disclosure checks against actual repository content and real filesystem/Git inputs."""
from pathlib import Path
import importlib.util
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
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

    def test_current_readme_is_public(self):
        self.assertEqual([], self.errors())

    def test_testing_guide_property_counts_match_sources(self):
        suites = {
            "Structured Fields": "RequestSeal.StructuredFieldsPropertyTest",
            "Signature base": "RequestSeal.SignatureBasePropertyTest",
            "JOSE": "RequestSeal.JOSEPropertyTest",
            "Discovery": "RequestSeal.DiscoveryPropertyTest",
            "ETS replay": "RequestSeal.ReplayETSPropertyTest",
            "PostgreSQL replay": "RequestSeal.ReplayPostgresPropertyTest",
        }
        counts = {}
        files = sorted((ROOT / "test/property").glob("*.exs"))
        self.assertTrue(files, "property source inventory must not be empty")
        for path in files:
            modules = re.split(r"^defmodule (\S+) do\s*$", path.read_text(), flags=re.MULTILINE)
            for name, source in zip(modules[1::2], modules[2::2]):
                count = source.count('property "')
                if count:
                    self.assertNotIn(name, counts)
                    counts[name] = count
        self.assertEqual(set(suites.values()), set(counts))
        guide = (ROOT / "docs/guides/testing.md").read_text()
        rows = re.findall(r"^\| ([^|]+) \| (\d+) \| \d+ \|$", guide, re.MULTILINE)
        self.assertEqual(len(suites), len(rows))
        self.assertEqual(
            {suite: counts[module] for suite, module in suites.items()},
            {suite: int(count) for suite, count in rows},
        )

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

    def test_missing_metadata(self):
        self.assertTrue(any("metadata" in e for e in docs.content_errors(ROOT, "docs/guides/input.md", "# Input\n", self.paths)))

    def test_metadata_is_hidden_in_a_leading_comment(self):
        metadata = "<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: RFC 9421 · Review when: API changes -->\n"
        self.assertEqual([], docs.content_errors(ROOT, "docs/guides/input.md", metadata + "# Input\n", self.paths))
        for source in (
            metadata.replace("Kind:", "Category:"),
            "# Input\n" + metadata,
            "**Status:** current · **Kind:** guide · **Updated:** 2026-10-08 · **Governed by:** RFC 9421 · **Review when:** API changes\n",
        ):
            with self.subTest(source=source):
                self.assertTrue(any("metadata" in e for e in docs.content_errors(ROOT, "docs/guides/input.md", source, self.paths)))

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

    def test_actual_child_uses_repository_toolchain_context(self):
        output, _ = self.execute('IO.puts(File.cwd!()); IO.puts("COMPLETED_TEST")')
        self.assertIn(str(ROOT), output.splitlines())

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


class ToolchainTest(unittest.TestCase):
    def sources(self):
        return {path: (ROOT/path).read_text() for path in (
            ".tool-versions", "mix.exs", "config/config.exs", ".github/workflows/ci.yml",
            "tools/notebooks/mix.exs", "tools/notebooks/config/config.exs",
            "livebooks/environment.livemd")}

    def test_version_manager_comments_and_four_part_patch_are_supported(self):
        sources = self.sources()
        sources[".tool-versions"] = "# development pins\n" + sources[".tool-versions"].replace("29.1.1", "29.1.1.1 # exact patch")
        sources[".github/workflows/ci.yml"] = sources[".github/workflows/ci.yml"].replace("29.1.1", "29.1.1.1")
        self.assertEqual([], gate.toolchain_errors(sources))
        sources[".tool-versions"] = "elixir too many tokens here"
        self.assertTrue(any("version-manager" in error for error in gate.toolchain_errors(sources)))

    def test_actual_pins_are_consistent(self):
        self.assertEqual([], gate.toolchain_errors(self.sources()))

    def test_library_range_and_runtime_floor_are_declared(self):
        sources = self.sources()
        self.assertIn('elixir: "~> 1.18"', sources["mix.exs"])
        self.assertIn("minimum_otp = 27", sources["config/config.exs"])
        self.assertIn("running_otp < minimum_otp", sources["config/config.exs"])

    def test_ci_declares_three_supported_pairs(self):
        workflow = self.sources()[".github/workflows/ci.yml"]
        self.assertIn("- lane: floor\n            elixir: '1.18.4'\n            otp: '27.3.4'", workflow)
        self.assertIn("- lane: mid\n            elixir: '1.19.5'\n            otp: '28.5.0.7'", workflow)
        self.assertIn("- lane: latest\n            elixir: '1.20.4'\n            otp: '29.1.1'", workflow)

    def test_owned_dependency_rule_is_enforced(self):
        sources = self.sources()
        for old, new in [
            ('Version.match?(System.version(), ">= 1.20.0")', 'true'),
            ('{:ash_onetime, "~> 1.5", optional: true}', '{:ash_onetime, "~> 1.5"}'),
            ('{:ash_hooks, "~> 2.0", optional: true}', '{:ash_hooks, "== 2.0.3", optional: true}'),
            ('{:ash, "~> 3.34 and >= 3.34.3", optional: true}', '{:ash, "~> 3.34", optional: true}'),
            ('] ++ test_dependencies ++ owned_integrations()', '] ++ test_dependencies'),
        ]:
            with self.subTest(old=old):
                changed = dict(sources)
                self.assertIn(old, changed["mix.exs"])
                changed["mix.exs"] = changed["mix.exs"].replace(old, new)
                self.assertTrue(gate.toolchain_errors(changed))

    def test_ci_runs_optional_clients_on_floor(self):
        workflow = self.sources()[".github/workflows/ci.yml"]
        self.assertIn("- if: matrix.lane == 'floor'\n        run: python3 scripts/check_optional_clients.py", workflow)

    def test_ci_budget_covers_every_lane(self):
        self.assertIn("timeout-minutes: 40", self.sources()[".github/workflows/ci.yml"])

    def test_additional_matrix_lane_is_rejected(self):
        path = ".github/workflows/ci.yml"
        mutations = [
            "          - lane: other\n"
            "            elixir: '1.20.4'\n"
            "            otp: '29.1.1'\n",
            "          - elixir: '1.20.4'\n"
            "            lane: other\n"
            "            otp: '29.1.1'\n",
            "          - elixir: '1.20.4'\n"
            "            otp: '29.1.1'\n",
            "          - {lane: other, elixir: '1.20.4', otp: '29.1.1'}\n",
            "        os: ['ubuntu-24.04']\n",
        ]
        for extra in mutations:
            with self.subTest(extra=extra):
                sources = self.sources()
                self.assertEqual(1, sources[path].count("    services:\n"))
                sources[path] = sources[path].replace("    services:\n", extra + "    services:\n")
                self.assertEqual(
                    ["CI matrix must contain only the floor, mid, and latest lanes"],
                    gate.toolchain_errors(sources),
                )

    def test_range_floor_and_matrix_mutations_are_rejected(self):
        mutations = [
            (".github/workflows/ci.yml", "timeout-minutes: 40", "timeout-minutes: 20"),
            (".github/workflows/ci.yml", "- lane: mid", "- lane: other"),
            (".github/workflows/ci.yml", "elixir: '1.19.5'", "elixir: '1.19.4'"),
            (".github/workflows/ci.yml", "otp: '28.5.0.7'", "otp: '28.5.0.3'"),
            (".github/workflows/ci.yml", "matrix.lane == 'mid'", "matrix.lane == 'other'"),
            (".github/workflows/ci.yml", "run: python3 scripts/check_optional_clients.py", "run: mix test test/client_adapters_test.exs"),
            ("mix.exs", '{:finch, ">= 0.23.0 and < 0.25.0"', '{:finch, ">= 0.24.0 and < 0.25.0"'),
            ("mix.exs", '{:req, "~> 0.7.4"', '{:req, "~> 0.7.5"'),
            (".github/workflows/ci.yml", "runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
            (".github/workflows/ci.yml", "fail-fast: false", "fail-fast: true"),
            (".github/workflows/ci.yml", "image: postgres:18", "image: postgres:17"),
            ("mix.exs", 'elixir: "~> 1.18"', 'elixir: "~> 1.19"'),
            ("mix.exs", 'elixir: "~> 1.18"', 'elixir: "~> 1.18.4"'),
            ("mix.exs", "unless Code.ensure_loaded?(:json) do", "if Code.ensure_loaded?(:json) do"),
            ("config/config.exs", "running_otp < minimum_otp", "running_otp != minimum_otp"),
            ("config/config.exs", "String.to_integer()", "String.to_float()"),
            ("tools/notebooks/config/config.exs", 'expected_otp = "29"', 'expected_otp = "27"'),
            ("tools/notebooks/config/config.exs", "running_otp != expected_otp", "running_otp < expected_otp"),
            ("livebooks/environment.livemd", '"29" = System.otp_release()', '"27" = System.otp_release()'),
            (".tool-versions", "elixir 1.20.4-otp-29", "elixir 1.20.4-otp-28"),
            (".tool-versions", "nodejs 24.21.0", "nodejs latest"),
            (".github/workflows/ci.yml", "- lane: floor", "- lane: other"),
            (".github/workflows/ci.yml", "elixir: '1.18.4'", "elixir: '1.19.5'"),
            (".github/workflows/ci.yml", "otp: '27.3.4'", "otp: '28.5.0.3'"),
            (".github/workflows/ci.yml", "- lane: latest", "- lane: other"),
            (".github/workflows/ci.yml", "elixir: '1.20.4'", "elixir: '1.20.3'"),
            (".github/workflows/ci.yml", "otp: '29.1.1'", "otp: '29.0.3'"),
            (".github/workflows/ci.yml", "${{ matrix.elixir }}", "1.20.4"),
            (".github/workflows/ci.yml", "${{ matrix.otp }}", "29.1.1"),
            (".github/workflows/ci.yml", "matrix.lane == 'floor'", "matrix.lane == 'other'"),
            (".github/workflows/ci.yml", "matrix.lane == 'latest'", "matrix.lane == 'other'"),
            (".github/workflows/ci.yml", "mix test --warnings-as-errors", "mix test test/crypto_test.exs"),
            (".github/workflows/ci.yml", "REQUESTSEAL_REPLAY_PG_URL:", "UNUSED_DATABASE_URL:"),
        ]
        for path, old, new in mutations:
            with self.subTest(path=path, mutation=old):
                sources = self.sources()
                self.assertIn(old, sources[path])
                sources[path] = sources[path].replace(old, new)
                self.assertTrue(gate.toolchain_errors(sources))

    def test_optional_client_floors_derive_from_package_requirements(self):
        spec = importlib.util.spec_from_file_location("optional_clients", ROOT / "scripts/check_optional_clients.py")
        clients = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(clients)
        source = self.sources()["mix.exs"]
        self.assertEqual(("0.23.0", "0.7.4"), clients.client_floors(source))
        self.assertEqual(("0.24.0", "0.7.5"), clients.client_floors(
            source.replace(">= 0.23.0", ">= 0.24.0").replace("~> 0.7.4", "~> 0.7.5")))
        with self.assertRaises(ValueError):
            clients.client_floors(source.replace("{:req,", "{:other,"))

    def test_actual_action_refs_reject_mutable_tags_and_missing_checkout(self):
        inputs = self.sources()
        original = inputs[".github/workflows/ci.yml"]
        import re
        checkout = re.search(r"actions/checkout@[0-9a-f]{40}", original).group()
        for changed in (original.replace(checkout, "actions/checkout@v4"), original.replace(checkout, "other/action@" + "a" * 40)):
            with self.subTest(changed=changed):
                inputs[".github/workflows/ci.yml"] = changed
                self.assertTrue(gate.toolchain_errors(inputs))

    def test_each_real_pin_channel_detects_drift(self):
        mutations = {
            ".tool-versions": ("29.1.1", "29.1.2"),
            "mix.exs": ('elixir: "~> 1.18"', 'elixir: "1.20.4"'),
            "config/config.exs": ('minimum_otp = 27', 'minimum_otp = 29'),
            ".github/workflows/ci.yml": ("otp: '29.1.1'", "otp: '29.1.2'"),
            "tools/notebooks/mix.exs": ('elixir: "1.20.4"', 'elixir: "1.20.5"'),
            "tools/notebooks/config/config.exs": ('import_config "../../../config/config.exs"', 'import_config "other.exs"'),
            "livebooks/environment.livemd": ('"1.20.4" = System.version()', '"1.20.5" = System.version()'),
        }
        for path, (old, new) in mutations.items():
            with self.subTest(path=path):
                inputs = self.sources()
                self.assertIn(old, inputs[path])
                inputs[path] = inputs[path].replace(old, new)
                self.assertTrue(gate.toolchain_errors(inputs), path)



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

if __name__ == "__main__":
    unittest.main()
