"""First-party link checks using real Git, ExDoc, and published Hex artifacts."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_docs as docs
import check as gate
import release
from processes import run, temporary_directory
from urllib.parse import urlsplit


class DocumentationLinksTest(unittest.TestCase):
    def test_main_links_use_current_files_and_inventory_without_any_main_ref(self):
        with temporary_directory(prefix="requestseal-main-test-") as directory:
            root = Path(directory)
            run(["git", "init", "--quiet", "--initial-branch=candidate"], cwd=root)
            (root / ".tool-versions").write_bytes((ROOT / ".tool-versions").read_bytes())
            (root / "mix.exs").write_text('''defmodule LinkFixture.MixProject do
  use Mix.Project
  def project do
    [app: :link_fixture, version: "2.0.0-dev", deps: [],
     docs: [extras: ["README.md", "new.md", "deleted.md"]],
     package: [files: ["README.md", "new.md", "deleted.md", "mix.exs"]]]
  end
end
''')
            (root / "README.md").write_text("# Entry\n")
            (root / "deleted.md").write_text("# Old\n")
            run(["git", "add", "README.md", "deleted.md", "mix.exs"], cwd=root)
            run(["git", "-c", "user.name=Link test", "-c", "user.email=link@example.invalid",
                 "commit", "--quiet", "-m", "Initial files"], cwd=root)
            (root / "new.md").write_text("# New\n")
            (root / "deleted.md").unlink()
            (root / "unlisted.md").write_text("# Repository only\n")
            self.assertFalse(docs.ref_exists(root, "refs/heads/main"))
            self.assertFalse(docs.ref_exists(root, "refs/remotes/origin/main"))
            references = {}

            def errors(path):
                return docs.first_party_link_errors(
                    root, "README.md", urlsplit("https:\x2f\x2fgithub.com/baselabs/request_seal/blob/main/" + path),
                    "2.0.0-dev", {"README.md"}, references)

            self.assertEqual([], errors("new.md"))
            self.assertTrue(errors("deleted.md"))
            self.assertTrue(errors("unlisted.md"))
            self.assertIn("new.md", references["WORKTREE"][0]["documents"])

    def test_current_and_published_pages_come_from_real_exdoc_and_hex_once(self):
        current = docs.public_configuration(ROOT)["version"]
        references = {}
        output = io.StringIO()
        scratch_before = set(Path(tempfile.gettempdir()).glob("requestseal-docs-*"))
        with redirect_stdout(output):
            for version in (current, "1.0.0"):
                for page in ("RequestSeal.html", "api-reference.html", "web-bot-auth.html"):
                    with self.subTest(version=version, page=page):
                        self.assertEqual([], docs.first_party_link_errors(
                            ROOT, "README.md", urlsplit(f"https:\x2f\x2frequest-seal.hexdocs.pm/{version}/{page}"),
                            current, {"README.md"}, references))
                with self.subTest(version=version, page="missing"):
                    errors = docs.first_party_link_errors(
                        ROOT, "README.md", urlsplit(f"https:\x2f\x2frequest-seal.hexdocs.pm/{version}/not-a-real-page.html"),
                        current, {"README.md"}, references)
                    self.assertTrue(any("missing from real documentation output" in error for error in errors))
        self.assertEqual(1, output.getvalue().count("RUN mix docs "))
        self.assertEqual(1, output.getvalue().count("RUN mix hex.docs fetch "))
        self.assertEqual(scratch_before, set(Path(tempfile.gettempdir()).glob("requestseal-docs-*")))

    def test_failed_published_docs_fetch_removes_scratch(self):
        scratch_before = set(Path(tempfile.gettempdir()).glob("requestseal-docs-*"))
        output = io.StringIO()
        references = {}
        with redirect_stdout(output):
            for page in ("RequestSeal.html", "api-reference.html"):
                errors = docs.first_party_link_errors(
                    ROOT, "README.md", urlsplit(f"https:\x2f\x2frequest-seal.hexdocs.pm/99.0.0/{page}"),
                    "2.0.0-dev", {"README.md"}, references)
                self.assertTrue(any("version not published on Hex: 99.0.0" in error for error in errors), errors)
        self.assertEqual(1, output.getvalue().count("RUN mix hex.docs fetch "))
        self.assertEqual(scratch_before, set(Path(tempfile.gettempdir()).glob("requestseal-docs-*")))

    def test_missing_pages_and_ids_use_real_current_and_published_output(self):
        current = docs.public_configuration(ROOT)["version"]
        references = {}
        for version in (current, "1.0.0"):
            base = f"https:\x2f\x2frequest-seal.hexdocs.pm/{version}/"
            valid = docs.first_party_link_errors(ROOT, "README.md", base + "RequestSeal.html", current, set(), references)
            self.assertEqual([], valid)
            ids = references[("hexdocs", version)]["RequestSeal.html"]
            self.assertTrue(ids)
            fragment = next(value for value in sorted(ids) if value)
            self.assertEqual([], docs.first_party_link_errors(
                ROOT, "README.md", base + "RequestSeal.html#" + fragment, current, set(), references))
            self.assertEqual(["HexDocs fragment is missing from real documentation output for " + version],
                             docs.first_party_link_errors(ROOT, "README.md", base + "RequestSeal.html#no-such-requestseal-id",
                                                          current, set(), references))
            self.assertEqual([], docs.first_party_link_errors(ROOT, "README.md", base, current, set(), references))
            for link in (f"[Missing]({base}not-a-real-page.html)", f"[missing]: {base}not-a-real-page.html",
                         f'<a href="{base}not-a-real-page.html">missing</a>', f'<img src="{base}not-a-real-page.html">',
                         f"<{base}not-a-real-page.html>", f"**{base}not-a-real-page.html**"):
                with self.subTest(version=version, link=link):
                    errors = docs.content_errors(ROOT, "README.md", link, docs.public_paths(ROOT), current, set(), references)
                    self.assertEqual(1, len(errors), errors)
                    self.assertIn("HexDocs page is missing from real documentation output for " + version, errors[0])
                    self.assertNotIn("cannot inspect", errors[0])

    def test_current_output_can_be_reused_without_a_second_build(self):
        current = docs.public_configuration(ROOT)["version"]
        with temporary_directory(prefix="requestseal-reuse-docs-") as directory:
            output = Path(directory) / "current"
            run(["mix", "docs", "--warnings-as-errors", "--output", output], cwd=ROOT,
                extra_env={"MIX_ENV": "dev"}, timeout=900)
            captured = io.StringIO()
            with redirect_stdout(captured):
                pages = docs.documentation_pages(ROOT, current, current, output)
            self.assertIn("RequestSeal.html", pages)
            self.assertNotIn("RUN mix docs", captured.getvalue())

    def test_check_run_builds_documentation_once_and_removes_scratch(self):
        captured = io.StringIO()
        scratch_before = set(Path(tempfile.gettempdir()).glob("requestseal-docs-*"))
        with redirect_stdout(captured):
            gate.check_documentation()
        self.assertEqual(1, captured.getvalue().count("RUN mix docs "))
        self.assertIn("--docs-output", captured.getvalue())
        self.assertEqual(scratch_before, set(Path(tempfile.gettempdir()).glob("requestseal-docs-*")))

    def test_all_tracked_text_files_are_scanned_including_corpus_and_package_metadata(self):
        with temporary_directory(prefix="requestseal-tracked-links-") as directory:
            root = Path(directory)
            run(["git", "init", "--quiet"], cwd=root)
            (root / "README.md").write_text("# Entry\n")
            files = ("corpus/cases/profile/example.json", "livebooks/example.livemd", "lib/example.ex", "mix.exs", "metadata.txt")
            target = "https:\x2f\x2fhexdocs.pm/request_seal/1.0.0/RequestSeal.Profile.html"
            for relative in files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"url":"' + target + '"}\n')
            (root / "image.bin").write_bytes(b"\0" + target.encode())
            run(["git", "add", "README.md", "image.bin", *files], cwd=root)
            errors = docs.tracked_link_errors(root, docs.public_paths(root), "2.0.0-dev", set(), {})
            self.assertEqual(len(files), len(errors), errors)
            for relative in files:
                self.assertTrue(any(error.startswith(relative + ":1:") and "canonical" in error for error in errors), errors)
            # The check also sees newly authored, untracked text before staging.
            (root / "new.txt").write_text(target)
            self.assertEqual(len(files) + 1, len(docs.tracked_link_errors(root, docs.public_paths(root), "2.0.0-dev", set(), {})))

    def test_source_fragments_check_worktree_and_tagged_bytes(self):
        with temporary_directory(prefix="requestseal-source-lines-") as directory:
            root = Path(directory)
            run(["git", "init", "--quiet"], cwd=root)
            (root / "README.md").write_text("first\nsecond\n")
            run(["git", "add", "README.md"], cwd=root)
            run(["git", "-c", "user.name=Link test", "-c", "user.email=link@example.invalid", "commit", "--quiet", "-m", "Source lines"], cwd=root)
            run(["git", "tag", "v1.0.0"], cwd=root)
            references = {"WORKTREE": ({"documents": {"README.md"}}, {"README.md": "100644"})}
            for ref in ("main", "v1.0.0"):
                base = f"https:\x2f\x2fgithub.com/baselabs/request_seal/blob/{ref}/README.md"
                self.assertEqual([], docs.first_party_link_errors(root, "README.md", base + "#L1-L2", "2.0.0-dev", set(), references))
                for fragment in ("#L3", "#L2-L1"):
                    self.assertRegex(" ".join(docs.first_party_link_errors(root, "README.md", base + fragment, "2.0.0-dev", set(), references)), "line count")

    def test_shared_extractor_and_classifier_cover_both_callers(self):
        target = "https:\x2f\x2frequest-seal.hexdocs.pm/2.3.4/readme.html"
        for source in (f"[{target}]({target})", f"[Guide]({target})—details", f"[guide]: {target}",
                       f'<a href="{target}">guide</a>', f'<img src="{target}">', f"<{target}>", f"~~{target}~~"):
            self.assertEqual([target], [value for _, value, _ in docs.extract_destinations(source)])
        for target, kind in ((target, "hexdocs"), ("https:\x2f\x2fgithub.com/baselabs/request_seal/issues/123", "github_live"),
                             ("https:\x2f\x2fgithub.com/baselabs/request_seal/pull/123", "github_live"),
                             ("https:\x2f\x2fgithub.com/baselabs/request_seal/compare/v1.0.0...v2.3.4", "github_compare"),
                             ("https:\x2f\x2fhex.pm/packages/request_seal/2.3.4", "hex_package")):
            self.assertEqual(kind, release.validate_destination(target, "2.3.4"))
            self.assertEqual(kind, docs.classify_destination(target)["kind"])

    def test_queries_are_not_dropped_before_document_validation(self):
        for suffix in ("?raw=true", "?"):
            target = "https:\x2f\x2fgithub.com/baselabs/request_seal/blob/main/README.md" + suffix
            errors = docs.content_errors(ROOT, "README.md", f"[Source]({target})", docs.public_paths(ROOT))
            self.assertEqual(1, len(errors), errors)
            self.assertIn("no query string", errors[0])

    def test_uppercase_www_does_not_escape_tracked_first_party_validation(self):
        target = "WWW\x2eGITHUB.COM/baselabs/request_seal/blob/main/README.md"
        errors = docs.content_errors(ROOT, "README.md", target, docs.public_paths(ROOT))
        self.assertEqual(1, len(errors), errors)
        self.assertIn("canonical", errors[0])

    def test_profile_corpus_urls_are_canonical(self):
        for path in (ROOT / "corpus/cases/profile").glob("*.json"):
            for _, target, _ in release.extract_destinations(path.read_text(), markdown=False):
                with self.subTest(path=path, target=target):
                    self.assertIsNotNone(release.classify_destination(target))


if __name__ == "__main__":
    unittest.main()
