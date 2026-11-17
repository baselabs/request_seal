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
                    root, "README.md", urlsplit("https://github.com/baselabs/request_seal/blob/main/" + path),
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
                            ROOT, "README.md", urlsplit(f"https://request-seal.hexdocs.pm/{version}/{page}"),
                            current, {"README.md"}, references))
                with self.subTest(version=version, page="missing"):
                    errors = docs.first_party_link_errors(
                        ROOT, "README.md", urlsplit(f"https://request-seal.hexdocs.pm/{version}/not-a-real-page.html"),
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
                    ROOT, "README.md", urlsplit(f"https://request-seal.hexdocs.pm/99.0.0/{page}"),
                    "2.0.0-dev", {"README.md"}, references)
                self.assertTrue(any("missing api-reference.html" in error for error in errors))
        self.assertEqual(1, output.getvalue().count("RUN mix hex.docs fetch "))
        self.assertEqual(scratch_before, set(Path(tempfile.gettempdir()).glob("requestseal-docs-*")))


if __name__ == "__main__":
    unittest.main()
