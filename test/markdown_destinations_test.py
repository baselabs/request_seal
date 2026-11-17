"""Publication destinations against recorded, real GitHub GFM rendering."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import check_docs as docs


class MarkdownDestinationsTest(unittest.TestCase):
    def test_recorded_github_renderer_corpus(self):
        corpus = json.loads((ROOT / "test/fixtures/markdown_destinations.json").read_text())
        self.assertEqual("synthetic", corpus["source"])
        for sample in corpus["samples"]:
            with self.subTest(sample=sample["name"], construct=sample["construct"]):
                body = sample["markdown"]
                outside = {release.reference_label(match[1]) for match in
                           release.REFERENCE_START.finditer(sample.get("outside_definitions", ""))}
                expected = sample["expected"]
                if "reject" in expected:
                    with self.assertRaisesRegex(ValueError, expected["reject"]):
                        release.release_destinations(body, corpus["version"], all_reference_labels=outside)
                    continue
                destinations = release.release_destinations(body, corpus["version"])
                self.assertEqual(sorted(set(expected["destinations"])), sorted(set(destinations)))
                entries = release.extract_destinations(body, strict=True)
                self.assertFalse(any(ambiguous for _, _, ambiguous in entries))
                self.assertEqual(sorted(set(destinations)), sorted({target for _, target, _ in entries}))
                hrefs = {"http://" + target if target.startswith("www.") else target for target in destinations}
                self.assertEqual(sample["github_hrefs"], sorted(hrefs))

    def test_external_definition_changes_rendering_and_is_rejected(self):
        corpus = json.loads((ROOT / "test/fixtures/markdown_destinations.json").read_text())
        sample = next(sample for sample in corpus["samples"] if sample["name"] == "label-inline-outside")
        self.assertNotEqual(sample["github_hrefs"], sample["github_document_hrefs"])
        for outside in ("before", "after"):
            body = "## 2.3.4 - 2026-11-17\n\n" + sample["markdown"] + "\n"
            definitions = sample["outside_definitions"] + "\n"
            source = definitions + "\n" + body if outside == "before" else (
                body + "\n## 2.3.3 - 2026-11-16\n\n" + definitions)
            with self.subTest(outside=outside), self.assertRaisesRegex(ValueError, "reference 'b'"):
                release.release_notes(source, "2.3.4")

    def test_renderer_confirms_table_delimiter_indentation_limit(self):
        corpus = json.loads((ROOT / "test/fixtures/markdown_destinations.json").read_text())
        for indentation in range(5):
            sample = next(sample for sample in corpus["samples"]
                          if sample["name"] == "table-delimiter-indent-" + str(indentation))
            self.assertEqual(indentation < 4, "table" in sample["github_blocks"])

    def test_unsupported_structures_fail_both_documentation_scan_paths(self):
        body = "- | `x | https://example.com/missing | `y |\n  |---|---|---|"
        errors = docs.content_errors(ROOT, "README.md", body, {"README.md"})
        self.assertTrue(any("table in a container" in error for error in errors), errors)
        # This is a real source file in a temporary repository; no tracked file
        # or network response is patched to exercise the second scan path.
        from processes import run, temporary_directory
        with temporary_directory(prefix="requestseal-markdown-scan-") as directory:
            root = Path(directory)
            run(["git", "init", "--quiet"], cwd=root)
            (root / "README.md").write_text(body)
            configuration = {"files": {"README.md"}, "documents": {"README.md"}}
            errors = docs.tracked_link_errors(root, {"README.md"}, "2.3.4", set(), {}, configuration=configuration)
            self.assertTrue(any("table in a container" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
