"""Publication destinations against recorded, real GitHub GFM rendering."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import check_docs as docs
import record_markdown


class MarkdownDestinationsTest(unittest.TestCase):
    def test_combinatorial_section_covers_every_ordered_pair_and_arrangement(self):
        corpus = json.loads((ROOT / "test/fixtures/markdown_destinations.json").read_text())
        samples = [sample for sample in corpus["samples"] if "pair" in sample]
        generated = list(record_markdown.combinatorial_samples())
        self.assertEqual(364, len(samples))
        self.assertEqual({sample["name"]: sample["markdown"] for sample in generated},
                         {sample["name"]: sample["markdown"] for sample in samples})
        constructs = {name for sample in samples for name in sample["pair"]}
        self.assertEqual(14, len(constructs))
        self.assertEqual({(left, right, arrangement) for left in constructs for right in constructs if left != right
                          for arrangement in ("adjacent", "overlap")},
                         {(sample["pair"][0], sample["pair"][1], sample["arrangement"]) for sample in samples})
        self.assertEqual({"paragraph", "list", "quote", "table", "footnote"},
                         {sample["container"] for sample in samples})
        # This prevents an unrelated shared rejection from making the whole
        # pair matrix vacuous. Both arrangements must retain accepted cases.
        for arrangement in ("adjacent", "overlap"):
            accepted = [sample for sample in samples if sample["arrangement"] == arrangement
                        and "destinations" in sample["expected"]]
            self.assertGreater(len(accepted), 20)
            self.assertTrue(all("github_hrefs" in sample for sample in accepted))

    def test_recording_resumes_only_missing_renderings(self):
        corpus = json.loads((ROOT / "test/fixtures/markdown_destinations.json").read_text())
        self.assertEqual([], list(record_markdown.pending_recordings(corpus["samples"])))
        sample = next(sample for sample in corpus["samples"] if sample["name"] == "label-inline-outside")
        # Simulate an interrupted save using the actual committed reference
        # data, without replacing the renderer or any command/API response.
        outside_missing = {key: value for key, value in sample.items() if key != "github_document_hrefs"}
        queued = list(record_markdown.pending_recordings([outside_missing]))
        self.assertEqual(1, len(queued))
        self.assertEqual("github_document_hrefs", queued[0][1])
        self.assertIn(sample["outside_definitions"], queued[0][2])
        section_missing = {key: value for key, value in sample.items() if key != "github_hrefs"}
        queued = list(record_markdown.pending_recordings([section_missing]))
        self.assertEqual(1, len(queued))
        self.assertEqual(("github_hrefs", sample["markdown"]), queued[0][1:])

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
