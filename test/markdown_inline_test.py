"""Pure string regressions for interacting Markdown inline constructs."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import check_docs as docs

TARGET = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
INNER = "https://example.com/inner"


class MarkdownInlineTest(unittest.TestCase):
    def destinations(self, source):
        return [target for _, target, _ in release.extract_destinations(source, strict=True)]

    def test_literal_closers_preserve_the_entire_bare_destination(self):
        for source in (f"[a] b]({TARGET})x", rf"\[a]({TARGET})x",
                       f"| [a | b]({TARGET})x |\n|---|---|",
                       f"[[x]({INNER})]({TARGET})x",
                       f"[[x][r]]({TARGET})x\n\n[r]: {INNER}"):
            with self.subTest(source=source):
                targets = self.destinations(source)
                self.assertIn(TARGET + ")x", targets)
                self.assertNotIn(TARGET, targets)
        self.assertEqual([TARGET], self.destinations(f"[outer [literal]]({TARGET})"))

    def test_angle_constructs_win_over_later_backticks_by_position(self):
        angles = ("<ftp://example.com/a`b>", "<mailto:a`b@example.com>", "<a`b@example.com>",
                  "<a+:a`b>", "<" + "a" * 32 + ":a`b>", '<span title="a`b>c">',
                  "<!-- a`b -->", "<?a`b?>", "<!CDATA a`b>", "<![CDATA[a`b]]>")
        for angle in angles:
            with self.subTest(angle=angle):
                self.assertIn(TARGET, [target for _, target, _ in docs.extract_destinations(
                    f"Before {angle} {TARGET} `")])
                self.assertNotIn(TARGET, self.destinations(f"``Before {angle} {TARGET} ``"))

    def test_autolink_schemes_require_two_to_thirty_two_characters(self):
        for scheme in ("x", "x" * 33):
            with self.subTest(length=len(scheme)):
                self.assertNotIn(TARGET, self.destinations(f"<{scheme}:a`b> {TARGET} `"))

    def test_escaped_angle_opener_leaves_the_closing_angle_in_the_bare_url(self):
        self.assertEqual([TARGET + ">"], self.destinations(r"\<" + TARGET + ">"))
        with self.assertRaisesRegex(ValueError, "canonical"):
            release.release_destinations(r"\<" + TARGET + ">", "2.3.4")
        self.assertEqual([TARGET], self.destinations(r"\\<" + TARGET + ">"))

    def test_multiline_labels_and_invalid_fence_info_are_shared_rejections(self):
        for indentation in range(4):
            source = "Use [a b].\n\n" + " " * indentation + "[a\nb]: " + TARGET + "."
            with self.subTest(indentation=indentation), self.assertRaisesRegex(ValueError, "multiline reference label"):
                self.destinations(source)
        for source, reason in (("```x`y\n" + TARGET + "\n\nPara", "backtick fence info"),
                               ("[a\nb]: text", "multiline reference label")):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, reason):
                    release.release_destinations(source, "2.3.4")
                entries = docs.extract_destinations(source)
                self.assertTrue(any(ambiguous and reason in target for _, target, ambiguous in entries))
        self.assertEqual([], self.destinations("~~~x`y\n" + TARGET + "\n~~~"))

    def test_unclosed_brackets_suppress_bare_urls_and_affect_code_pairing(self):
        for source in ("Before [unclosed " + TARGET, f"Before [<https://example.com/inner> {TARGET}"):
            with self.subTest(source=source):
                self.assertNotIn(TARGET, self.destinations(source))
        self.assertIn(TARGET, self.destinations(f"[`x`] {TARGET} tail `"))
        self.assertEqual([], self.destinations(f"[`{INNER}]({INNER})` {TARGET} tail `"))

    def test_www_requires_its_source_boundary_even_after_code_or_links(self):
        for prefix in ("`x`", f"[x]({INNER})", "word", "x)"):
            with self.subTest(prefix=prefix):
                self.assertNotIn("www.example.com/x", self.destinations(prefix + "www.example.com/x"))
        for prefix in ("", " ", "(", "*", "_", "~"):
            with self.subTest(prefix=prefix):
                self.assertIn("www.example.com/x", self.destinations(prefix + "www.example.com/x"))

    def test_unused_definitions_and_encoded_interactions_are_named_rejections(self):
        for source, reason in ((f"`[x]`\n\n[x]: {INNER}", "unused link reference definition"),
                               (f"`[^x]`\n\n[^x]: {INNER}", "unused footnote definition"),
                               (f"<{INNER}[x]>", "autolink destination encoding"),
                               (f"{INNER}[x]({TARGET})", "encoding in an extended autolink")):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, reason):
                release.release_destinations(source, "2.3.4")

    def test_failed_angle_www_is_rejected_without_claiming_a_rendered_link(self):
        for host in ("www.github.com", "WWW.GITHUB.COM"):
            source = "<" + host + "/baselabs/request_seal/blob/v2.3.4/README.md>"
            for container in ("{}", "> {}", "- {}", "| {} |\n|---|", "Use [^x].\n\n[^x]: {}"):
                body = container.format(source)
                with self.subTest(body=body), self.assertRaisesRegex(ValueError, "destination .*ambiguous literal angle"):
                    release.release_destinations(body, "2.3.4")

    def test_failed_angles_preserve_http_and_simple_email_destinations(self):
        for target, expected in (("http://example.com/path", "http://example.com/path"),
                                 ("https://example.com/path", "https://example.com/path"),
                                 ("user@example.com", "mailto:user@example.com")):
            for source in ("<" + target, "<<" + target + ">"):
                with self.subTest(source=source):
                    self.assertEqual([expected], release.release_destinations(source, "2.3.4"))
        for source in ("<user%20name@example.com", "<user@example..com"):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "extended email autolink after literal angle"):
                release.release_destinations(source, "2.3.4")


if __name__ == "__main__":
    unittest.main()
