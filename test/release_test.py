"""Release safety checks against real Git repositories and artifact metadata."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import sbom
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
        (self.root / "mix.exs").write_text(f'@version "{version}"\nversion: @version,\nsource_url: "https://github.com/example/library",\n')
        (self.root / "corpus/index.json").write_text(json.dumps({"elixir_release": "v" + version}))
        (self.root / "CHANGELOG.md").write_text(f"# Changelog\n\n## {version} - 2026-11-17\n\n- Release behavior.\n")

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

    def test_verify_cli_emits_version_and_semantic_prerelease_outputs(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(ROOT / "scripts/release.py", scripts / "release.py")
        for version, prerelease in (("2.0.0", "false"), ("2.0.0-rc.1", "true"), ("0.6.0", "false")):
            with self.subTest(version=version):
                self.identity(version)
                output = self.root / "github-output"
                output.write_text("")
                result = subprocess.run(
                    [sys.executable, "-B", str(scripts / "release.py"), "--verify"],
                    env=dict(os.environ, GITHUB_EVENT_NAME="workflow_dispatch",
                             GITHUB_REF="refs/heads/main", GITHUB_OUTPUT=str(output)),
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f"version={version}\nprerelease={prerelease}\n", output.read_text())

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

    def test_shared_version_cases(self):
        cases = json.loads((ROOT / "test/fixtures/release_versions.json").read_text())
        for case in cases:
            version = case["version"]
            with self.subTest(version=version):
                self.assertEqual(case["development"], release.development_snapshot(version))
                self.assertEqual(case["source_ref"], release.source_ref(version))
                self.assertEqual(case["install_requirement"], release.install_requirement(version))
                self.identity(version)
                if case["development"]:
                    with self.assertRaisesRegex(ValueError, "development snapshots"):
                        self.verify()
                else:
                    self.assertEqual(version, self.verify())
                    self.git("tag", "v" + version)
                    self.assertEqual(version, self.verify("push", "refs/tags/v" + version))
                sources = {path: (self.root / path).read_text() for path in ("mix.exs", "corpus/index.json", "CHANGELOG.md")}
                self.assertEqual([], gate.corpus_release_errors(sources))

    def test_changelog_release_notes(self):
        source = "# Changelog\n\n## Unreleased 2.4.0\n\n- Future.\n\n## 2.3.4 - 2026-11-17\n\n### Fixed\n\n- Public release behavior.\n\n## 2.3.3 - 2026-11-16\n\n- Older.\n"
        self.assertEqual("### Fixed\n\n- Public release behavior.\n", release.release_notes(source, "2.3.4"))
        for changed in (
            source.replace("2.3.4", "2.3.5"),
            source.replace(" - 2026-11-17", ""),
            source.replace("2026-11-17", "2026-02-30"),
            source.replace("### Fixed\n\n- Public release behavior.", ""),
            source.replace("- Public release behavior.", ""),
            source.replace("## 2.3.4 -", "## Unreleased 2.3.4 -"),
        ):
            with self.subTest(source=changed), self.assertRaises(ValueError):
                release.release_notes(changed, "2.3.4")
        (self.root / "CHANGELOG.md").write_text(source.replace("## 2.3.4 -", "## Unreleased 2.3.4 -"))
        with self.assertRaisesRegex(ValueError, "dated section"):
            self.verify()  # Dry run must reject before any tag exists.

    def test_bumped_version_rejects_stale_documented_installs(self):
        source = '{:request_seal, "~> 2.0"}'
        for path in ("README.md", "livebooks/environment.livemd", "livebooks/overview.md"):
            self.assertEqual([], docs.release_errors(path, source, "2.0.0-dev"))
            for version in ("2.1.0-dev", "3.0.0-dev"):
                self.assertTrue(docs.release_errors(path, source, version))

    def test_release_gate_requires_cut_notes_for_all_release_versions(self):
        for version in ("2.3.4", "2.3.4-rc.1", "2.3.4-dev"):
            self.identity(version)
            sources = {path: (self.root / path).read_text() for path in ("mix.exs", "corpus/index.json", "CHANGELOG.md")}
            self.assertEqual([], gate.corpus_release_errors(sources))
            sources["CHANGELOG.md"] = "## Unreleased " + version + "\n\n- Pending.\n"
            self.assertEqual(release.development_snapshot(version), not gate.corpus_release_errors(sources))

    def test_release_notes_normalize_crlf_and_ignore_fenced_headings(self):
        for fence in ("```", "~~~~"):
            body = f"- Released.\n\n{fence}markdown\n## 2.3.4 - 2026-11-17\n## Example\n{fence}\n\n- Still this release.\n"
            source = f"## 2.3.4 - 2026-11-17\n\n{body}\n## 2.3.3 - 2026-11-16\n\n- Older.\n"
            self.assertEqual(body, release.release_notes(source, "2.3.4"))
            self.assertEqual(body, release.release_notes(source.replace("\n", "\r\n"), "2.3.4"))

    def test_release_notes_pin_relative_inline_and_reference_links(self):
        body = ('[Guide](docs/guide.md) [Title](./docs/title.md "Title")\n'
                '[Angle](<docs/angle.md>) [Reference][guide]\n'
                '\n[guide]: docs/guide.md#section "Guide"\n'
                '[Web](https://example.com/docs) [Mail](mailto:team@example.com)\n'
                '[Anchor](#section) [Network](//example.com/docs)\n'
                '```markdown\n[Example](docs/example.md)\n```\n')
        expected = body
        for path in ("docs/guide.md", "./docs/title.md", "docs/angle.md"):
            expected = expected.replace(path, "https://github.com/example/library/blob/v2.3.4/" + path.removeprefix("./"))
        self.assertEqual(expected, release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4", "https://github.com/example/library"))

    def test_stale_corpus_and_unexpected_event_are_refused(self):
        (self.root / "corpus/index.json").write_text('{"elixir_release":"v2.3.3"}')
        with self.assertRaisesRegex(ValueError, "elixir_release"):
            self.verify()
        self.identity("2.3.4")
        with self.assertRaisesRegex(ValueError, "workflow_dispatch"):
            self.verify("pull_request")

    def test_release_notes_markdown_destinations_and_code(self):
        base = "https://github.com/example/library"
        blob = base + "/blob/v2.3.4/"
        raw = base + "/raw/v2.3.4/"
        cases = (
            ("[t](docs/x.md)", "[t](" + blob + "docs/x.md)"),
            ("[t](/docs/x.md)", "[t](" + blob + "docs/x.md)"),
            ("[t](./docs/../README.md#part)", "[t](" + blob + "README.md#part)"),
            ('[t](docs/x.md "Title")', '[t](' + blob + 'docs/x.md "Title")'),
            ("[t](<docs/a b.md>)", "[t](<" + blob + "docs/a%20b.md>)"),
            ("[id]: <docs/a b.md#part> 'Title'", "[id]: <" + blob + "docs/a%20b.md#part> 'Title'"),
            ("[id]: /docs/x.md", "[id]: " + blob + "docs/x.md"),
            ("![a](docs/x.png)", "![a](" + raw + "docs/x.png)"),
            ("![a](<docs/a b.png>)", "![a](<" + raw + "docs/a%20b.png>)"),
            ("[t](docs/a(b).md)", "[t](" + blob + "docs/a%28b%29.md)"),
            ("[t](https://example.com/a) [t](#part)", None),
            (r"[t](https://example.com/a\)b) [t](#part\))", None),
            ("[t](ssh://example.com/a) [t](mailto:team@example.com)", None),
            ("[t](custom:opaque) [t](//example.com/a)", None),
            ("[^1]: docs/x.md is footnote prose", None),
            ("`[t](docs/x.md)` and ``[t](docs/y.md) `tick` ``", None),
            ("`multiline\n[t](docs/x.md)\ncode`", None),
            ("```markdown\n[t](docs/x.md)\n[id]: docs/x.md\n```", None),
            ("~~~~markdown\n![a](docs/x.png)\n~~~~", None),
            ("    [t](docs/x.md)\n    [id]: docs/x.md", None),
            ("\t![a](docs/x.png)", None),
            (r"\[t](docs/x.md)", None),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual((source if expected is None else expected) + "\n",
                                 release.release_notes("## 2.3.4 - 2026-11-17\n\n" + source + "\n", "2.3.4", base))

    def test_release_notes_reject_escaping_and_query_only_destinations(self):
        for target in ("../x.md", "docs/../../x.md", "a/../../x.md", "?raw=1"):
            for link in (f"[t]({target})", f"![a]({target})", f"[id]: {target}"):
                with self.subTest(link=link), self.assertRaisesRegex(ValueError, re.escape(target)):
                    release.release_notes("## 2.3.4 - 2026-11-17\n\n" + link, "2.3.4")

    def test_release_notes_pin_links_adjacent_to_code_only_outside_code(self):
        source = '`[code](docs/a.md)` [live](docs/a.md)\n\n    [code](../escape.md)\n\n[live](docs/b.md)\n'
        expected = source.replace('[live](docs/', '[live](https://github.com/example/library/blob/v2.3.4/docs/')
        self.assertEqual(expected, release.release_notes("## 2.3.4 - 2026-11-17\n\n" + source, "2.3.4", "https://github.com/example/library"))

    def pin(self, source):
        return release.pin_markdown_links(source, "2.3.4", "https://github.com/example/library")

    def test_container_indentation_pins_prose_and_rejects_escapes(self):
        for source in (
            "- Outer\n    - Inner [n](docs/x.md)",
            "- Item\n\n    Second paragraph [n](docs/x.md)",
            "1. Item\n    continued [n](docs/x.md)",
            "- Outer\n    - Inner\n        - Third [n](docs/x.md)",
            "- Outer\n\t- Inner [n](docs/x.md)",
            "Paragraph\n    continued [n](docs/x.md)",
            "> Paragraph\n>     continued [n](docs/x.md)",
            "- Item\n  > Paragraph\n  >     continued [n](docs/x.md)",
            "- Lazy\ncontinuation [n](docs/x.md)",
            "- Item\n\nOutside\n    continued [n](docs/x.md)",
        ):
            with self.subTest(source=source):
                self.assertEqual(source.replace("docs/x.md", "https://github.com/example/library/blob/v2.3.4/docs/x.md"), self.pin(source))
                with self.assertRaisesRegex(ValueError, "escapes the repository"):
                    self.pin(source.replace("docs/x.md", "../x.md"))

    def test_container_indented_and_fenced_code_is_preserved(self):
        for source in (
            "    [n](../x.md)", "\t[n](../x.md)",
            "- Item\n\n      [n](../x.md)",
            "- Item\n\n  \t  [n](../x.md)",
            "- Item\n\n\t  [n](../x.md)",
            "-     [n](../x.md)",
            "- Item\n    ```md\n    [n](../x.md)\n    ```",
            "- Item\n  > ```md\n  > [n](../x.md)\n  > ```",
            ">     [n](../x.md)",
        ):
            with self.subTest(source=source):
                self.assertEqual(source, self.pin(source))
        source = "- Item\n  ```md\n  [code](../x.md)\n  ```\n  [live](docs/x.md)"
        self.assertIn("[live](https://github.com/example/library/blob/v2.3.4/docs/x.md)", self.pin(source))

    def test_nested_image_and_reference_images_use_raw_destinations(self):
        source = "[![badge](docs/x.png)](docs/y.md)"
        self.assertEqual("[![badge](https://github.com/example/library/raw/v2.3.4/docs/x.png)](https://github.com/example/library/blob/v2.3.4/docs/y.md)", self.pin(source))
        for image in ("![a][logo]", "![logo][]", "![logo]", "![a][ LoGo ]", "![a][my  logo]"):
            definition = "[My LoGo]: docs/logo.png" if "my" in image else "[LoGo]: docs/logo.png"
            with self.subTest(image=image):
                source = image + "\n\n" + definition
                self.assertEqual(source.replace("docs/logo.png", "https://github.com/example/library/raw/v2.3.4/docs/logo.png"), self.pin(source))

    def test_reference_label_cannot_serve_both_images_and_links(self):
        for source in (
            "![a][logo] [b][LOGO]\n\n[logo]: docs/x.png",
            "![My  Logo][] [my logo]\n\n[MY LOGO]: docs/x.png",
            "[![logo]](docs/y.md) [logo]\n\n[logo]: docs/x.png",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "both image and link: (?:my )?logo"):
                self.pin(source)

    def test_reference_definitions_require_a_complete_valid_line(self):
        for source in (
            "[Breaking]: The API now requires x",
            '[id]: docs/x.md "title" trailing prose',
            "[id]: docs/x.md 'unclosed",
            "[id]: docs/x.md (unclosed",
            '[id]: docs/x.md "title\n\nunclosed"',
        ):
            with self.subTest(source=source):
                self.assertEqual(source, self.pin(source))

    def test_reference_definitions_in_containers_and_on_following_lines(self):
        for source in (
            "- [id]: docs/x.md", "> [id]: docs/x.md",
            "- Item\n\n    [id]: docs/x.md",
            "- Outer\n    - [id]: docs/x.md",
            "- > [id]: docs/x.md",
            "[id]:\n  docs/x.md", "> [id]:\n>   docs/x.md",
            "- [id]:\n    docs/x.md",
            '[id]: docs/x.md "title\ncontinued"',
            "[id]: docs/x.md 'title\ncontinued'",
            "[id]: docs/x.md (title\ncontinued)",
            '[id]: docs/x.md\n  "title"',
            '> [id]: docs/x.md "title\n> continued"',
        ):
            with self.subTest(source=source):
                self.assertEqual(source.replace("docs/x.md", "https://github.com/example/library/blob/v2.3.4/docs/x.md"), self.pin(source))

    def test_destinations_preserve_percent_bytes_and_resolve_markdown_escapes(self):
        for source, target in (
            ("[t](docs/a%29.md)", "docs/a%29.md"),
            (r"[t](docs/a\)b.md)", "docs/a%29b.md"),
            ("[t](<docs/a b.md>)", "docs/a%20b.md"),
            ("[t](docs/a%2f%2F.md)", "docs/a%2f%2F.md"),
            ("[t](<docs/a\\b.md>)", "docs/a%5Cb.md"),
        ):
            with self.subTest(source=source):
                self.assertIn("https://github.com/example/library/blob/v2.3.4/" + target, self.pin(source))

    def test_escaped_and_unpaired_backticks_do_not_hide_links(self):
        for source in (
            r"\`[n](docs/x.md)`",
            "`unpaired\n\n[n](docs/x.md)\n`later",
            "```a`b```\n[n](docs/x.md)",
        ):
            with self.subTest(source=source):
                self.assertIn("[n](https://github.com/example/library/blob/v2.3.4/docs/x.md)", self.pin(source))
        source = "~~~a`b\n[n](../x.md)\n~~~"
        self.assertEqual(source, self.pin(source))
        self.assertFalse(next(release.markdown_lines("```a`b```\n"))[1])
        self.assertTrue(next(release.markdown_lines("~~~a`b\n"))[1])

    def test_commonmark_brief_differential_cases_have_exact_output(self):
        # CommonMark 0.31.2 §§2.4, 4.1, 4.3, 4.7, 6.1, 6.3, 6.4, 6.6:
        # https://spec.commonmark.org/0.31.2/ . Expected destinations reflect
        # parsed links/images, never Markdown-looking literal text.
        blob = "https://github.com/example/library/blob/v2.3.4/"
        raw = "https://github.com/example/library/raw/v2.3.4/"
        cases = [
            ("Title\n---\n    code [n](docs/x.md)", "Title\n---\n    code [n](docs/x.md)"),
            ("para\n\n---\n    code [n](docs/x.md)", "para\n\n---\n    code [n](docs/x.md)"),
            ("para\n\n* * *\n\n    code [n](docs/x.md)", "para\n\n* * *\n\n    code [n](docs/x.md)"),
            ("para\n\n- - -\n\n    code [n](docs/x.md)", "para\n\n- - -\n\n    code [n](docs/x.md)"),
            (r"\``a [t](docs/x.md)`", r"\``a [t](docs/x.md)`"),
            ("`` [L](docs/a.md)\n- x ``", "`` [L](" + blob + "docs/a.md)\n- x ``"),
            ("[`A`] ![`B`]\n\n[`A`]: docs/a.md\n[`B`]: docs/b.png",
             "[`A`] ![`B`]\n\n[`A`]: " + blob + "docs/a.md\n[`B`]: " + raw + "docs/b.png"),
            ("para\n[id]: docs/x.md", "para\n[id]: docs/x.md"),
            ("[t](docs/a\N{NO-BREAK SPACE}b.md)", "[t](" + blob + "docs/a\N{NO-BREAK SPACE}b.md)"),
            (r"[t](<docs/a\>b.md>)", "[t](<" + blob + "docs/a%3Eb.md>)"),
            ("[a [b](x)](y)", "[a [b](" + blob + "x)](y)"),
            ("<div>\n[t](docs/a.md)\n</div>", "<div>\n[t](docs/a.md)\n</div>"),
            ('text <!-- [t](docs/a.md) <img src="ignored.png"> --> end',
             'text <!-- [t](docs/a.md) <img src="ignored.png"> --> end'),
            ('text <a href="docs/a.md">[t](docs/b.md)</a>',
             'text <a href="' + blob + 'docs/a.md">[t](' + blob + 'docs/b.md)</a>'),
            ("<img src='docs/b.png'>", "<img src='" + raw + "docs/b.png'>"),
            ("[" * 5000 + "t" + "]" * 5000 + "(docs/x.md)",
             "[" * 5000 + "t" + "]" * 5000 + "(" + blob + "docs/x.md)"),
        ]
        for source, expected in cases:
            with self.subTest(source=source[:100]):
                self.assertEqual(expected, self.pin(source))

    def test_whatwg_4_1_encoded_dot_segments_reject_escapes_and_normalize(self):
        # https://url.spec.whatwg.org/#url-path-segment: dot segments include
        # case-insensitive %2e, .%2e, %2e. and %2e%2e before normalization.
        for path in ("%2e%2e/x.md", "%2e%2e/%2e%2e/x.md", "a/.%2E/../x.md"):
            for source in (f"[t]({path})", f"![t]({path})", f"[t]: {path}",
                           f'<a href="{path}">', f"<img src='{path}'>"):
                with self.subTest(source=source), self.assertRaisesRegex(ValueError, "escapes the repository"):
                    self.pin(source)
        for path in ("a/%2e%2e/x.md", "%2E/docs/x.md", "a/.%2E/x.md", "a/%2e./x.md"):
            expected = "docs/x.md" if path.startswith("%2E/") else "x.md"
            self.assertEqual("[t](https://github.com/example/library/blob/v2.3.4/" + expected + ")", self.pin(f"[t]({path})"))

    def test_commonmark_4_1_and_4_3_breaks_end_paragraphs_and_lazy_continuations(self):
        for marker in ("---", "***", "___", "* * *", "- - -", "   * * *"):
            source = "para\n\n" + marker + "\n\n    code [n](docs/x.md)"
            self.assertEqual(source, self.pin(source))
        for marker in ("---", "***", "___", "* * *", "- - -"):
            source = "- para\n" + marker + "\n\n    code [n](docs/x.md)"
            self.assertEqual(source, self.pin(source))
        for marker in ("===", "---"):
            source = "Title\n" + marker + "\n    code [n](docs/x.md)"
            self.assertEqual(source, self.pin(source))

    def test_commonmark_4_6_all_seven_html_block_kinds_and_6_6_tokens(self):
        # §4.6 types 1–7, their different endings, and §6.6 inline raw HTML.
        opaque = (
            "<script>\n[t](docs/a.md)\n\n<img src='literal.png'>\n</script>",
            "<!--\n[t](docs/a.md)\n-->", "<?\n[t](docs/a.md)\n?>",
            "<!DOCTYPE\n[t](docs/a.md)\n>", "<![CDATA[\n[t](docs/a.md)\n]]>",
            "<div>\n[t](docs/a.md)\n</div>", "<custom>\n[t](docs/a.md)\n</custom>",
            "text <!-- [t](docs/a.md) --> end", "text <? [t](docs/a.md) ?> end",
            "text <![CDATA[ [t](docs/a.md) ]]> end", "text <!A [t](docs/a.md)> end",
            '`<a href="docs/a.md">`', '    <img src="docs/b.png">',
            'text <span title="[t](docs/a.md)"> end',
        )
        for source in opaque:
            with self.subTest(source=source):
                self.assertEqual(source, self.pin(source))
        blob = "https://github.com/example/library/blob/v2.3.4/"
        raw = "https://github.com/example/library/raw/v2.3.4/"
        for source, expected in (
            ('<div>\n<a href="docs/a.md"><img src=docs/b.png>\n</div>',
             '<div>\n<a href="' + blob + 'docs/a.md"><img src=' + raw + 'docs/b.png>\n</div>'),
            ('text <a\n href="docs/a.md?a=1&amp;b=2"> end',
             'text <a\n href="' + blob + 'docs/a.md?a=1&amp;b=2"> end'),
            ('<a href="docs/a.md" title="[t](literal.md)">',
             '<a href="' + blob + 'docs/a.md" title="[t](literal.md)">'),
            ('<pre src="docs/b.png">\n[t](literal.md)\n</pre>',
             '<pre src="' + raw + 'docs/b.png">\n[t](literal.md)\n</pre>'),
            ('para\n<custom>\n[t](docs/a.md)', 'para\n<custom>\n[t](' + blob + 'docs/a.md)'),
        ):
            with self.subTest(source=source):
                self.assertEqual(expected, self.pin(source))
        for source in ('<a href="?raw=1">', '<img src="?raw=1">'):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "invalid relative link"):
                self.pin(source)

    def test_commonmark_6_3_and_6_4_nested_links_and_images(self):
        blob = "https://github.com/example/library/blob/v2.3.4/"
        raw = "https://github.com/example/library/raw/v2.3.4/"
        for source, expected in (
            ("[a [b](x)](y)", "[a [b](" + blob + "x)](y)"),
            ("![a [b](x)](y)", "![a [b](" + blob + "x)](" + raw + "y)"),
            ("[a ![b](x)](y)", "[a ![b](" + raw + "x)](" + blob + "y)"),
            ("[a [b][id]](y)\n\n[id]: x", "[a [b][id]](y)\n\n[id]: " + blob + "x"),
        ):
            with self.subTest(source=source):
                self.assertEqual(expected, self.pin(source))

    def test_commonmark_6_inlines_do_not_reparse_destinations_or_autolinks(self):
        blob = "https://github.com/example/library/blob/v2.3.4/"
        for source, expected in (
            ("[t](docs/a`b.md) `outside`", "[t](" + blob + "docs/a%60b.md) `outside`"),
            ("<https://example.com/[t](literal.md)>", "<https://example.com/[t](literal.md)>"),
            ("[a <https://example.com>](literal.md)", "[a <https://example.com>](literal.md)"),
            ("[a <team@example.com>](literal.md)", "[a <team@example.com>](literal.md)"),
            ('<a title="`">`[t](docs/a.md)', '<a title="`">`[t](' + blob + 'docs/a.md)'),
        ):
            with self.subTest(source=source):
                self.assertEqual(expected, self.pin(source))

    def test_real_changelog_pins_exact_public_destinations(self):
        source = (ROOT / "CHANGELOG.md").read_text()
        expected = source
        for path in ("docs/guides/verifying-releases.md", "docs/reference/compatibility.md",
                     "docs/guides/web-bot-auth.md", "docs/guides/phoenix-and-plug.md"):
            expected = expected.replace("](" + path + ")", "](https://github.com/example/library/blob/v2.3.4/" + path + ")")
        self.assertEqual(expected, self.pin(source))

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
            sources = {path: (self.root / path).read_text() for path in ("mix.exs", "corpus/index.json", "CHANGELOG.md")}
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
    def test_each_focused_check_has_its_own_help_option(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/check.py"), "--help"], capture_output=True, text=True, check=True, timeout=30)
        for flag in ("--ci-actions-only", "--corpus-release-only", "--package-only", "--sbom-only", "--notebooks-only"):
            self.assertRegex(result.stdout, r"(?m)^  " + flag + r"\s+")
            option = re.search(r"(?m)^  " + flag + r"\s+([\s\S]*?)(?=\n  --|\Z)", result.stdout)[1]
            help_text = " ".join(option.split())
            if flag == "--notebooks-only":
                self.assertIn("cannot combine with focused check flags", help_text)
            else:
                self.assertIn("can combine with other focused checks", help_text)
                self.assertIn("but not with --notebooks-only", help_text)

    def test_changelog_has_one_release_link_pinning_statement(self):
        current = (ROOT / "CHANGELOG.md").read_text().split("## Unreleased 2.0.0", 1)[1].split("\n## ", 1)[0]
        self.assertEqual(1, len(re.findall(r"pin(?:s)? (?:relative )?documentation links", current)))

    def test_prerelease_flag_uses_the_verified_job_output(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        verify, publish = workflow.split("\n  publish:\n")
        self.assertIn("prerelease: ${{ steps.identity.outputs.prerelease }}", verify)
        self.assertIn("PRERELEASE: ${{ needs.verify.outputs.prerelease }}", publish)
        self.assertIn('if [ "$PRERELEASE" = true ]; then\n              flags+=(--prerelease)', publish)
        self.assertIn('"${flags[@]}" "${assets[@]}"', publish)
        self.assertNotRegex(publish, r"\$\{?VERSION[^\n]*(?:rc|alpha|beta)")

    def test_existing_release_http_status_is_fail_closed_and_reused(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        publish = workflow.split("\n  publish:\n")[1]
        self.assertEqual(1, publish.count('gh api --include "repos/$GH_REPO/releases/tags/$GITHUB_REF_NAME"'))
        self.assertNotIn("gh release view", publish)
        detection = publish.split("- name: Detect existing release", 1)[1].split("- name: Compare existing", 1)[0]
        self.assertIn('if [ "$status" = 404 ]; then', detection)
        self.assertIn('gh api --paginate "repos/$GH_REPO/releases" > "$response"', detection)
        self.assertIn('select(.draft and .tag_name == $tag)', detection)
        self.assertIn('--arg tag "$GITHUB_REF_NAME"', detection)
        self.assertRegex(detection, r'Refusing to publish over draft release: \$draft[^\n]*\n\s+exit 1')
        self.assertLess(detection.index('gh api --paginate'), detection.index("echo 'exists=false'"))
        self.assertEqual(1, publish.count('id: existing'))
        self.assertIn('HTTP ${status:-unavailable}', publish)
        self.assertRegex(publish, r'HTTP \$\{status:-unavailable\}[^\n]*\n\s+exit 1')
        self.assertIn("if: steps.existing.outputs.exists == 'true'", publish)
        self.assertIn("EXISTS: ${{ steps.existing.outputs.exists }}", publish)
        self.assertIn('if [ "$EXISTS" = true ]; then', publish)
        self.assertEqual(2, publish.count("NAMES: ${{ steps.existing.outputs.names }}"))

    def test_draft_filter_executes_real_jq_on_paginated_release_lists(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        detection = workflow.split("- name: Detect existing release", 1)[1].split("- name: Compare existing", 1)[0]
        program = re.search(r"draft=\$\(jq -sr --arg tag \"\$GITHUB_REF_NAME\" '([^']+)'", detection)[1]
        # gh api --paginate emits consecutive JSON arrays, one per page.
        cases = (
            ([[{"draft": False, "tag_name": "v1.0.0", "id": 1}],
              [{"draft": True, "tag_name": "v2.0.0", "id": 2}], []], "v2.0.0\n"),
            ([[]], ""),
            ([[{"draft": False, "tag_name": "v2.0.0", "id": 3}]], ""),
            ([[{"draft": True, "tag_name": "v2.0.0", "id": 4}]], "v2.0.0\n"),
            ([[{"draft": True, "tag_name": "v2.1.0", "id": 5}]], ""),
        )
        for pages, expected in cases:
            with self.subTest(pages=pages):
                result = subprocess.run(["jq", "-sr", "--arg", "tag", "v2.0.0", program],
                                        input="\n".join(json.dumps(page) for page in pages),
                                        capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(expected, result.stdout)

    def test_sbom_platform_assets_and_aliases(self):
        platforms = (
            ("Linux", "x86_64", "mix_sbom_Linux_X64", "b490502890f692672f14619bd12798462a613ecfbab2652bd26f8c909a050fd1"),
            ("Linux", "aarch64", "mix_sbom_Linux_ARM64", "1366218a3a99cf9d1775513819808d0590b565ee18a307b48b141c8a1337e2ed"),
            ("Darwin", "x86_64", "mix_sbom_macOS_X64", "ff4cfdf710c2e2e1c9f1c57dfe2667f3a9e52b1bd2054b655e576654b9a04294"),
            ("Darwin", "arm64", "mix_sbom_macOS_ARM64", "7930b9e35dce94e16072ab75a12d4faf2c26b1664d5d2b6c040ccff6a1242f46"),
        )
        self.assertEqual(4, len(sbom.TOOL_PLATFORMS))
        for system, machine, asset, digest in platforms:
            aliases = (machine,) if machine == "x86_64" else ("arm64", "aarch64")
            for alias in aliases:
                with self.subTest(system=system, machine=alias):
                    self.assertEqual((asset, digest), sbom.tool_platform(os.uname_result((system, "", "", "", alias))))
        with self.assertRaisesRegex(ValueError, "Unsupported SBOM platform FreeBSD riscv64") as error:
            sbom.tool_platform(os.uname_result(("FreeBSD", "", "", "", "riscv64")))
        for system, machine, _, _ in platforms:
            self.assertIn(system + " " + machine, str(error.exception))

    def test_notebook_and_focused_modes_are_mutually_exclusive(self):
        for flag in ("--ci-actions-only", "--corpus-release-only", "--package-only", "--sbom-only"):
            for flags in (("--notebooks-only", flag), (flag, "--notebooks-only")):
                result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/check.py"), *flags], capture_output=True, text=True, timeout=30)
                self.assertEqual(2, result.returncode)
                self.assertIn("not allowed with argument", result.stderr)

    def test_existing_assets_are_compared_before_either_attestation(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        publish = workflow.split("\n  publish:\n")[1]
        self.assertLess(publish.index('cmp "$asset"'), publish.index("uses: actions/attest@"))
        self.assertLess(publish.rindex("uses: actions/attest@"), publish.index("gh release upload"))

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

    def test_sbom_serial_binds_package_identity_and_bytes_and_sorts_graph(self):
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
               "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"name": "request_seal", "version": "2.0.0-dev"}},
               "components": [{"bom-ref": "z", "name": "telemetry"}, {"bom-ref": "a", "name": "plug"}],
               "dependencies": [{"ref": "z", "dependsOn": ["z", "a"]}, {"ref": "a"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.cdx.json"
            path.write_text(json.dumps(bom))
            tarball = Path(directory) / "package.tar"
            tarball.write_bytes(b"package contents")
            release.normalize_sbom(path, tarball)
            first = path.read_bytes()
            normalized = json.loads(first)
            serial = uuid.UUID(normalized["serialNumber"])
            self.assertEqual(serial.urn, normalized["serialNumber"])
            self.assertEqual(5, serial.version)
            self.assertNotIn("timestamp", normalized["metadata"])
            self.assertEqual(bom["metadata"]["component"], normalized["metadata"]["component"])
            self.assertEqual(["a", "z"], [c["bom-ref"] for c in normalized["components"]])
            release.normalize_sbom(path, tarball)
            self.assertEqual(first, path.read_bytes())
            path.write_text(json.dumps(bom))
            release.normalize_sbom(path, tarball)
            self.assertEqual(first, path.read_bytes())
            tarball.write_bytes(b"different package contents")
            release.normalize_sbom(path, tarball)
            self.assertNotEqual(normalized["serialNumber"], json.loads(path.read_text())["serialNumber"])
            path.write_text(json.dumps({**bom, "specVersion": "1.5"}))
            with self.assertRaisesRegex(ValueError, "CycloneDX 1.6"):
                release.normalize_sbom(path, tarball)

    def test_untrusted_tool_bytes_are_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mix_sbom"
            path.write_bytes(b"untrusted executable bytes")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                sbom.verify_tool(path)
            self.assertEqual(0, path.stat().st_mode & 0o111)

    def test_malformed_sbom_reports_a_clear_cli_error_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sbom.json"
            path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}')
            tarball = Path(directory) / "package.tar"
            tarball.write_bytes(b"package bytes")
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/release.py"), "--normalize-sbom", str(path), "--tarball", str(tarball)], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Malformed release SBOM", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
