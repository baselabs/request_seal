"""Release safety checks against real Git repositories and artifact metadata."""
from contextlib import closing, contextmanager, redirect_stdout
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.utils import formatdate
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import sbom
import check as gate
import check_docs as docs
from processes import run, temporary_directory

@contextmanager
def local_http(responses, observed=None, response_delay=0, tls_context=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if observed is not None:
                observed.append(time.monotonic())
            sequence = responses[self.path]
            response = sequence.pop(0) if len(sequence) > 1 else sequence[0]
            if isinstance(response, tuple):
                status, headers, *bodies = response
                body = bodies[0] if bodies else b""
            else:
                status, headers, body = response, {}, b""
            if status == 0:
                self.close_connection = True
                return
            time.sleep(response_delay)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            if 300 <= status < 400 and "Location" not in headers:
                self.send_header("Location", "/ok")
            try:
                self.end_headers()
                chunks = [(0, body)] if isinstance(body, bytes) else body
                for delay, chunk in chunks:
                    time.sleep(delay)
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass  # The deadline test closes its real client socket first.

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        if tls_context is not None:
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        server.daemon_threads = False  # server_close joins every request thread.
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            scheme = "https" if tls_context is not None else "http"
            yield f"{scheme}://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            thread.join()


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
        return run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True)

    def identity(self, version):
        (self.root / "mix.exs").write_text(f'@version "{version}"\nversion: @version,\nsource_url: "https://github.com/example/library",\n')
        (self.root / "corpus/index.json").write_text(json.dumps({"elixir_release": "v" + version}))
        (self.root / "CHANGELOG.md").write_text(f"# Changelog\n\n## {version} - 2026-11-17\n\n- Release behavior.\n")

    def verify(self, event="workflow_dispatch", ref="refs/heads/main"):
        return release.verify_identity(self.root, event, ref)

    def test_dispatch_refuses_an_existing_annotated_tag_even_at_head(self):
        self.assertEqual("2.3.4", self.verify())
        self.git("tag", "-a", "v2.3.4", "-m", "Release fixture")
        with self.assertRaisesRegex(ValueError, "already tagged"):
            self.verify()

    def test_dispatch_refuses_an_existing_lightweight_tag_even_at_head(self):
        self.git("tag", "v2.3.4")
        with self.assertRaisesRegex(ValueError, "already tagged"):
            self.verify()

    def test_verify_cli_emits_version_and_semantic_prerelease_outputs(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(ROOT / "scripts/release.py", scripts / "release.py")
        shutil.copyfile(ROOT / "scripts/processes.py", scripts / "processes.py")
        for version, prerelease in (("2.0.0", "false"), ("2.0.0-rc.1", "true"), ("0.6.0", "false")):
            with self.subTest(version=version):
                self.identity(version)
                output = self.root / "github-output"
                output.write_text("")
                result = run(
                    [sys.executable, "-B", str(scripts / "release.py"), "--verify"],
                    env=dict(os.environ, GITHUB_EVENT_NAME="workflow_dispatch",
                             GITHUB_REF="refs/heads/main", DEFAULT_BRANCH="main", GITHUB_OUTPUT=str(output)),
                    capture_output=True, text=True, check=False, timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f"version={version}\nprerelease={prerelease}\n", output.read_text())

    def test_tag_at_another_commit_also_refuses_dispatch(self):
        self.git("tag", "v2.3.4")
        self.git("commit", "--quiet", "--allow-empty", "-m", "Another commit")
        with self.assertRaisesRegex(ValueError, "already tagged"):
            self.verify()

    def test_only_dispatch_of_the_explicit_default_branch_is_allowed(self):
        for event in ("push", "pull_request", "schedule", "workflow_call"):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, "workflow_dispatch"):
                self.verify(event, "refs/heads/main")
        for ref in ("refs/tags/v2.3.4", "refs/heads/topic", "refs/heads/main/other", ""):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "default branch"):
                self.verify(ref=ref)
        self.assertEqual("2.3.4", release.verify_identity(self.root, "workflow_dispatch", "refs/heads/trunk", "trunk"))
        with self.assertRaisesRegex(ValueError, "default branch"):
            release.verify_identity(self.root, "workflow_dispatch", "refs/heads/main", "")

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
        with self.assertRaisesRegex(ValueError, "dated section|ambiguous release heading"):
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

    def test_stale_corpus_and_unexpected_event_are_refused(self):
        (self.root / "corpus/index.json").write_text('{"elixir_release":"v2.3.3"}')
        with self.assertRaisesRegex(ValueError, "elixir_release"):
            self.verify()
        self.identity("2.3.4")
        with self.assertRaisesRegex(ValueError, "workflow_dispatch"):
            self.verify("pull_request")

    def test_release_notes_are_verbatim_with_literal_absolute_destinations(self):
        body = ('### Changed\n\n'
                '-  Keep **wording**, `code`, &copy; and trailing spaces.  \n'
                '[Guide](https://request-seal.hexdocs.pm/2.3.4/web-bot-auth.html#replay)\n'
                '[Source](<https://github.com/baselabs/request_seal/blob/v2.3.4/README.md> "Read me")\n'
                '![Asset](https://raw.githubusercontent.com/baselabs/request_seal/v2.3.4/image.png)\n'
                '[External](https://www.rfc-editor.org/rfc/rfc9421.html#section-2)\n'
                '[Advisory](https://github.com/baselabs/request_seal/security/advisories/GHSA-vj55-78vg-59wf)\n'
                '[Query](https://example.com/a%28b%29?q=1&next=2)\n'
                '[Mail](mailto:security@example.com) [Reference][guide]\n\n'
                '[guide]: https://request-seal.hexdocs.pm/2.3.4/compatibility.html "Policy"\n'
                '[Example](https://example.com/comment)\n'
                '```markdown\n[Example](https://example.com/code)\n```\n')
        source = '## Unreleased 2.4.0\n\n[Pending](relative.md)\n\n## 2.3.4 - 2026-11-17\n\n' + body + '\n'
        self.assertEqual(body, release.release_notes(source, "2.3.4"))
        self.assertEqual(body, release.release_notes(source.replace("\n", "\r\n"), "2.3.4"))

    def test_every_visible_destination_is_checked_in_containers_and_comments(self):
        targets = ("docs/x.md", "", "#fragment", "?q=1", "//example.com/x", "custom:opaque",
                   "https://", "https://example.com:bad/x", "https://user@example.com/x",
                   "https://%68exdocs.pm/request_seal/1.0.0/web-bot-auth.html",
                   "https://hexdocs.pm./request_seal/1.0.0/web-bot-auth.html",
                   "https://hexdocs.pm/request_seal/1.0.0/web-bot-auth.html",
                   "https://request-seal.hexdocs.pm/1.0.0/web-bot-auth.html",
                   "https://request-seal.hexdocs.pm/web-bot-auth.html",
                   "https://raw.githubusercontent.com/baselabs/request_seal/main/README.md",
                   "https://github.com/baselabs/request_seal/blob/main/README.md",
                   "https://github.com/baselabs/request_seal/raw/v2.3.3/image.png",
                   "https://github.com/baselabs/request_seal/tree/v2.3.4/docs",
                   "https://hexdocs.pm/request_seal/2.3.4/%2e%2e/compatibility.html")
        prose = ("{}", "> {}", "- Outer\n    - {}")
        comments = ("<!-- {} -->", "<!--> {}", "<!---> {}")
        containers = prose + tuple(container.format(comment) for container in prose for comment in comments)
        for target in targets:
            for link in (f"[link]({target})", f"![image]({target})", f"[ref]: {target}",
                         f'<a href="{target}">link</a>', f"<img src='{target}'>"):
                for container in containers:
                    with self.subTest(target=target, container=container, link=link):
                        body = container.format(link)
                        with self.assertRaises(ValueError) as raised:
                            release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4")
                        message = str(raised.exception)
                        self.assertRegex(message, r"CHANGELOG.md:\d+:")
                        if "<!--" in body:
                            number = 3 + body[:body.index("<!--")].count("\n")
                            self.assertEqual(f"CHANGELOG.md:{number}: unsupported HTML comment; use prose outside comments", message)
                        else:
                            self.assertRegex(message, "destination|ambiguous reference definition")
                            self.assertIn(target, message)

    def test_visible_comments_and_quotes_are_still_checked(self):
        for container in ("{}", "> {}", "- {}", "- Outer\n    - {}"):
            for comment in ("<!-- [bad](relative.md) -->", "<!--> [bad](relative.md)", "<!---> [bad](relative.md)"):
                body = "- Intro.\n\n" + container.format(comment)
                number = 5 + container.count("\n")
                message = f"CHANGELOG.md:{number}: unsupported HTML comment; use prose outside comments"
                with self.subTest(body=body), self.assertRaisesRegex(ValueError, "^" + re.escape(message) + "$"):
                    release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4")
        body = "- Intro.\n\n> [bad](relative.md)"
        with self.assertRaisesRegex(ValueError, "CHANGELOG.md:5: destination 'relative.md'"):
            release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4")

    def test_raw_html_and_ambiguous_destinations_are_rejected(self):
        for body in ('<a href="https://example.com/a">link</a>', '<img src="https://example.com/a">',
                     '<div>Example</div>', '<?instruction?>', '<![CDATA[example]]>',
                     '[x](<https://example.com/a b>)', '[x](https://example.com/a(b))',
                     r'[x](https://example.com/a\)b)', '[x](https://example.com/a?x=1&amp;y=2)',
                     '[x](https://example.com/%zz)', '[x] (https://example.com/a)',
                     '[x](\nhttps://example.com/a)', '[ref]:\n  https://example.com/a',
                     '[ref]: https://example.com/a "title" trailing', '[x](relative<path)',
                     '[x](): malformed', '[ref]: <relative>'):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, r"CHANGELOG.md:3:"):
                release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4")

    def test_section_format_rejects_ambiguous_boundaries(self):
        for suffix in ('\n\n## 2.3.4 - 2026-11-17\n\n- Duplicate.',
                       '\n\n```markdown\n## 2.3.3 - 2026-11-16',
                       '\n\n  ## 2.3.3 - 2026-11-16', '\n\n> ## 2.3.3 - 2026-11-16',
                       '\n\n- ```markdown', '\n\n    ~~~', '\n\n```a`b', '\n\n- > ```markdown',
                       '\n\n<!--\n## 2.3.3 - 2026-11-16\n-->',
                       '\n## 2.3.3 - 2026-11-16\n\n- Missing blank.',
                       '\n\n## An ambiguous heading'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                release.release_notes("## 2.3.4 - 2026-11-17\n\n- Released." + suffix, "2.3.4")
        for fence in ("```", "~~~~"):
            body = f"- Released.\n\n{fence}markdown\n## Unreleased 2.4.0\n## 2.3.3 - 2026-11-16\n{fence + fence[0]}\n"
            self.assertEqual(body, release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4"))
        with self.assertRaisesRegex(ValueError, "unsupported raw HTML"):
            release.release_notes("<div>\n\n## 2.3.4 - 2026-11-17\n\n- Ambiguous HTML section.\n", "2.3.4")

    def test_all_release_entry_points_share_the_same_gate(self):
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/release.py", self.root / "scripts/release.py")
        shutil.copyfile(ROOT / "scripts/processes.py", self.root / "scripts/processes.py")
        valid = "https://request-seal.hexdocs.pm/2.3.4/compatibility.html"
        for target in (valid, "relative.md", "", "#frag", "https://hexdocs.pm/request_seal/1.0.0/compatibility.html"):
            body = f"- [Policy]({target})\n"
            source = "## 2.3.4 - 2026-11-17\n\n" + body
            (self.root / "CHANGELOG.md").write_text(source)
            sources = {path: (self.root / path).read_text() for path in ("mix.exs", "corpus/index.json", "CHANGELOG.md")}
            with self.subTest(target=target):
                if target == valid:
                    self.assertEqual(body, release.release_notes(source, "2.3.4"))
                    self.assertEqual("2.3.4", self.verify())
                    self.assertEqual([], gate.corpus_release_errors(sources))
                else:
                    with self.assertRaises(ValueError) as raised:
                        release.release_notes(source, "2.3.4")
                    message = str(raised.exception)
                    self.assertEqual([message], gate.corpus_release_errors(sources))
                    with self.assertRaisesRegex(ValueError, re.escape(message)):
                        self.verify()
                for arguments in (("--release-notes", "--for-version", "2.3.4"),
                                  ("--verify", "--notes-file", str(self.root / "notes.md"))):
                    result = run([sys.executable, "-B", str(self.root / "scripts/release.py"), *arguments],
                                            env=dict(os.environ, GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/heads/main", DEFAULT_BRANCH="main"),
                                            capture_output=True, text=True, check=False, timeout=30)
                    self.assertEqual(target == valid, result.returncode == 0, result.stderr)
                    if target != valid:
                        self.assertEqual(message + "\n", result.stderr)
                if target == valid:
                    self.assertEqual(body, (self.root / "notes.md").read_text())

    def test_real_historical_notes_and_finalized_release_are_verbatim(self):
        source = (ROOT / "CHANGELOG.md").read_text()
        body = source.split("## 1.0.0 - 2026-11-11\n", 1)[1].split("\n## ", 1)[0].strip("\n") + "\n"
        self.assertEqual(body, release.release_notes(source, "1.0.0"))
        self.assertEqual(4, body.count("https://request-seal.hexdocs.pm/1.0.0/"))
        finalized = source.replace("## Unreleased 2.0.0", "## 2.0.0 - 2026-11-17").replace(
            "https://github.com/baselabs/request_seal/blob/main/docs/guides/verifying-releases.md",
            "https://request-seal.hexdocs.pm/2.0.0/verifying-releases.html")
        expected = finalized.split("## 2.0.0 - 2026-11-17\n", 1)[1].split("\n## ", 1)[0].strip("\n") + "\n"
        self.assertEqual(expected, release.release_notes(finalized, "2.0.0"))

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


    def test_dispatch_resolves_future_tagged_source_and_raw_assets_in_head(self):
        self.assertFalse(docs.ref_exists(self.root, "refs/tags/v2.3.4"))
        for base in ("https://github.com/baselabs/request_seal/blob/v2.3.4/",
                     "https://raw.githubusercontent.com/baselabs/request_seal/v2.3.4/"):
            with self.subTest(base=base):
                release.verify_published_destinations(f"[Source]({base}mix.exs)", "2.3.4",
                                                      event="workflow_dispatch", root=self.root)
                for path in ("missing.md", "corpus"):
                    with self.assertRaisesRegex(ValueError, "missing or nonregular file in HEAD"):
                        release.verify_published_destinations(f"[Source]({base}{path})", "2.3.4",
                                                              event="workflow_dispatch", root=self.root)
        (self.root / "uncommitted.md").write_text("not in HEAD")
        (self.root / "symlink.md").symlink_to("mix.exs")
        self.git("add", "symlink.md")
        self.git("commit", "--quiet", "-m", "Add symlink")
        for path in ("uncommitted.md", "symlink.md"):
            with self.assertRaisesRegex(ValueError, "missing or nonregular file in HEAD"):
                release.verify_published_destinations(
                    f"[Source](https://github.com/baselabs/request_seal/blob/v2.3.4/{path})",
                    "2.3.4", event="workflow_dispatch", root=self.root)

    def test_source_fragments_resolve_against_the_dispatch_head_line_count(self):
        target = "https://github.com/baselabs/request_seal/blob/v2.3.4/mix.exs"
        for fragment in ("#L1", "#L1-L2"):
            release.verify_published_destinations(f"[Source]({target}{fragment})", "2.3.4", "workflow_dispatch", self.root)
        for fragment in ("#L9999", "#L2-L1"):
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "line count"):
                release.verify_published_destinations(f"[Source]({target}{fragment})", "2.3.4", "workflow_dispatch", self.root)

    def test_compare_requires_an_existing_ancestor_tag_in_dispatch(self):
        body = "https://github.com/baselabs/request_seal/compare/v2.3.3...v2.3.4"
        with self.assertRaisesRegex(ValueError, "base tag is missing"):
            release.verify_published_destinations(body, "2.3.4", "workflow_dispatch", self.root)
        self.git("tag", "v2.3.3")
        release.verify_published_destinations(body, "2.3.4", "workflow_dispatch", self.root)
        self.git("checkout", "--quiet", "--orphan", "unrelated")
        self.git("commit", "--quiet", "-m", "Unrelated history")
        with self.assertRaisesRegex(ValueError, "not an ancestor"):
            release.verify_published_destinations(body, "2.3.4", "workflow_dispatch", self.root)

    def test_prepublication_current_hex_package_requires_no_network_requests(self):
        # Audit the real code in a separate interpreter so the observer is removed
        # with the process. No HTTP client or classifier is replaced.
        self.identity("1.0.0")
        script = '''import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import release, check_docs, check
root = Path(sys.argv[2])
requests = []
sys.addaudithook(lambda event, args: requests.append(event) if event in
                ("socket.connect", "socket.getaddrinfo", "urllib.Request") else None)
target = "https://hex.pm/packages/request_seal/1.0.0"
source = "## 1.0.0 - 2026-11-17\\n\\n- " + target + "\\n"
notes = release.release_notes(source, "1.0.0")
sources = {name: (root / name).read_text() for name in ("mix.exs", "corpus/index.json")}
sources["CHANGELOG.md"] = source
assert check.corpus_release_errors(sources) == []
assert check_docs.first_party_link_errors(root, "README.md", target, "1.0.0", set(), {}) == []
print("NETWORK_EVENTS=" + json.dumps(requests))
'''
        result = run([sys.executable, "-B", "-c", script, ROOT / "scripts", self.root],
                     capture_output=True, text=True, timeout=30)
        self.assertIn("NETWORK_EVENTS=[]", result.stdout)
        for target in ("https://hex.pm/packages/request-seal/1.0.0",
                       "https://hex.pm/packages/request_seal/2.0.0"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "canonical|version 1.0.0"):
                release.release_destinations(target, "1.0.0")

    def test_dispatch_and_push_fetch_the_current_hex_package_page_live(self):
        self.identity("1.0.0")
        target = "https://hex.pm/packages/request_seal/1.0.0"
        for event in ("workflow_dispatch", "push"):
            output = io.StringIO()
            with self.subTest(event=event), redirect_stdout(output):
                release.verify_published_destinations(target, "1.0.0", event, self.root, deadline_seconds=20)
            self.assertIn("HTTP 200 " + target, output.getvalue())


class DestinationRegressionTest(unittest.TestCase):
    def test_bare_url_candidates_include_quotes_backticks_and_non_ascii(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        for suffix in ("'s", '"s', "`", "\N{NO-BREAK SPACE}next"):
            with self.subTest(suffix=suffix):
                candidate = target + suffix
                self.assertEqual([candidate], [value for _, value, _ in release.extract_destinations(candidate)])
                for classify in (release.classify_destination,
                                 lambda value: release.validate_destination(value, "2.3.4")):
                    with self.assertRaisesRegex(ValueError, "canonical form: https://request-seal.hexdocs.pm/"):
                        classify(candidate)
        for quote in ("'", '"'):
            with self.subTest(quote=quote):
                body = quote + target + quote
                self.assertEqual([target], release.release_destinations(body, "2.3.4"))

    def test_code_spans_cannot_pair_across_block_boundaries(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        for body in (f"- Renamed `a to b\n- See {target} for `details`.",
                     f"### Changed `x\n- See {target} for `details`.",
                     f"Paragraph `x\n\nSee {target} for `details`.",
                     f"Title `x\n===\nSee {target} for `details`."):
            with self.subTest(body=body):
                self.assertEqual([target], release.release_destinations(body, "2.3.4"))
        self.assertEqual([], release.release_destinations(f"`text\n{target}`", "2.3.4"))
        self.assertEqual([target], release.release_destinations(f"Unclosed `` text {target}", "2.3.4"))

    def test_escaped_backticks_cannot_open_code_spans(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        body = f"- Escaped \\` then {target} and `code`."
        self.assertEqual([target], release.release_destinations(body, "2.3.4"))
        self.assertEqual([], release.release_destinations(f"Two slashes \\\\`{target}`", "2.3.4"))
        # Within a span a backslash does not escape its closing delimiter.
        self.assertEqual([target], release.release_destinations(f"`code\\` {target}", "2.3.4"))

    def test_only_the_first_backtick_of_an_escaped_run_is_escaped(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        body = f"- \\``a` {target} `b`"
        self.assertEqual([target], release.release_destinations(body, "2.3.4"))
        self.assertEqual([], release.release_destinations(f"\\```{target}``", "2.3.4"))

    def test_code_spans_cannot_pair_across_table_cells(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        for header, delimiter in ((f"| `x | {target} | `y |", "|---|---|---|"),
                                  (f"`x | {target} | `y", "---|---|---")):
            body = header + "\n" + delimiter + "\n| a | b | c |"
            with self.subTest(header=header):
                self.assertEqual([target], release.release_destinations(body, "2.3.4"))

    def test_code_spans_cannot_pair_across_table_rows(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        for body in (f"| a `x | b |\n|---|---|\n| {target} | `y |",
                     f"| a | b |\n|---|---|\n| `x | a |\n| {target} | `y |",
                     f"`x\n:-\n{target}\n`y"):
            with self.subTest(body=body):
                self.assertEqual([target], release.release_destinations(body, "2.3.4"))

    def test_escaped_table_pipes_and_ordinary_prose_preserve_code_spans(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        for body in (f"| `a\\| {target}` | b |\n|---|---|\n| a | b |",
                     f"`a | {target} | b`", f"`a |\n{target}\n| b`"):
            with self.subTest(body=body):
                self.assertEqual([], release.release_destinations(body, "2.3.4"))
        visible = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        for slashes in ("\\", "\\\\", "\\\\\\"):
            body = f"| `a{slashes}| {target}` | `x |\n|---|---|\n| {visible} | `y |"
            with self.subTest(slashes=slashes):
                self.assertEqual([visible], release.release_destinations(body, "2.3.4"))

    def test_whitespace_separates_shortcuts_from_full_references(self):
        for separator in (" ", "\n"):
            body = "[RFC 9421]" + separator + "[section 2]"
            self.assertEqual([], release.release_destinations(body, "2.3.4"))
            for definitions, targets in (
                ("[RFC 9421]: https://example.com/rfc", ["https://example.com/rfc"]),
                ("[RFC 9421]: https://example.com/rfc\n[section 2]: https://example.com/section",
                 ["https://example.com/rfc", "https://example.com/section"]),
            ):
                self.assertEqual(targets, release.release_destinations(body + "\n\n" + definitions, "2.3.4"))
        with self.assertRaisesRegex(ValueError, "reference 'b' requires a definition"):
            release.release_destinations("[a][b]", "2.3.4")

    def test_literal_label_before_an_inline_link_does_not_form_a_full_reference(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        self.assertEqual([target], release.release_destinations(f"[a][b]({target})", "2.3.4"))
        with self.assertRaisesRegex(ValueError, "canonical"):
            release.release_destinations("[a][b](https://hexdocs.pm/request_seal/2.3.4/readme.html)", "2.3.4")

    def test_hyphenated_paths_are_first_party_and_require_canonical_spelling(self):
        for target, canonical in (
            ("https://github.com/baselabs/request-seal/blob/v2.3.4/mix.exs",
             "https://github.com/baselabs/request_seal/blob/v2.3.4/<path>"),
            ("https://hexdocs.pm/request-seal/2.3.4/readme.html",
             "https://request-seal.hexdocs.pm/2.3.4/<page>"),
            ("https://hex.pm/packages/request-seal/2.3.4", "https://hex.pm/packages/request_seal/2.3.4"),
        ):
            with self.subTest(target=target):
                self.assertIsNotNone(release.first_party(release.urlsplit(target)))
                with self.assertRaisesRegex(ValueError, re.escape(canonical)):
                    release.validate_destination(target, "2.3.4")
        self.assertEqual("hexdocs", release.classify_destination("https://request-seal.hexdocs.pm/2.3.4/readme.html")["kind"])

    def test_link_occupied_range_starts_at_its_own_matched_bracket(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/missing.html"
        body = f"- [x] see {target} foo](https://example.com)"
        self.assertEqual([target, "https://example.com"], release.release_destinations(body, "2.3.4"))

    def test_heading_end_is_a_valid_reference_definition_boundary(self):
        for heading in ("### Links", "Links\n====", "Links\n----", "`Links`\n===="):
            with self.subTest(heading=heading):
                self.assertEqual(["https://example.com"], release.release_destinations(
                    heading + "\n[g]: https://example.com\n\nUse [g].", "2.3.4"))

    def test_setext_underline_requires_a_preceding_paragraph_line(self):
        for prefix in ("Para\n\n===", "===", "Para\n\n--", "### Heading\n===",
                       "[other]: https://example.com\n===", "```text\ncode\n```\n==="):
            # Keep the earlier definition used so the failure isolates the
            # missing paragraph before the setext-shaped underline.
            body = prefix + "\n[g]: https://example.com\n\nUse [g]. [other]"
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, "ambiguous reference definition"):
                release.release_destinations(body, "2.3.4")
        # A standalone thematic break remains a real block boundary.
        self.assertEqual(["https://example.com"], release.release_destinations(
            "Para\n\n---\n[g]: https://example.com\n\nUse [g].", "2.3.4"))

    def test_footnote_definitions_can_interrupt_a_paragraph(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        self.assertEqual([], release.release_destinations("Note[^1].\n[^1]: text", "2.3.4"))
        self.assertEqual([target], release.release_destinations(f"Note[^1].\n[^1]: See {target}", "2.3.4"))

    def test_footnotes_require_unique_section_local_definitions(self):
        self.assertEqual([], release.release_destinations("- Note[^one].\n\n[^one]: Explanation.", "2.3.4"))
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        self.assertEqual([target], release.release_destinations(f"Note[^one].\n\n[^one]: See {target}", "2.3.4"))
        with self.assertRaisesRegex(ValueError, "footnote.*requires a definition inside"):
            release.release_destinations("Note[^one].", "2.3.4")
        with self.assertRaisesRegex(ValueError, "duplicate footnote definition"):
            release.release_destinations("Note[^one].\n\n[^one]: First.\n[^one]: Second.", "2.3.4")
        source = ("## 2.3.4 - 2026-11-17\n\nNote[^one].\n\n"
                  "## 2.3.3 - 2026-11-16\n\n[^one]: Other section.\n")
        with self.assertRaisesRegex(ValueError, "footnote.*requires a definition inside"):
            release.release_notes(source, "2.3.4")

    def test_rendered_markup_blobs_reject_line_fragments(self):
        for extension in (".md", ".markdown", ".livemd", ".rst", ".adoc", ".rdoc", ".mdx", ".rst.txt"):
            target = "https://github.com/baselabs/request_seal/blob/v2.3.4/file" + extension
            with self.subTest(extension=extension), self.assertRaisesRegex(ValueError, "line fragments.*rendered markup"):
                release.validate_destination(target + "#L1", "2.3.4")
            self.assertEqual("github", release.validate_destination(target, "2.3.4"))
        self.assertEqual("github", release.validate_destination(
            "https://github.com/baselabs/request_seal/blob/v2.3.4/mix.exs#L1", "2.3.4"))

    def test_scheme_case_requires_the_canonical_form(self):
        with self.assertRaisesRegex(ValueError, "canonical form: https://request-seal.hexdocs.pm/"):
            release.classify_destination("HTTPS://request-seal.hexdocs.pm/2.3.4/readme.html")

    def test_redirect_failure_does_not_skip_the_next_target(self):
        output = io.StringIO()
        with local_http({"/a-redirect": [302], "/z-ok": [200]}) as (base, requests):
            with redirect_stdout(output), self.assertRaises(ValueError) as raised:
                release.verify_http_destinations([base + "/a-redirect", base + "/z-ok"], deadline_seconds=2)
            self.assertEqual(["/a-redirect", "/z-ok"], requests)
            self.assertIn(f"{base}/a-redirect: HTTP 302", str(raised.exception))
            self.assertIn(base + "/z-ok: HTTP 200", str(raised.exception))
            self.assertIn(f"HTTP 200 {base}/z-ok", output.getvalue())

    def test_decode_failure_does_not_skip_the_next_target(self):
        with local_http({"/a-invalid": [(200, {}, b"\xff")], "/z-ok": [200]}) as (base, requests):
            with self.assertRaisesRegex(ValueError, "response decode error: UnicodeDecodeError") as raised:
                release.verify_http_destinations([base + "/a-invalid#fragment", base + "/z-ok"], deadline_seconds=2)
            self.assertEqual(["/a-invalid", "/z-ok"], requests)
            self.assertIn(base + "/z-ok: HTTP 200", str(raised.exception))

    def test_slow_drip_body_cannot_extend_the_read_deadline(self):
        body = [(0.02, b"x")] * 100
        with local_http({"/drip": [(200, {}, body)]}) as (base, requests):
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "destination deadline exceeded while reading response body"):
                release.verify_http_destinations([base + "/drip#missing"], deadline_seconds=0.15)
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(["/drip"], requests)

    def test_body_reads_refresh_the_public_connection_socket_timeout(self):
        with local_http({"/body": [(200, {"Content-Length": "2"}, b"ok")]}) as (base, requests):
            url = release.urlsplit(base)
            with closing(HTTPConnection(url.hostname, url.port, timeout=10)) as connection:
                connection.request("GET", "/body")
                sock = connection.sock
                with connection.getresponse() as response:
                    self.assertEqual(b"ok", release.read_response_body(
                        response, sock, time.monotonic() + 0.5, collect=True))
                self.assertGreater(sock.gettimeout(), 0)
                self.assertLessEqual(sock.gettimeout(), 0.5)
            self.assertEqual(["/body"], requests)

    def test_truncated_body_is_a_transport_failure_and_is_retried(self):
        with local_http({"/truncated": [(200, {"Content-Length": "20"}, b"partial"), 200]}) as (base, requests):
            release.verify_http_destinations([base + "/truncated"], deadline_seconds=4)
            self.assertEqual(["/truncated", "/truncated"], requests)

    def test_issue_number_redirect_names_its_pull_request_url(self):
        path = "/baselabs/request_seal/issues/12"
        pull = "https://github.com/baselabs/request_seal/pull/12"
        with local_http({path: [(302, {"Location": pull})]}) as (base, requests):
            with self.assertRaisesRegex(ValueError, re.escape("use " + pull)):
                release.verify_http_destinations([base + path], deadline_seconds=2)
            self.assertEqual([path], requests)


class ReleaseWorkflowTest(unittest.TestCase):
    def test_each_focused_check_has_its_own_help_option(self):
        result = run([sys.executable, "-B", str(ROOT / "scripts/check.py"), "--help"], capture_output=True, text=True, check=True, timeout=30)
        for flag in ("--ci-actions-only", "--corpus-release-only", "--package-only", "--sbom-only", "--notebooks-only"):
            self.assertRegex(result.stdout, r"(?m)^  " + flag + r"\s+")
            option = re.search(r"(?m)^  " + flag + r"\s+([\s\S]*?)(?=\n  --|\Z)", result.stdout)[1]
            help_text = " ".join(option.split())
            if flag == "--notebooks-only":
                self.assertIn("cannot combine with focused check flags", help_text)
            else:
                self.assertIn("can combine with other focused checks", help_text)
                self.assertIn("but not with --notebooks-only", help_text)

    def test_changelog_states_verbatim_release_notes_and_versioned_documentation(self):
        current = (ROOT / "CHANGELOG.md").read_text().split("## Unreleased 2.0.0", 1)[1].split("\n## ", 1)[0]
        self.assertIn("Release notes are the CHANGELOG section\n  verbatim, and documentation links are versioned.", current)
        self.assertNotIn("CommonMark", current)

    def test_destination_readback_follows_upload_and_hex_byte_comparison(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text()
        command = 'python3 scripts/release.py --check-destinations --for-version "$VERSION"'
        readback = 'python3 scripts/publication.py --verify-registry --version "$VERSION"'
        self.assertLess(workflow.index("run: mix run --no-mix-exs"), workflow.index(readback))
        self.assertLess(workflow.index(readback), workflow.index(command))
        self.assertIn(command + " --destination-event workflow_dispatch", workflow)
        self.assertNotIn("--destination-event push", workflow)
        self.assertIn("python3 scripts/release.py --verify --notes-file release-notes.md", workflow)
        self.assertIn("fetch-depth: 0", (ROOT / ".github/workflows/ci.yml").read_text())
        runbook = (ROOT / "docs/operations/releases.md").read_text()
        for contract in ("verbatim", "same line", "inside fences", "no CommonMark conformance claim",
                         "Each real HTTP GET must return 200", "own release notes", "Code spans and code blocks"):
            self.assertIn(contract, runbook)

    def test_postpublication_check_uses_real_http_and_rejects_a_missing_page(self):
        output = io.StringIO()
        with redirect_stdout(output):
            release.verify_published_destinations(
                "[Source](https://github.com/baselabs/request_seal/blob/v1.0.0/README.md)", "1.0.0", event="push")
        self.assertIn("HTTP 200 https://github.com/baselabs/request_seal/blob/v1.0.0/README.md", output.getvalue())
        with self.assertRaisesRegex(ValueError, "HTTP 404"):
            release.verify_published_destinations(
                "[Missing](https://request-seal.hexdocs.pm/1.0.0/no-such-release-page.html)",
                "1.0.0")

    def test_only_canonical_first_party_forms_pass_the_offline_gate(self):
        for target in ("https://request-seal.hexdocs.pm/2.3.4/RequestSeal.html",
                       "https://github.com/baselabs/request_seal/blob/v2.3.4/README.md",
                       "https://raw.githubusercontent.com/baselabs/request_seal/v2.3.4/README.md"):
            self.assertTrue(release.validate_destination(target, "2.3.4"))
        for target, canonical in (
            ("https://hexdocs.pm/request_seal/2.3.4/compatibility.html", "https://request-seal.hexdocs.pm/2.3.4/<page>"),
            ("https://github.com/baselabs/request_seal/raw/v2.3.4/README.md", "https://github.com/baselabs/request_seal/blob/v2.3.4/<path>"),
        ):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, re.escape(canonical)):
                release.validate_destination(target, "2.3.4")

    def test_autolinks_and_bare_urls_follow_the_same_destination_rules_everywhere(self):
        prose = ("{}", "> {}", "- {}")
        comments = ("<!-- {} -->", "<!--> {}", "<!---> {}")
        for container in prose + tuple(outer.format(comment) for outer in prose for comment in comments):
            for target in ("https://github.com/baselabs/request_seal/blob/main/README.md",
                           "http://request-seal.hexdocs.pm/2.3.4/readme.html",
                           "www.github.com/baselabs/request_seal/blob/v2.3.4/README.md",
                           "WWW.GITHUB.COM/baselabs/request_seal/blob/v2.3.4/README.md",
                           "https://hexdocs.pm/request_seal/2.3.4/readme.html"):
                for occurrence in (target, "<" + target + ">"):
                    body = container.format(occurrence)
                    reason = "unsupported HTML comment; use prose outside comments" if "<!--" in body else "destination"
                    with self.subTest(body=body), self.assertRaisesRegex(ValueError, re.escape("CHANGELOG.md:3: " + reason)):
                        release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4")
        for target in ("mailto:security@example.com", "custom:opaque", "http://example.com/a"):
            with self.subTest(target=target):
                body = "<" + target + ">"
                if target.startswith("custom"):
                    with self.assertRaises(ValueError):
                        release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4")
                else:
                    self.assertEqual(body + "\n", release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4"))

    def test_indented_closing_fence_cannot_swallow_the_next_release(self):
        for closing in ("   ```", " ```", "  ```", "- ```", "  1. ```", "> ```",
                        "- [ ] ```", "- [x] ```", "  1. [X] ```"):
            source = ("## 2.3.4 - 2026-11-17\n\n- Released.\n\n```text\ncode\n" + closing
                      + "\n\n## 2.3.3 - 2026-11-16\n\n- Old.\n")
            with self.subTest(closing=closing), self.assertRaisesRegex(ValueError, "CHANGELOG.md:7:.*fence"):
                release.release_notes(source, "2.3.4")
        self.assertTrue(release.release_notes((ROOT / "CHANGELOG.md").read_text(), "1.0.0"))

    def test_first_party_classification_cannot_be_bypassed_by_normalization(self):
        targets = (
            "https://hexdocs.pm/Request_Seal/1.0.0/readme.html",
            "https://www.github.com/baselabs/request_seal/blob/main/README.md",
            "https://github.com/baselabs/./request_seal/blob/v2.3.4/README.md",
            "https://hexdocs.pm/x/../request_seal/2.3.4/readme.html",
            "https://hexdocs.pm/request_seal/../other/2.3.4/readme.html",
            "https://github.com/baselabs/request_seal/../other/blob/v2.3.4/README.md",
            "https://GITHUB.COM/BaseLabs/Request_Seal/blob/v2.3.4/README.md",
            "https://request-seal.hexdocs.pm/2.3.4/%72eadme.html",
            "https://github.com/baselabs/%72equest_seal/blob/v2.3.4/README.md",
            "https://user@github.com/baselabs/request_seal/blob/v2.3.4/README.md",
            "https://github.com:443/baselabs/request_seal/blob/v2.3.4/README.md",
            "https://www.request-seal.hexdocs.pm/2.3.4/readme.html",
            "https://RAW.GITHUBUSERCONTENT.COM/baselabs/request_seal/v2.3.4/README.md",
        )
        for target in targets:
            with self.subTest(target=target):
                self.assertIsNotNone(release.first_party(release.urlsplit(target)))
                with self.assertRaises(ValueError):
                    release.release_notes("## 2.3.4 - 2026-11-17\n\n" + target, "2.3.4")
                self.assertTrue(docs.first_party_link_errors(ROOT, "README.md", release.urlsplit(target), "2.3.4", set(), {}))

    def test_references_must_resolve_inside_the_released_section(self):
        for use in ("[Guide][policy]", "[policy][]", "[policy]", "![Guide][policy]", "![policy][]", "![policy]"):
            for outside in ("before", "after"):
                definition = "[POLICY]: https://example.com/policy\n"
                body = "- " + use + "\n"
                source = "## 2.3.4 - 2026-11-17\n\n" + body
                if outside == "before":
                    source = definition + "\n" + source
                    line = 5
                else:
                    source += "\n## 2.3.3 - 2026-11-16\n\n" + definition
                    line = 3
                with self.subTest(use=use, outside=outside), self.assertRaisesRegex(ValueError, f"CHANGELOG.md:{line}: reference"):
                    release.release_notes(source, "2.3.4")
                self.assertEqual(body + "\n" + definition, release.release_notes(
                    "## 2.3.4 - 2026-11-17\n\n" + body + "\n" + definition, "2.3.4"))
        for use in ("[Guide][missing]", "[missing][]",
                    "[][missing]", "![][missing]", "[][]", "![][]"):
            with self.assertRaisesRegex(ValueError, "CHANGELOG.md:3: reference"):
                release.release_notes("## 2.3.4 - 2026-11-17\n\n" + use, "2.3.4")
        self.assertEqual("- Literal [brackets].\n", release.release_notes(
            "## 2.3.4 - 2026-11-17\n\n- Literal [brackets].", "2.3.4"))

    def test_live_http_retries_propagation_but_never_redirects(self):
        with local_http({"/propagating": [404, 503, 200], "/redirect": [301], "/ok": [200]}) as (base, requests):
            release.verify_http_destinations([base + "/propagating"], deadline_seconds=5)
            self.assertEqual(3, requests.count("/propagating"))
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "HTTP 301"):
                release.verify_http_destinations([base + "/redirect"], deadline_seconds=5)
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(1, requests.count("/redirect"))
            self.assertNotIn("/ok", requests)

    def test_live_http_reports_all_failures_and_honors_one_total_deadline(self):
        with local_http({"/missing": [404], "/unavailable": [503], "/bad": [400], "/transport": [0, 200]}) as (base, requests):
            release.verify_http_destinations([base + "/transport"], deadline_seconds=3)
            self.assertEqual(2, requests.count("/transport"))
            started = time.monotonic()
            with self.assertRaises(ValueError) as raised:
                release.verify_http_destinations([base + path for path in ("/missing", "/unavailable", "/bad")], deadline_seconds=1.2)
            for path, status in (("/missing", 404), ("/unavailable", 503), ("/bad", 400)):
                self.assertIn(f"{base}{path}: HTTP {status}", str(raised.exception))
            self.assertEqual(1, requests.count("/bad"))
            self.assertLess(time.monotonic() - started, 2)

    def test_gfm_bare_destinations_strip_only_extended_autolink_suffixes(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        for suffix in ("?", "!", ".", ",", ":", "*", "_", "~", "'", '"', ";", ")", "&copy;", "&ABC;", "**).", "';&copy;\""):
            with self.subTest(suffix=suffix):
                self.assertEqual([target], release.release_destinations(target + suffix, "2.3.4"))
        for wrapper in ("**{}**", "_{}_", "~~{}~~", "<{}>"):
            self.assertEqual([target], release.release_destinations(wrapper.format(target), "2.3.4"))
        self.assertEqual([target], release.release_destinations(target + "<", "2.3.4"))
        self.assertEqual("https://example.com/a(b)", release.bare_destination("https://example.com/a(b))"))
        self.assertEqual("https://example.com/a", release.bare_destination("https://example.com/a;"))
        for suffix in ("&123;", "&abc123;", "&abc_foo;", "&#123;", "&#39;", "&#x27;", "&#xAB;"):
            candidate = target + suffix[:-1]
            with self.subTest(suffix=suffix):
                self.assertEqual([candidate], [value for _, value, _ in release.extract_destinations(target + suffix)])
                self.assertEqual([candidate], release.release_destinations(target + suffix, "2.3.4"))
        self.assertEqual(target + "&é", release.bare_destination(target + "&é;"))
        with self.assertRaisesRegex(ValueError, "canonical"):
            release.release_destinations(target + "&é;", "2.3.4")

    def test_visible_links_accept_emphasis_own_url_text_and_shortcut_references(self):
        target = "https://request-seal.hexdocs.pm/2.3.4/readme.html"
        for body in (f"*[Guide]({target})*", f"**[Guide]({target})**", f"[Guide]({target})—details",
                     f"[{target}]({target})", "www.example.com", target.rsplit("/", 1)[0] + "/",
                     "[RFC 9421] [section 2]\n\n[RFC 9421]: https://example.com/rfc\n[section 2]: https://example.com/section"):
            with self.subTest(body=body):
                self.assertEqual(body + "\n", release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4"))

    def test_code_spans_and_blocks_have_no_destinations_or_reference_uses(self):
        for code in ("[bad](relative.md)", "[Guide][missing]", "<<size::16>>", "<<a::binary>>",
                     "https://hexdocs.pm/request_seal/1.0.0/readme.html", '<a href="relative.md">x</a>'):
            for container in ("`{}`", "``{}``", "```text\n{}\n```", "~~~~\n{}\n~~~~", "    {}", "    - {}", "- Item\n\n      {}"):
                body = container.format(code)
                with self.subTest(body=body):
                    self.assertEqual([], release.release_destinations(body, "2.3.4"))
                    self.assertEqual(body + "\n", release.release_notes("## 2.3.4 - 2026-11-17\n\n" + body, "2.3.4"))

    def test_list_continuations_remain_visible_after_a_blank_line(self):
        for body in ("- Item\n\n    [bad](relative.md)", "- Item\n\n    1. [bad](relative.md)",
                     "- Item\n\n    - [bad](relative.md)"):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "destination 'relative.md'"):
                release.release_destinations(body, "2.3.4")

    def test_reference_definitions_are_block_scoped_and_not_code(self):
        for definition in ("```text\n[guide]: https://example.com/guide\n```",
                           "    [guide]: https://example.com/guide"):
            with self.subTest(definition=definition), self.assertRaisesRegex(ValueError, "reference 'guide'"):
                release.release_notes("## 2.3.4 - 2026-11-17\n\n[guide]\n\n" + definition, "2.3.4")
        for definition in ("Paragraph\n[guide]: https://example.com/guide",
                           "Paragraph\n    [guide]: https://example.com/guide"):
            with self.subTest(definition=definition), self.assertRaisesRegex(ValueError, "CHANGELOG.md:4: ambiguous reference definition"):
                release.release_notes("## 2.3.4 - 2026-11-17\n\n" + definition, "2.3.4")
        self.assertEqual(["https://example.com/a", "https://example.com/b"], release.release_destinations(
            "[a]: https://example.com/a\n[b]: https://example.com/b\n\n[a] [b]", "2.3.4"))

    def test_every_alternate_first_party_host_is_classified_and_rejected(self):
        targets = [f"https://{host}/baselabs/request_seal/v2.3.4/README.md" for host in
                   ("raw.github.com", "codeload.github.com", "media.githubusercontent.com", "uploads.github.com")]
        targets += ["https://api.github.com/repos/baselabs/request_seal/contents/README.md",
                    "https://hex.pm/api/packages/request_seal/releases/2.3.4",
                    "https://diff.hex.pm/diff/request_seal/2.3.3..2.3.4",
                    "https://preview.hex.pm/preview/request_seal/2.3.4",
                    "https://repo.hex.pm/tarballs/request_seal-2.3.4.tar",
                    "https://repo.hex.pm/docs/request_seal-2.3.4.tar.gz"]
        for target in targets:
            with self.subTest(target=target):
                self.assertIsNotNone(release.first_party(release.urlsplit(target)))
                with self.assertRaisesRegex(ValueError, "canonical"):
                    release.validate_destination(target, "2.3.4")
                self.assertRegex(" ".join(docs.first_party_link_errors(ROOT, "README.md", release.urlsplit(target), "2.3.4", set(), {})), "canonical")

    def test_queries_and_unsupported_fragments_are_rejected_with_the_canonical_form(self):
        bases = ("https://request-seal.hexdocs.pm/2.3.4/readme.html",
                 "https://github.com/baselabs/request_seal/blob/v2.3.4/README.md",
                 "https://raw.githubusercontent.com/baselabs/request_seal/v2.3.4/README.md",
                 "https://hex.pm/packages/request_seal/2.3.4")
        for base in bases:
            for suffix in ("?raw=true", "?"):
                with self.subTest(target=base + suffix), self.assertRaisesRegex(ValueError, "no query string.*canonical"):
                    release.validate_destination(base + suffix, "2.3.4")
        for base in bases[1:]:
            for fragment in ("#readme", "#L0", "#L1-Lx"):
                with self.subTest(target=base + fragment), self.assertRaisesRegex(ValueError, "fragment.*canonical"):
                    release.validate_destination(base + fragment, "2.3.4")

    def test_live_http_retries_remote_disconnect_and_rate_limit_retry_after(self):
        observed = []
        with local_http({"/disconnect": [0, 200]}, observed) as (base, requests):
            release.verify_http_destinations([base + "/disconnect"], deadline_seconds=4)
            self.assertEqual(["/disconnect", "/disconnect"], requests)
        observed = []
        with local_http({"/rate": [(429, {"Retry-After": "2"}), 200]}, observed) as (base, requests):
            release.verify_http_destinations([base + "/rate"], deadline_seconds=5)
            self.assertEqual(["/rate", "/rate"], requests)
            self.assertGreaterEqual(observed[1] - observed[0], 2)
        self.assertGreater(release.retry_after_seconds(formatdate(time.time() + 10, usegmt=True)), 8)

    def test_permanent_http_status_fails_promptly_with_other_transient_failures(self):
        for status in (400, 401, 403, 405, 410, 451):
            with local_http({"/final": [status], "/missing": [404]}) as (base, requests):
                started = time.monotonic()
                with self.subTest(status=status), self.assertRaises(ValueError) as raised:
                    release.verify_http_destinations([base + "/final", base + "/missing"], deadline_seconds=10)
                self.assertLess(time.monotonic() - started, 2)
                self.assertIn(f"{base}/final: HTTP {status}", str(raised.exception))
                self.assertIn(f"{base}/missing: HTTP 404", str(raised.exception))
                self.assertEqual(1, requests.count("/final"))

    def test_429_retry_after_never_extends_the_total_deadline(self):
        with local_http({"/rate": [(429, {"Retry-After": "120"})]}) as (base, requests):
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "HTTP 429"):
                release.verify_http_destinations([base + "/rate"], deadline_seconds=0.2)
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(["/rate"], requests)

    def test_socket_timeout_is_limited_to_the_remaining_deadline(self):
        with local_http({"/slow": [200]}, response_delay=3) as (base, requests):
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "destination deadline exceeded while reading response headers"):
                release.verify_http_destinations([base + "/slow"], deadline_seconds=0.1)
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(["/slow"], requests)


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
                result = run([sys.executable, "-B", str(ROOT / "scripts/check.py"), *flags], capture_output=True, text=True, check=False, timeout=30)
                self.assertEqual(2, result.returncode)
                self.assertIn("not allowed with argument", result.stderr)

    def test_release_actions_use_immutable_commits(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text()
        required = {"actions/checkout", "erlef/setup-beam", "actions/setup-python",
                    "actions/upload-artifact", "actions/attest"}
        self.assertEqual([], gate.ci_action_errors(workflow, required))
        for action in required:
            import re
            changed = re.sub(re.escape(action) + r"@[0-9a-f]{40}", action + "@v4", workflow)
            with self.subTest(action=action):
                self.assertTrue(gate.ci_action_errors(changed, required))

    def test_attestations_and_artifacts_precede_the_keyed_upload_without_creating_tags(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text()
        self.assertNotIn("gh release", workflow)
        self.assertNotIn("git tag", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("contents: write", workflow)
        for permission in ("id-token", "attestations"):
            self.assertIn(permission + ": write", workflow)
        self.assertIn("sbom-path: sbom.cdx.json", workflow)
        self.assertLess(workflow.index("scripts/publication.py --version"), workflow.index("uses: actions/attest@"))
        self.assertLess(workflow.rindex("uses: actions/attest@"), workflow.index("run: mix run --no-mix-exs"))
        for artifact in ("corpus.tar.gz", "corpus.sha256", "sbom.cdx.json", "release-notes.md"):
            self.assertIn("            " + artifact, workflow)

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
            result = run([sys.executable, "-B", str(ROOT / "scripts/release.py"), "--normalize-sbom", str(path), "--tarball", str(tarball)], capture_output=True, text=True, check=False, timeout=30)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Malformed release SBOM", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
