"""Archive inspection and publication boundaries, using real files and tar archives."""
import hashlib
import io
import json
import shlex
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import publication
from workflow_yaml import load

# A real public release attested by its own workflow, with the attestation bundles and the Sigstore
# trusted root saved beside this test, so verification runs offline and without credentials.
ATTESTED = {"repository": "baselabs/charter_agreement_signer",
            "workflow": "baselabs/charter_agreement_signer/.github/workflows/supply-chain.yml",
            "ref": "refs/tags/v1.0.0"}
ATTESTED_COMMIT = "f9a7bc3c8c644afa74cdf95fd2d3b832fa99ce00"
ATTESTED_URL = ("https://github.com/baselabs/charter_agreement_signer/releases/download/v1.0.0/"
                "charter_agreement_signer-1.0.0.tar")
ATTESTED_SHA256 = "1ef96b66cce510de79ae59ab7f4d8293afb5822fbdd25fca20eb19a8350ce228"
FIXTURES = ROOT / "test/fixtures/attestation"
OFFLINE = ("--bundle", str(FIXTURES / "charter_agreement_signer-1.0.0.bundle.jsonl"),
           "--custom-trusted-root", str(FIXTURES / "trusted_root.jsonl"))


def tar_bytes(entries, mode="w"):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode=mode) as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            if data is None:
                member.type = tarfile.SYMTYPE
                member.linkname = "outside"
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="requestseal-publication-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def package(self, *, files=None, metadata=None, checksum=None, format=b"3"):
        files = [("mix.exs", b"public source")] if files is None else files
        contents = tar_bytes(files, "w:gz")
        metadata = metadata or b'{<<"name">>,<<"request_seal">>}.\n{<<"version">>,<<"2.3.4">>}.\n'
        checksum = checksum or hashlib.sha256(format + metadata + contents).hexdigest().upper().encode()
        path = self.root / "package.tar"
        path.write_bytes(tar_bytes([("VERSION", format), ("CHECKSUM", checksum),
                                   ("metadata.config", metadata), ("contents.tar.gz", contents)]))
        (self.root / "mix.exs").write_bytes(b"public source")
        return path

    def test_package_accepts_only_exact_inventory_identity_checksum_and_source_bytes(self):
        publication.inspect_package(self.package(), "2.3.4", {"mix.exs"}, self.root)
        cases = (
            {"checksum": b"0" * 64}, {"format": b"4"},
            {"metadata": b'{<<"name">>,<<"other">>}.\n{<<"version">>,<<"2.3.4">>}.\n'},
            {"metadata": b'{<<"name">>,<<"request_seal">>}.\n{<<"version">>,<<"2.3.5">>}.\n'},
            {"files": [("mix.exs", b"changed")]},
            {"files": [("mix.exs", b"public source"), ("extra", b"unapproved")]},
            {"files": []}, {"files": [("mix.exs", None)]},
            {"files": [("../outside", b"x")]}, {"files": [("/outside", b"x")]},
            {"files": [("mix.exs", b"public source"), ("mix.exs", b"public source")]},
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                publication.inspect_package(self.package(**case), "2.3.4", {"mix.exs"}, self.root)
        path = self.package()
        with tarfile.open(path, "a") as archive:
            archive.addfile(tarfile.TarInfo("extra"))
        with self.assertRaisesRegex(ValueError, "four regular"):
            publication.inspect_package(path, "2.3.4", {"mix.exs"}, self.root)

    def test_docs_archive_is_deterministic_and_checks_required_pages_and_symlinks(self):
        docs = self.root / "docs"
        docs.mkdir()
        output = self.root / "docs.tar.gz"
        with self.assertRaisesRegex(ValueError, "lacks"):
            publication.build_docs_archive(docs, output)
        for name in ("index.html", "api-reference.html", "assets/style.css", ".build"):
            path = docs / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(name)
        publication.build_docs_archive(docs, output)
        first = output.read_bytes()
        publication.build_docs_archive(docs, output)
        self.assertEqual(first, output.read_bytes())
        with tarfile.open(output) as archive:
            self.assertEqual(["api-reference.html", "assets/style.css", "index.html"], archive.getnames())
        (docs / "link").symlink_to(docs / "index.html")
        with self.assertRaisesRegex(ValueError, "symlink"):
            publication.build_docs_archive(docs, output)

    def metadata(self, version="1.0.0"):
        return {"name": "request_seal", "releases": [{"version": version}]}

    def release(self, **changes):
        return {"version": "2.3.4", "checksum": "a" * 64,
                "retirement": None, "has_docs": False, **changes}

    def plan(self, release, metadata=None, checksum="a" * 64):
        return publication.upload_plan("request_seal", "2.3.4",
                                       self.metadata() if metadata is None else metadata, release, checksum)

    def test_registry_inventory_requires_an_existing_name_but_allows_a_recovery_version(self):
        for version in ("1.0.0", "2.3.4"):
            self.assertEqual([], publication.registry_errors("request_seal", self.metadata(version)))
        for metadata in (None, {}, {"name": "other"}, {"name": "request_seal", "releases": []},
                         {"name": "request_seal", "releases": [{}]}, self.metadata(123),
                         {"name": "request_seal", "releases": [None]},
                         {"name": "request_seal", "releases": "1.0.0"}):
            self.assertTrue(publication.registry_errors("request_seal", metadata))
            with self.assertRaises(ValueError):
                publication.upload_plan("request_seal", "2.3.4", metadata, None, "a" * 64)
        self.assertIn("request_seal", publication.registry_errors("request_seal", None)[0])
        self.assertIn("first publication", publication.registry_errors("request_seal", None)[0])

    def test_only_explicit_api_not_found_means_absence(self):
        for path, metadata in (("", self.metadata()), ("/releases/2.3.4", self.release())):
            self.assertEqual(metadata, publication.registry_response(path, 200, metadata))
            self.assertIsNone(publication.registry_response(path, 404, {"message": "not found"}))
            for status in (201, 202, 301, 401, 403, 429, 500, 503):
                with self.subTest(status=status), self.assertRaisesRegex(ValueError, f"HTTP {status}"):
                    publication.registry_response(path, status, metadata)
            for malformed in (None, [], "metadata", 0, False):
                with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, "invalid metadata"):
                    publication.registry_response(path, 200, malformed)

    def test_upload_plan_uploads_only_missing_archives_and_uses_the_outer_checksum(self):
        self.assertEqual("package-and-docs", self.plan(None))
        for checksum in ("a" * 64, "A" * 64):
            for listed in ("1.0.0", "2.3.4"):
                self.assertEqual("docs", self.plan(self.release(checksum=checksum), self.metadata(listed)))
                self.assertEqual("none", self.plan(self.release(checksum=checksum, has_docs=True), self.metadata(listed)))
        tarball = self.package()
        outer = hashlib.sha256(tarball.read_bytes()).hexdigest()
        with tarfile.open(tarball) as archive:
            inner = archive.extractfile("CHECKSUM").read().decode().lower()
        self.assertNotEqual(inner, outer)
        self.assertEqual("docs", self.plan(self.release(checksum=outer), checksum=outer))
        with self.assertRaisesRegex(ValueError, "bytes differ.*never replace"):
            self.plan(self.release(checksum=inner), checksum=outer)

    def test_upload_plan_refuses_retirement_differing_bytes_and_uncertain_api_states(self):
        for has_docs in (False, True):
            with self.assertRaisesRegex(ValueError, "bytes differ.*never replace"):
                self.plan(self.release(checksum="b" * 64, has_docs=has_docs))
            for retirement in ({"reason": "security", "message": "withdrawn"}, {}, False, "retired"):
                with self.subTest(retirement=retirement), self.assertRaisesRegex(ValueError, "retired"):
                    self.plan(self.release(retirement=retirement, has_docs=has_docs))
        for release in ([], "release", {}, self.release(version="2.3.5")):
            with self.subTest(release=release), self.assertRaisesRegex(ValueError, "identity"):
                self.plan(release)
        release = self.release()
        del release["retirement"]
        with self.assertRaisesRegex(ValueError, "retirement state is missing"):
            self.plan(release)
        for checksum in (None, 123, "a" * 63, "g" * 64, "a" * 64 + "\n"):
            with self.subTest(checksum=checksum), self.assertRaisesRegex(ValueError, "checksum"):
                self.plan(self.release(checksum=checksum))
            with self.subTest(local_checksum=checksum), self.assertRaisesRegex(ValueError, "checksum"):
                self.plan(self.release(), checksum=checksum)
        for has_docs in (None, 0, 1, "false", [], {}):
            with self.subTest(has_docs=has_docs), self.assertRaisesRegex(ValueError, "documentation state"):
                self.plan(self.release(has_docs=has_docs))
        for key in ("checksum", "has_docs"):
            release = self.release()
            del release[key]
            with self.assertRaises(ValueError):
                self.plan(release)
        with self.assertRaisesRegex(ValueError, "release metadata is absent"):
            self.plan(None, self.metadata("2.3.4"))

    def test_readback_compares_package_bytes_and_requires_docs_presence_without_replacement(self):
        self.assertEqual([], publication.readback_errors("request_seal", "2.3.4", self.metadata(),
                                                        self.release(has_docs=True), "a" * 64))
        for release, missing in ((None, "package-and-docs"), (self.release(), "docs")):
            errors = publication.readback_errors("request_seal", "2.3.4", self.metadata(), release, "a" * 64)
            self.assertEqual(["Hex publication is incomplete (missing " + missing +
                              "); approve any held uploads and dispatch again"], errors)
        for release in (self.release(retirement={"reason": "security"}), self.release(checksum="b" * 64)):
            with self.assertRaises(ValueError):
                publication.readback_errors("request_seal", "2.3.4", self.metadata(), release, "a" * 64)
        self.assertEqual([], publication.package_errors(b"inspected", b"inspected"))
        for served in (b"changed", b"", b"inspected\n"):
            self.assertEqual(["Published package bytes differ from the inspected archive; never replace"],
                             publication.package_errors(b"inspected", served))

    def docs_archive(self, record=None, entries=None):
        record = {"package": "request_seal", "version": "2.3.4", "commit": "c" * 40} if record is None else record
        data = record if isinstance(record, bytes) else json.dumps(record).encode()
        return tar_bytes([("index.html", b"<html>"), ("release.json", data)] if entries is None else entries, "w:gz")

    def test_docs_are_identified_by_their_release_record_never_by_bytes(self):
        self.assertEqual("c" * 40, publication.docs_release_commit(self.docs_archive(), "2.3.4"))
        good = {"package": "request_seal", "version": "2.3.4", "commit": "c" * 40}
        records = ({**good, "package": "other"}, {**good, "version": "2.3.5"}, {**good, "commit": "c" * 39},
                   {**good, "commit": "C" * 40}, {**good, "commit": 1}, {**good, "extra": True},
                   {"package": "request_seal", "version": "2.3.4"}, ["request_seal", "2.3.4", "c" * 40])
        for record in records:
            with self.subTest(record=record), self.assertRaisesRegex(ValueError, "release.json does not name"):
                publication.docs_release_commit(self.docs_archive(record), "2.3.4")
        for archive in (self.docs_archive(b"{not json"), self.docs_archive(b"\xff"), b"", b"not gzip",
                        self.docs_archive()[:40]):
            with self.subTest(archive=archive[:12]), self.assertRaisesRegex(ValueError, "unreadable"):
                publication.docs_release_commit(archive, "2.3.4")
        record = json.dumps(good).encode()
        for entries in ([("release.json", record)], [("index.html", b"<html>")]):
            with self.subTest(entries=[name for name, _ in entries]), self.assertRaisesRegex(ValueError, "lacks"):
                publication.docs_release_commit(self.docs_archive(entries=entries), "2.3.4")
        for entries in ([("index.html", b"<html>"), ("release.json", None)],
                        [("index.html", b"<html>"), ("release.json", record), ("../outside", b"x")],
                        [("index.html", b"<html>"), ("release.json", record), ("release.json", record)]):
            with self.assertRaisesRegex(ValueError, "unsafe, duplicate"):
                publication.docs_release_commit(self.docs_archive(entries=entries), "2.3.4")

    def git(self, *argv):
        return subprocess.run(["git", "-C", str(self.root / "repository"), *argv], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, message):
        self.git("-c", "user.name=Publication Test", "-c", "user.email=test@example.invalid",
                 "commit", "--allow-empty", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def test_published_commit_is_the_dispatched_commit_or_its_default_branch_ancestor(self):
        (self.root / "repository").mkdir()
        self.git("init", "--quiet", "--initial-branch=main")
        first = self.commit("first")
        second = self.commit("second")
        self.git("switch", "--quiet", "--create", "side", first)
        side = self.commit("side")
        repository = self.root / "repository"
        self.assertEqual(second, publication.published_commit(second, second, repository))
        self.assertEqual(first, publication.published_commit(first, second, repository))
        for docs in (side, "0" * 40):
            with self.subTest(docs=docs), self.assertRaisesRegex(ValueError, "neither the dispatched"):
                publication.published_commit(docs, second, repository)
        with self.assertRaisesRegex(ValueError, "neither the dispatched"):
            publication.published_commit(second, first, repository)

    def attested_assets(self):
        request = Request(ATTESTED_URL, headers={"User-Agent": "RequestSeal-publication-test"})
        with urlopen(request, timeout=60) as response:
            data = response.read()
        self.assertEqual(ATTESTED_SHA256, hashlib.sha256(data).hexdigest())
        paths = [self.root / name for name in ("request_seal-2.3.4.tar", "corpus.tar.gz", "sbom.cdx.json")]
        for path in paths:
            path.write_bytes(data)
        return paths

    def test_kept_docs_commit_must_own_every_attested_release_asset(self):
        package, corpus, sbom = self.attested_assets()
        dispatched = "d" * 40
        # The published commit's run attested these exact bytes, the package with both predicates.
        self.assertEqual([], publication.published_asset_errors(
            ATTESTED_COMMIT, dispatched, package, [corpus, sbom], ATTESTED, OFFLINE))
        # When the served docs name the dispatched commit, this run attests its own assets.
        unattested = self.root / "unattested"
        unattested.write_bytes(b"built here")
        self.assertEqual([], publication.published_asset_errors(
            dispatched, dispatched, unattested, [unattested], ATTESTED, OFFLINE))
        final = "this run's release assets are not the published commit's; release a new version"
        # A rebuilt corpus whose bytes differ from the published run's has no attestation for it.
        corpus.write_bytes(corpus.read_bytes() + b"\0")
        self.assertEqual([f"corpus.tar.gz has no {publication.PROVENANCE} attestation for published commit "
                          f"{ATTESTED_COMMIT}", final],
                         publication.published_asset_errors(ATTESTED_COMMIT, dispatched, package, [corpus, sbom],
                                                            ATTESTED, OFFLINE))
        # Identical bytes attested by another commit's run do not belong to this published commit.
        corpus.write_bytes(package.read_bytes())
        other = "e" * 40
        self.assertEqual([f"{path.name} has no {predicate} attestation for published commit {other}"
                          for path, predicate in ((package, publication.PROVENANCE), (corpus, publication.PROVENANCE),
                                                  (sbom, publication.PROVENANCE), (package, publication.SBOM))] + [final],
                         publication.published_asset_errors(other, dispatched, package, [corpus, sbom],
                                                            ATTESTED, OFFLINE))

    def test_asset_proof_runs_the_consumer_guide_verification_commands(self):
        guide = (ROOT / "docs/guides/verifying-releases.md").read_text().replace("\\\n", " ")
        commands = [shlex.split(line.strip()) for line in guide.splitlines()
                    if line.strip().startswith("gh attestation verify ")]
        expected = [publication.attestation_argv("FILE", predicate, "$SOURCE_COMMIT")
                    for predicate in (publication.PROVENANCE, publication.SBOM)]
        self.assertEqual([argv[:3] + argv[4:] for argv in expected], [argv[:3] + argv[4:] for argv in commands])

    def test_built_docs_carry_a_release_record_for_the_dispatched_commit(self):
        docs = self.root / "docs"
        docs.mkdir()
        for name in ("index.html", "api-reference.html"):
            (docs / name).write_text(name)
        for commit in ("c" * 39, "C" * 40, None):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "full lowercase commit"):
                publication.write_release_record(docs, "2.3.4", commit)
        self.assertFalse((docs / "release.json").exists())
        publication.write_release_record(docs, "2.3.4", "d" * 40)
        self.assertEqual({"package": "request_seal", "version": "2.3.4", "commit": "d" * 40},
                         json.loads((docs / "release.json").read_text()))
        with self.assertRaisesRegex(ValueError, "already contains release.json"):
            publication.write_release_record(docs, "2.3.4", "d" * 40)
        output = self.root / "docs.tar.gz"
        publication.build_docs_archive(docs, output)
        self.assertEqual("d" * 40, publication.docs_release_commit(output.read_bytes(), "2.3.4"))

    def test_requested_version_mismatch_refuses_before_loading_the_project(self):
        with self.assertRaisesRegex(ValueError, "differs from mix.exs"):
            publication.prepare(self.root, self.root, "99.0.0", "c" * 40)

    def test_changelog_gate_is_verbatim_and_precedes_release_processing(self):
        expected = r'''python3 -I - "$RUNNER_TEMP/requestseal-archives/request_seal-$VERSION.tar" "$VERSION" <<'PY'
import io, re, sys, tarfile
archive, version = sys.argv[1], sys.argv[2]
def refuse(message):
    raise SystemExit(f'{archive}: {message}; publication refused')
with tarfile.open(archive, 'r:*') as outer:
    if 'contents.tar.gz' in outer.getnames():
        package = tarfile.open(fileobj=io.BytesIO(outer.extractfile('contents.tar.gz').read()), mode='r:gz')
        root = ''
    else:
        package, root = outer, 'package/'
    found = [member for member in package.getmembers() if member.isfile()
             and re.fullmatch(re.escape(root) + r'(?i:changelog(?:\.md|\.markdown|\.txt)?)', member.name)]
    if len(found) != 1:
        refuse('the package must ship exactly one root CHANGELOG')
    try:
        lines = package.extractfile(found[0]).read().decode('utf-8').splitlines()
    except UnicodeDecodeError:
        refuse('the packaged CHANGELOG is not UTF-8')
headings, fence = {}, False
for index, line in enumerate(lines):
    if re.match(r' {0,3}(```|~~~)', line):
        fence = not fence
    elif not fence and (match := re.match(r' {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$', line)):
        headings[index] = (len(match.group(1)), match.group(2) or '')
token = re.compile(r'(?<![0-9A-Za-z.+-])v?' + re.escape(version) + r'(?![0-9A-Za-z.+-])')
stamped = [index for index, (_, title) in headings.items() if token.search(title)]
if not stamped:
    refuse(f'the packaged CHANGELOG has no section for {version}')
at, level = stamped[0], headings[stamped[0]][0]
def written(start):
    end = next((index for index, (depth, _) in headings.items() if index > start and depth <= level), len(lines))
    return any(line.strip() for index, line in enumerate(lines[start + 1:end], start + 1) if index not in headings)
if not written(at):
    refuse(f'the packaged CHANGELOG section for {version} is empty')
for start, (depth, title) in headings.items():
    if start < at and depth == level and written(start):
        refuse(f'the packaged CHANGELOG has entries above {version}, under "{title}"')
print(f'{archive}: the packaged CHANGELOG is stamped for {version}')
PY
'''
        name = "Refuse a package whose changelog is not stamped for its version"
        jobs = load((ROOT / ".github/workflows/publish.yml").read_text())["jobs"]
        steps = jobs["publish"]["steps"]
        matches = [(job, index) for job, job_body in jobs.items()
                   for index, step in enumerate(job_body["steps"]) if step.get("name") == name]
        self.assertEqual(1, len(matches))
        job, position = matches[0]
        self.assertEqual("publish", job)
        self.assertEqual({"name": name, "shell": "bash", "run": expected,
                          "env": {"VERSION": "${{ steps.identity.outputs.version }}"}},
                         steps[position])
        names = [step.get("name") for step in steps]
        self.assertEqual(["Build and inspect the package and documentation without a key",
                          name, "Generate and verify package dependency SBOM"],
                         names[position - 1:position + 2])
        for following in ("Plan only missing uploads, and prove kept docs' commit owns every release asset",
                          "Upload only the missing inspected archives"):
            self.assertIn(following, names[position + 2:])

    def test_changelog_gate_reads_the_hex_package_and_rejects_unstamped_releases(self):
        steps = load((ROOT / ".github/workflows/publish.yml").read_text())["jobs"]["publish"]["steps"]
        script = next(step["run"] for step in steps
                      if step.get("name") == "Refuse a package whose changelog is not stamped for its version")
        version = "2.3.4"
        runner = self.root / "runner temp"
        archive = runner / "requestseal-archives" / f"request_seal-{version}.tar"
        archive.parent.mkdir(parents=True)
        prior = b"## 2.3.3 - 2026-11-16\n\n- Prior release.\n"
        current = b"## 2.3.4 - 2026-11-17\n\n- Released behavior.\n\n"
        unreleased = b"# Changelog\n\n## Unreleased\n\n"
        for changelog, refusal in (
            (unreleased + current + prior, None),
            (unreleased + b"- Pending changes.\n\n" + current + prior,
             "has entries above 2.3.4"),
            (b"## 2.3.5 - 2026-11-18\n\n- Newer release.\n\n" + current + prior,
             "has entries above 2.3.4"),
            (unreleased + prior, "has no section for 2.3.4"),
            (unreleased + b"## 2.3.4 - 2026-11-17\n\n" + prior,
             "section for 2.3.4 is empty"),
        ):
            with self.subTest(refusal=refusal, changelog=changelog):
                self.package(files=[("CHANGELOG.md", changelog)]).replace(archive)
                result = subprocess.run(
                    ["/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
                    input=script, capture_output=True, text=True, timeout=30,
                    env={"RUNNER_TEMP": str(runner), "VERSION": version,
                         "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"},
                )
                if refusal is None:
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn("the packaged CHANGELOG is stamped for 2.3.4", result.stdout)
                else:
                    self.assertEqual(1, result.returncode, result.stdout)
                    self.assertIn(refusal, result.stderr)
                    self.assertIn("publication refused", result.stderr)

    def test_dispatch_boundary_key_isolation_and_native_uploads(self):
        source = (ROOT / ".github/workflows/publish.yml").read_text()
        workflow = load(source)
        self.assertEqual({"workflow_dispatch": ""}, workflow["on"])
        self.assertNotIn("qualified", source)
        actor = 'contains(fromJSON(\'["corepay","palermo-git"]\'), github.actor) && contains(fromJSON(\'["corepay","palermo-git"]\'), github.triggering_actor)'
        for name, job in workflow["jobs"].items():
            self.assertIn(actor, job["if"])
            steps = job["steps"]
            self.assertEqual('test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"', steps[0]["run"])
            keyed = [step for step in steps if "secrets." in str(step)]
            if name != "publish":
                self.assertNotIn("environment", job)
                self.assertEqual([], keyed)
                continue
            self.assertEqual(actor, job["if"])
            self.assertEqual("publish", job["environment"])
            self.assertEqual(1, len(keyed))
            step = keyed[0]
            self.assertEqual("${{ secrets.HEX_API_KEY }}", step["env"]["HEX_API_KEY"])
            self.assertEqual("${{ runner.temp }}/requestseal-upload", step["working-directory"])
            self.assertTrue(step["run"].startswith("mix run --no-mix-exs --no-start publish_hex.exs "))
            self.assertNotIn("HEX_API_KEY", step["run"])
            self.assertEqual("steps.registry.outputs.upload != 'none'", step["if"])
            self.assertEqual("${{ steps.registry.outputs.upload }}", step["env"]["UPLOAD"])
            self.assertNotIn("cache", source.lower())
            for command in ("--check-registry", "--verify --notes-file", "--directory", "mix docs", "--plan-upload"):
                self.assertIn(command, str(steps[:steps.index(step)]))
            planner = next(s for s in steps if s.get("id") == "registry")
            self.assertIn('--github-output "$GITHUB_OUTPUT"', planner["run"])
            self.assertIn('--commit "$GITHUB_SHA" --assets "$GITHUB_WORKSPACE"', planner["run"])
            self.assertEqual("${{ github.token }}", planner["env"]["GH_TOKEN"])
            sbom = next(s for s in steps if "scripts/sbom.py" in s.get("run", ""))
            # The kept-docs proof verifies the SBOM, so it exists before planning and any upload.
            self.assertLess(steps.index(sbom), steps.index(planner))
            self.assertNotIn("if", planner)
            self.assertLess(next(i for i, s in enumerate(steps) if "--docs" in s.get("run", "")), steps.index(planner))
            readback = next(s for s in steps if "--verify-registry" in s.get("run", ""))
            self.assertGreater(steps.index(readback), steps.index(step))
            self.assertNotIn("if", readback)
            self.assertNotIn("HEX_API_KEY", str(readback))
            inspection = next(s for s in steps if "--docs" in s.get("run", ""))
            self.assertIn('scripts/publication.py --version "$VERSION" --commit "$GITHUB_SHA" ', inspection["run"])
            self.assertIn('--verify-registry --version "$VERSION" --commit "$GITHUB_SHA" ', readback["run"])
            self.assertIn('--release-docs "request_seal-$VERSION-docs.tar.gz"', readback["run"])
            assets = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")]
            self.assertEqual(["release-assets"], [s["with"]["name"] for s in assets])
            # The release carries the docs the registry serves, written by the readback.
            self.assertGreater(steps.index(assets[0]), steps.index(readback))
            self.assertEqual({"request_seal-${{ steps.identity.outputs.version }}.tar",
                              "request_seal-${{ steps.identity.outputs.version }}-docs.tar.gz",
                              "corpus.tar.gz", "corpus.sha256", "sbom.cdx.json", "release-notes.md"},
                             set(assets[0]["with"]["path"].splitlines()))
        uploader = (ROOT / "scripts/publish_hex.exs").read_text()
        self.assertIn('File.exists?("mix.exs") or Mix.Project.get() != nil', uploader)
        self.assertIn('System.fetch_env!("HEX_API_KEY")', uploader)
        self.assertIn("auth = [key: key]", uploader)
        self.assertIn('unless upload in ["package-and-docs", "docs"]', uploader)
        self.assertIn('Hex.API.Release.get(nil, "request_seal", version, auth)', uploader)
        self.assertIn('Hex.API.Release.get_staged(url, auth)', uploader)
        self.assertIn('/packages/request_seal/releases/#{version}/staged', uploader)
        self.assertIn('Hex.API.Release.publish(nil, package, auth, fn _ -> :ok end, replace: false)', uploader)
        loop = uploader.index('Enum.reduce(uploads, :uploaded, fn kind, state ->')
        self.assertLess(uploader.index('state = read_release!'), loop)
        self.assertLess(uploader.index('stop_if_staged!(version, state)'), loop)
        self.assertLess(uploader.index('remaining_uploads!(version, uploads, state)'),
                        loop)
        self.assertIn('state = upload_state!(kind, state, result, package)', uploader)
        self.assertLess(uploader.index('state = upload_state!(kind, state, result, package)'),
                        uploader.index('end)\n\n    stop_if_staged!(version, state)'))
        self.assertIn("replace: false", uploader)
        self.assertIn('Hex.API.ReleaseDocs.publish(nil, "request_seal", version, docs, auth)', uploader)
        self.assertIn("is staged for approval; approve it on hex.pm, then dispatch again", uploader)
        for forbidden in ("Code.eval", "Code.require", "Mix.Task.run", "inspect(", "System.cmd"):
            self.assertNotIn(forbidden, uploader)


if __name__ == "__main__":
    unittest.main()
