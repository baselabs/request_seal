"""Archive inspection and publication boundaries, using real files and tar archives."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import publication
from workflow_yaml import load


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

    def test_readback_compares_both_package_and_docs_as_bytes_without_replacement(self):
        self.assertEqual([], publication.readback_errors("request_seal", "2.3.4", self.metadata(),
                                                        self.release(has_docs=True), "a" * 64))
        for release, missing in ((None, "package-and-docs"), (self.release(), "docs")):
            errors = publication.readback_errors("request_seal", "2.3.4", self.metadata(), release, "a" * 64)
            self.assertEqual(["Hex publication is incomplete (missing " + missing +
                              "); approve any held uploads and dispatch again"], errors)
        for release in (self.release(retirement={"reason": "security"}), self.release(checksum="b" * 64)):
            with self.assertRaises(ValueError):
                publication.readback_errors("request_seal", "2.3.4", self.metadata(), release, "a" * 64)
        for label in ("package", "documentation"):
            self.assertEqual([], publication.archive_errors(b"inspected", b"inspected", label))
            for served in (b"changed", b"", b"inspected\n"):
                errors = publication.archive_errors(b"inspected", served, label)
                self.assertEqual([f"Published {label} bytes differ from the inspected archive; never replace"], errors)

    def test_requested_version_mismatch_refuses_before_loading_the_project(self):
        with self.assertRaisesRegex(ValueError, "differs from mix.exs"):
            publication.prepare(self.root, self.root, "99.0.0")

    def test_dispatch_boundary_key_isolation_and_native_uploads(self):
        source = (ROOT / ".github/workflows/publish.yml").read_text()
        workflow = load(source)
        self.assertEqual({"workflow_dispatch": ""}, workflow["on"])
        self.assertNotIn("qualified", source)
        actor = 'contains(fromJSON(\'["corepay","palermo-git"]\'), github.actor) && contains(fromJSON(\'["corepay","palermo-git"]\'), github.triggering_actor)'
        for job in workflow["jobs"].values():
            self.assertEqual(actor, job["if"])
            self.assertEqual("publish", job["environment"])
            steps = job["steps"]
            self.assertEqual('test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"', steps[0]["run"])
            keyed = [step for step in steps if "secrets." in str(step)]
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
            self.assertNotIn("if", planner)
            self.assertLess(next(i for i, s in enumerate(steps) if "--docs" in s.get("run", "")), steps.index(planner))
            readback = next(s for s in steps if "--verify-registry" in s.get("run", ""))
            self.assertGreater(steps.index(readback), steps.index(step))
            self.assertNotIn("if", readback)
            self.assertNotIn("HEX_API_KEY", str(readback))
            assets = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")]
            self.assertEqual(["release-assets"], [s["with"]["name"] for s in assets])
            self.assertEqual({"request_seal-${{ steps.identity.outputs.version }}.tar",
                              "request_seal-${{ steps.identity.outputs.version }}-docs.tar.gz",
                              "corpus.tar.gz", "corpus.sha256", "sbom.cdx.json", "release-notes.md"},
                             set(assets[0]["with"]["path"].splitlines()))
        uploader = (ROOT / "scripts/publish_hex.exs").read_text()
        self.assertIn('File.exists?("mix.exs") or Mix.Project.get() != nil', uploader)
        self.assertIn('System.fetch_env!("HEX_API_KEY")', uploader)
        self.assertIn("auth = [key: key]", uploader)
        self.assertIn('unless upload in ["package-and-docs", "docs"]', uploader)
        self.assertIn('if upload == "package-and-docs" do\n  Hex.API.Release.publish', uploader)
        self.assertIn("replace: false", uploader)
        self.assertIn('Hex.API.ReleaseDocs.publish(nil, "request_seal", version, File.read!(docs_path), auth)', uploader)
        self.assertIn("Hex upload is held for approval; approve it and dispatch again", uploader)
        for forbidden in ("Code.eval", "Code.require", "Mix.Task.run", "inspect(", "System.cmd"):
            self.assertNotIn(forbidden, uploader)


if __name__ == "__main__":
    unittest.main()
