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

    def test_registry_inventory_refuses_absent_malformed_or_existing_versions(self):
        self.assertEqual([], publication.registry_errors("request_seal", "2.3.4",
                         {"name": "request_seal", "releases": [{"version": "1.0.0"}]}))
        for metadata in (None, {}, {"name": "other"}, {"name": "request_seal", "releases": []},
                         {"name": "request_seal", "releases": [{}]},
                         {"name": "request_seal", "releases": [{"version": "2.3.4"}]}):
            self.assertTrue(publication.registry_errors("request_seal", "2.3.4", metadata))

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
            self.assertNotIn("cache", source.lower())
            for command in ("--check-registry", "--verify --notes-file", "--directory", "mix docs"):
                self.assertIn(command, str(steps[:steps.index(step)]))
        uploader = (ROOT / "scripts/publish_hex.exs").read_text()
        self.assertIn('File.exists?("mix.exs") or Mix.Project.get() != nil', uploader)
        self.assertIn('System.fetch_env!("HEX_API_KEY")', uploader)
        self.assertIn("auth = [key: key]", uploader)
        self.assertIn("Hex.API.Release.publish(nil, package, auth)", uploader)
        self.assertIn('Hex.API.ReleaseDocs.publish(nil, "request_seal", version, docs, auth)', uploader)
        for forbidden in ("Code.eval", "Code.require", "Mix.Task.run", "inspect(", "System.cmd"):
            self.assertNotIn(forbidden, uploader)


if __name__ == "__main__":
    unittest.main()
