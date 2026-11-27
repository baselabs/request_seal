"""Exercise the qualification sign-off check against actual Git history."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check


class DcoTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.git("init", "--quiet")

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "user.name=Contributor", "-c", "user.email=author@example.invalid",
             "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
            cwd=self.root, check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()

    def commit(self, message="Change", *options):
        self.git("commit", "--quiet", "--allow-empty", "-m", message, *options)
        return self.git("rev-parse", "HEAD")

    def introduce_policy(self, *options):
        (self.root / "IPR.md").write_text("# Intellectual property\n")
        self.git("add", "IPR.md")
        return self.commit("Add contribution terms", *options)

    def test_requires_a_matching_trailer_on_every_commit_from_introduction(self):
        self.commit("Before contribution terms")
        self.introduce_policy("--signoff")
        self.commit("Two sign-offs\n\nSigned-off-by: Reviewer <review@example.invalid>", "--signoff")
        check.check_dco(self.root)

        wrong_name = self.commit("Wrong name", "--author=Other Author <author@example.invalid>", "--signoff")
        wrong_email = self.commit("Wrong email", "--author=Contributor <other@example.invalid>", "--signoff")
        prose = self.commit("Quoted body\n\nSigned-off-by: Contributor <author@example.invalid>\n\nEnd of quotation.")
        unsigned = self.commit("Missing trailer")
        self.commit("Signed tip", "--signoff")
        with self.assertRaisesRegex(ValueError, "matching Signed-off-by") as error:
            check.check_dco(self.root)
        for sha in (wrong_name, wrong_email, prose, unsigned):
            self.assertIn(sha, str(error.exception))

    def test_requires_the_introduction_commit_itself_to_be_signed(self):
        first = self.introduce_policy()
        self.commit("Signed follow-up", "--signoff")
        with self.assertRaisesRegex(ValueError, first):
            check.check_dco(self.root)

    def test_readding_the_policy_does_not_restart_the_check(self):
        self.introduce_policy("--signoff")
        unsigned = self.commit("Missing trailer")
        self.git("rm", "IPR.md")
        self.commit("Remove contribution terms", "--signoff")
        self.introduce_policy("--signoff")
        with self.assertRaisesRegex(ValueError, unsigned):
            check.check_dco(self.root)

    def test_checks_commits_reached_through_a_signed_merge(self):
        self.introduce_policy("--signoff")
        self.git("branch", "integration")
        self.git("checkout", "--quiet", "-b", "feature")
        unsigned = self.commit("Missing trailer on feature")
        self.git("checkout", "--quiet", "integration")
        self.git("merge", "--quiet", "--no-ff", "--signoff", "feature")
        with self.assertRaisesRegex(ValueError, unsigned):
            check.check_dco(self.root)

    def test_refuses_missing_or_shallow_policy_history(self):
        self.commit("Before contribution terms")
        with self.assertRaisesRegex(ValueError, "IPR.md introduction"):
            check.check_dco(self.root)
        self.introduce_policy("--signoff")
        self.commit("Signed follow-up", "--signoff")
        self.git("clone", "--quiet", "--no-local", "--depth=1", ".", "shallow")
        with self.assertRaisesRegex(ValueError, "full Git history"):
            check.check_dco(self.root / "shallow")


if __name__ == "__main__":
    unittest.main()
