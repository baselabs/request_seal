"""Reject stale, missing, or ambiguous mutation proofs."""
import difflib
import json
import re
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import processes
import mutations


def enclosing_function(source, position):
    """Identify an Elixir function by name and declared arity, never line number."""
    prefix = "\n".join(source[:position])
    definitions = list(re.finditer(r"^\s*defp?\s+([\w?!]+)\s*", prefix, re.MULTILINE))
    if not definitions:
        return None
    definition = definitions[-1]
    tail = "\n".join(source)[definition.end():]
    if not tail.startswith("("):
        return definition[1], 0
    depth, commas, quote, escaped = 0, 0, None, False
    for index, char in enumerate(tail):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return definition[1], 0 if not tail[1:index].strip() else commas + 1
        elif char == "," and depth == 1:
            commas += 1
    raise ValueError("unterminated function signature: " + definition[1])


def changed_lines(patch, root=None):
    """Ignore location/context/whitespace; retain edits and their function scope."""
    changes = []
    path = None
    position = None
    source = []
    edit_position = None
    lines = patch.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("--- a/"):
            path = line[6:]
        elif line.startswith("@@"):
            edit_position = None
            position = int(re.match(r"@@ -(\d+)", line)[1])
            if root is not None:
                # git apply accepts stale line numbers when context moved. Locate
                # that context in the current source before comparing edits.
                old = []
                count = int(re.match(r"@@ -\d+(?:,(\d+))?", line)[1] or 1)
                for context in lines[index + 1:]:
                    if len(old) == count:
                        break
                    if context.startswith(("@@", "diff --git", "--- a/")):
                        break
                    if not context or context.startswith((" ", "-")):
                        old.append(context[1:] if context else "")
                source = (root / path).read_text().splitlines()
                matches = [at + 1 for at in range(len(source) - len(old) + 1)
                           if source[at:at + len(old)] == old]
                if not matches:
                    raise ValueError(f"mutation context missing: {path}:{position}")
                position = min(matches, key=lambda at: abs(at - position))
        elif line.startswith("---") or line.startswith("+++"):
            continue
        elif position is not None:
            if line.startswith("-"):
                if edit_position is None:
                    edit_position = position
                scope = enclosing_function(source, position) if root is not None else None
                changes.append((path, scope, "-", re.sub(r"\s+", "", line[1:])))
                position += 1
            elif line.startswith("+"):
                scope = enclosing_function(source, edit_position or position) if root is not None else None
                changes.append((path, scope, "+", re.sub(r"\s+", "", line[1:])))
            elif not line or line.startswith(" "):
                edit_position = None
                position += 1
    return tuple(changes)


class MutationsTest(unittest.TestCase):
    def test_manifest_and_patches_agree_and_apply(self):
        for suite in ("jwe_open", "finch"):
            with self.subTest(suite=suite):
                self.check_suite(suite)

    def check_suite(self, suite):
        directory = ROOT / "test/mutations" / suite
        entries = json.loads((directory / "manifest.json").read_text())["mutations"]
        names = [entry["patch"] for entry in entries]
        self.assertTrue(names)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {path.name for path in directory.glob("*.patch")})
        fingerprints = {}
        contents = set()
        for entry in entries:
            with self.subTest(patch=entry["patch"]):
                patch = (directory / entry["patch"]).read_text()
                self.assertTrue(patch not in contents, "identical mutation patches")
                contents.add(patch)
                fingerprint = changed_lines(patch, ROOT)
                self.assertTrue(fingerprint)
                self.assertNotIn(fingerprint, fingerprints,
                                 f"duplicate changed lines: {fingerprints.get(fingerprint)}")
                fingerprints[fingerprint] = entry["patch"]
                self.assertTrue(entry["failure"].strip())
                self.assertNotIn("/", entry["patch"])
                test_file = ROOT / entry["file"]
                tests = re.findall(r'^\s*test\s+"([^"\n]+)"', test_file.read_text(), re.MULTILINE)
                self.assertEqual(tests.count(entry["test"]), 1,
                                 "mutation must name exactly one test in its file")
                self.assertNotIn("selection", entry, "line selections must not retarget mutations")
                result = processes.run(["git", "apply", "--check", directory / entry["patch"]],
                    cwd=ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class MutationRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        folder = Path(self.temporary.name)
        self.root = folder / "repo"
        self.root.mkdir()
        self.directory = folder / "patches"
        self.directory.mkdir()
        self.log = folder / "executions"
        self.arguments = folder / "arguments"
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "Test")
        self.run_git("config", "user.email", "test@example.invalid")
        self.baseline = "value = 0\n"
        (self.root / "value.py").write_text(self.baseline)
        (self.root / "selected.py").write_text(
            "from pathlib import Path\nimport json, sys\nfrom value import value\n"
            f"log = Path({str(self.log)!r})\n"
            "with log.open('a') as output: output.write(str(value) + '\\n')\n"
            f"arguments = Path({str(self.arguments)!r})\n"
            "with arguments.open('a') as output: output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if value == 3: print('unrelated failure'); sys.exit(1)\n"
            "if value == 4: Path('residue').write_text('dirty')\n"
            "if value in (1, 2, 4): print('guard rejected mutation'); sys.exit(1)\n")
        self.run_git("add", "value.py", "selected.py")
        self.run_git("commit", "-qm", "Baseline")

    def run_git(self, *args):
        return mutations.command(["git", *args], root=self.root).stdout

    def entry(self, value):
        name = f"value-{value}.patch"
        patch = "".join(difflib.unified_diff(
            self.baseline.splitlines(True), [f"value = {value}\n"],
            fromfile="a/value.py", tofile="b/value.py"))
        (self.directory / name).write_text(patch)
        return {"patch": name, "file": "selected.py", "test": "guard rejects value",
                "failure": "guard rejected mutation"}

    def prove(self, entry, green=None):
        return mutations.prove(entry, green=green, root=self.root,
                               directory=self.directory, test_command=(sys.executable, "-B"))

    def test_green_is_required_once_for_each_selected_command(self):
        green = set()
        for value in (1, 2):
            self.assertIn("GREEN baseline; RED", self.prove(self.entry(value), green))
        self.assertEqual(self.log.read_text().splitlines(), ["0", "1", "2"])
        different = self.entry(1)
        different["test"] = 'another named case: spaces and "quotes"'
        self.prove(different, green)
        self.assertEqual(self.log.read_text().splitlines()[-2:], ["0", "1"])
        argv = [json.loads(line) for line in self.arguments.read_text().splitlines()]
        self.assertEqual(argv[:3], [["--only", "test:test guard rejects value"]] * 3)
        self.assertEqual(argv[3:], [["--only", "test:test " + different["test"]]] * 2)
        self.assertEqual(self.run_git("status", "--porcelain"), "")
        (self.root / "revision").write_text("new baseline\n")
        self.run_git("add", "revision")
        self.run_git("commit", "-qm", "Next baseline")
        self.prove(self.entry(2), green)
        self.assertEqual(self.log.read_text().splitlines()[-2:], ["0", "2"])

    def test_line_changes_keep_the_named_test_in_runner_arguments(self):
        entry = self.entry(1)
        self.prove(entry)
        selected = self.root / "selected.py"
        selected.write_text("\n\n" + selected.read_text())
        self.run_git("add", "selected.py")
        self.run_git("commit", "-qm", "Move fixture lines")
        self.prove(entry)
        argv = [json.loads(line) for line in self.arguments.read_text().splitlines()]
        self.assertEqual(argv, [["--only", "test:test " + entry["test"]]] * 4)

    def test_non_green_baseline_never_applies_mutant(self):
        (self.root / "selected.py").write_text("print('guard rejected mutation'); raise SystemExit(1)\n")
        self.run_git("add", "selected.py")
        self.run_git("commit", "-qm", "Failing baseline")
        with self.assertRaisesRegex(RuntimeError, "baseline is not GREEN"):
            self.prove(self.entry(1))
        self.assertEqual((self.root / "value.py").read_text(), self.baseline)
        self.assertEqual(self.run_git("status", "--porcelain"), "")

    def test_survivor_and_unrelated_failure_are_reverted(self):
        for value, error in [(5, "remained GREEN"), (3, "without its claimed assertion")]:
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, error):
                self.prove(self.entry(value))
            self.assertEqual((self.root / "value.py").read_text(), self.baseline)
            self.assertEqual(self.run_git("status", "--porcelain"), "")

    def test_dirty_post_reversal_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "requires a clean tree"):
            self.prove(self.entry(4))
        self.assertEqual((self.root / "value.py").read_text(), self.baseline)
        self.assertTrue((self.root / "residue").is_file())

    def test_fingerprint_ignores_context_and_file_metadata(self):
        a = "--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n before\n-old\n+new\n after\n"
        b = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -2 +2 @@\n-old\n+new\n"
        self.assertEqual(changed_lines(a), changed_lines(b))
        self.assertNotEqual(changed_lines(a), changed_lines(b.replace("+new", "+other")))
        (self.root / "x").write_text("prefix\nbefore\nold\nafter\n")
        self.assertEqual(changed_lines(a, self.root), changed_lines(b, self.root))

    def test_fingerprint_normalizes_whitespace_and_repeated_lines_in_one_function(self):
        baseline = ("defmodule Sample do\n"
                    "  defp run(x, {a, b}) do\n    send(x, a)\n    send(x, a)\n  end\n"
                    "  defp other(x, {a, b}) do\n    send(x, a)\n  end\nend\n")
        (self.root / "sample.ex").write_text(baseline)

        def patch(line, value):
            lines = baseline.splitlines(True)
            lines[line - 1] = value + "\n"
            return "".join(difflib.unified_diff(baseline.splitlines(True), lines,
                           fromfile="a/sample.ex", tofile="b/sample.ex", n=0))

        first = changed_lines(patch(3, "    send(x, b)"), self.root)
        whitespace = changed_lines(patch(3, "  send( x,  b )  "), self.root)
        duplicate_line = changed_lines(patch(4, "    send(x, b)"), self.root)
        other_function = changed_lines(patch(7, "    send(x, b)"), self.root)
        self.assertEqual(first, whitespace)
        self.assertEqual(first, duplicate_line)
        self.assertNotEqual(first, other_function)
        self.assertEqual(first[0][1], ("run", 2))
        self.assertEqual(enclosing_function(["def run(a, b)", "def run(a)"], 2), ("run", 1))
        self.assertEqual(enclosing_function(["def run(a, b)"], 1), ("run", 2))


if __name__ == "__main__":
    processes.install_signal_handlers()
    unittest.main()
