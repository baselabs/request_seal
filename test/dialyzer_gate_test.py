"""Reject analysis suppressions using real Mix configuration and Elixir syntax."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_gate", ROOT / "scripts/check.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class DialyzerGateTest(unittest.TestCase):
    def assert_suppression(self, result, mechanism):
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("Dialyzer suppression is forbidden:", result.stdout)
        self.assertIn(mechanism, result.stdout)

    def check(self, configuration="[]", files=None, extra_project_code=""):
        command = ["mix", "run", "--no-compile", "--no-deps-check", "--no-start",
                   "-e", gate.DIALYZER_SUPPRESSION_CHECK]
        # Keep the fixture under the project so version managers use its pins.
        (ROOT / "_build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="dialyzer-gate-", dir=ROOT / "_build") as directory:
            root = Path(directory)
            (root / "mix.exs").write_text(
                "defmodule DialyzerGateFixture.MixProject do\n"
                "  use Mix.Project\n"
                "  def project, do: [app: :dialyzer_gate_fixture, version: \"0.0.0\", "
                f"dialyzer: {configuration}]\n"
                f"  {extra_project_code}\n"
                "end\n"
            )
            for name, content in (files or {}).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            return subprocess.run(command, cwd=root, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=60)

    def test_unsuppressed_configuration_passes(self):
        result = self.check(files={"lib/example.ex": """
defmodule Example do
  @moduledoc "The text @dialyzer is not an attribute."
  # @dialyzer {:nowarn_function, example: 0}
  def example, do: :ok
end
"""})
        self.assertEqual(0, result.returncode, result.stdout)

    def test_default_ignore_file_rejects_even_when_empty(self):
        for content in ("", "[]\n"):
            with self.subTest(content=content):
                result = self.check(files={".dialyzer_ignore.exs": content})
                self.assert_suppression(result, ".dialyzer_ignore.exs")

    def test_configured_ignore_file_rejects(self):
        result = self.check('[ignore_warnings: "config/analysis.exs"]',
                            {"config/analysis.exs": "[]\n"})
        self.assert_suppression(result, "ignore_warnings")

    def test_ignore_warnings_key_rejects_without_a_file(self):
        for configuration in ('[ignore_warnings: "absent.exs"]', '[ignore_warnings: nil]'):
            with self.subTest(configuration=configuration):
                result = self.check(configuration)
                self.assert_suppression(result, "ignore_warnings")

    def test_inactive_ignore_warnings_key_rejects(self):
        result = self.check(extra_project_code='''
def unused_configuration, do: [ignore_warnings: "absent.exs"]
''')
        self.assert_suppression(result, "ignore_warnings")

    def test_computed_ignore_warnings_key_rejects(self):
        result = self.check('Keyword.put([], String.to_atom("ignore_" <> "warnings"), nil)')
        self.assert_suppression(result, "ignore_warnings")

    def test_dialyzer_attributes_reject_in_nested_library_sources(self):
        for extension in ("ex", "exs"):
            with self.subTest(extension=extension):
                name = f"lib/nested/example.{extension}"
                result = self.check(files={name: """
defmodule Example do
  @dialyzer({:nowarn_function, example: 0})
  def example, do: :ok
end
"""})
                self.assert_suppression(result, f"@dialyzer in {name}")


if __name__ == "__main__":
    unittest.main()
