defmodule RequestSeal.JWEOpenAnalyzerTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Test.JWEOpenAnalyzer, as: Analyzer

  test "accepted lowered forms fixture" do
    {:ok, forms} = :epp.parse_file(~c"test/support/jwe_open_fixtures/accepted.erl", [], [])
    assert :ok == Analyzer.analyze_forms(:accepted, forms)
  end

  for {fixture, violation} <- [
        {"variable_callee", "dynamic callee"},
        {"variable_remote", "dynamic callee"},
        {"apply", "caller code reachable"},
        {"named_fun", "unknown or forbidden"},
        {"old_catch", "unknown or forbidden"}
      ] do
    test "refuses #{fixture}" do
      {:ok, forms} =
        :epp.parse_file(
          String.to_charlist("test/support/jwe_open_fixtures/" <> unquote(fixture) <> ".erl"),
          [],
          []
        )

      assert_raise RuntimeError, ~r/#{unquote(violation)}/, fn ->
        Analyzer.analyze_forms(String.to_atom(unquote(fixture)), forms)
      end
    end
  end

  test "on load and fun escape are rejected" do
    {:ok, forms} = :epp.parse_file(~c"test/support/jwe_open_fixtures/on_load.erl", [], [])
    assert_raise RuntimeError, ~r/on_load/, fn -> Analyzer.analyze_forms(:on_load, forms) end

    assert_raise RuntimeError, ~r/unapproved fun/, fn ->
      Analyzer.validate_forms!({:fun, 1, {:clauses, []}})
    end
  end

  test "unknown tags and missing debug information fail closed" do
    assert_raise RuntimeError, ~r/unknown or forbidden/, fn ->
      Analyzer.validate_forms!({:future_form, 1, []})
    end

    assert_raise RuntimeError, ~r/missing abstract code/, fn -> Analyzer.forms(:erlang) end
  end
end
