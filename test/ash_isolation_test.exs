defmodule RequestSeal.AshIsolationTest do
  use ExUnit.Case, async: false

  test "framework references are confined to the guarded protocol implementation" do
    files = Path.wildcard(Path.join(__DIR__, "../lib/**/*.ex"))
    # Positive control: the instrument sees the guarded protocol we actually invoke.
    hits =
      Enum.filter(files, fn file ->
        {:ok, ast} = Code.string_to_quoted(File.read!(file))

        {_, references} =
          Macro.prewalk(ast, [], fn
            {:__aliases__, _, [:Ash | _]} = node, refs -> {node, [node | refs]}
            node, refs -> {node, refs}
          end)

        references != []
      end)

    assert Enum.any?(hits, &String.ends_with?(&1, "/ash/scope.ex"))
    assert Enum.all?(hits, &String.contains?(&1, "/lib/request_seal/ash/"))

    {xref, status} =
      RequestSeal.SystemCommand.run("mix", ["xref", "graph", "--format", "plain"],
        stderr_to_stdout: true,
        env: [{"MIX_ENV", "test"}]
      )

    assert status == 0, xref
    assert xref =~ "lib/request_seal/ash/scope.ex"
  end
end
