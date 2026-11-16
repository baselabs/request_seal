defmodule RequestSeal.ToolchainTest do
  use ExUnit.Case, async: true

  test "the consumer Elixir requirement agrees with the lowest toolchain minor" do
    [_, versions] =
      Regex.run(~r/^elixir\s+(.+)$/m, File.read!(Path.expand("../.tool-versions", __DIR__)))

    floor =
      versions
      |> String.split()
      |> Enum.map(fn version ->
        version |> String.split("-otp-", parts: 2) |> hd() |> Version.parse!()
      end)
      |> Enum.min(Version)

    assert Mix.Project.config()[:elixir] == "~> #{floor.major}.#{floor.minor}"
  end
end
