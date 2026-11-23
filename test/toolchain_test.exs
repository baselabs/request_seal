defmodule RequestSeal.ToolchainTest do
  use ExUnit.Case, async: true

  test "the consumer Elixir requirement agrees with the lowest toolchain minor" do
    root = Path.expand("..", __DIR__)
    {output, 0} = System.cmd(Path.join(root, "scripts/toolchain.sh"), [], cd: root)

    outputs =
      output
      |> String.split("\n", trim: true)
      |> Map.new(fn line ->
        [key, value] = String.split(line, "=", parts: 2)
        {key, value}
      end)

    lanes = :json.decode(outputs["beam_lanes"])

    floor =
      [outputs["elixir"] | Enum.map(lanes, & &1["elixir"])]
      |> Enum.map(fn version ->
        version |> String.split("-otp-", parts: 2) |> hd() |> Version.parse!()
      end)
      |> Enum.min(Version)

    assert Mix.Project.config()[:elixir] == "~> #{floor.major}.#{floor.minor}"
  end
end
