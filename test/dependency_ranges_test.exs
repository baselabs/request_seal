defmodule RequestSeal.DependencyRangesTest do
  use ExUnit.Case, async: true

  test "every stable dependency range starts at its locked version and ends at the next major" do
    lock = Mix.Dep.Lock.read()

    for {name, requirement, _options} <-
          Enum.map(Mix.Project.config()[:deps], fn
            {name, requirement} -> {name, requirement, []}
            dep -> dep
          end),
        name != :ash_onetime,
        {:hex, _, locked, _, _, _, _, _} = lock[name],
        version = Version.parse!(locked),
        version.major >= 1 do
      assert requirement == ">= #{locked} and < #{version.major + 1}.0.0", Atom.to_string(name)
    end
  end
end
