defmodule RequestSeal.DependencyRangesTest do
  use ExUnit.Case, async: true

  test "every dependency admits its lock and caps compatibility below the next major" do
    lock = Mix.Dep.Lock.read()

    for {name, requirement, _options} <-
          Enum.map(Mix.Project.config()[:deps], fn
            {name, requirement} -> {name, requirement, []}
            dep -> dep
          end),
        {:hex, _, locked, _, _, _, _, _} = lock[name] do
      version = Version.parse!(locked)
      assert Version.match?(locked, requirement), Atom.to_string(name)
      refute Version.match?("#{version.major + 1}.0.0", requirement), Atom.to_string(name)

      assert requirement =~
               ~r/^(>= \d+\.\d+\.\d+ and < \d+\.\d+\.\d+|~> \d+\.\d+(\.\d+)?( and >= \d+\.\d+\.\d+)?)$/,
             Atom.to_string(name)
    end
  end

  test "published dependencies retain explicit floors and supported range shapes" do
    lock = Mix.Dep.Lock.read()

    for dep <- Mix.Project.config()[:deps] do
      {name, requirement, options} =
        case dep do
          {name, requirement} -> {name, requirement, []}
          dep -> dep
        end

      if Keyword.has_key?(options, :only) do
        {:hex, _, locked, _, _, _, _, _} = lock[name]

        if Version.parse!(locked).major == 0 do
          assert requirement =~ ~r/^~> 0\.\d+(\.\d+)?$/, Atom.to_string(name)
        end
      else
        assert_published_shape(requirement, name)
      end
    end
  end

  defp assert_published_shape("~> 0." <> _ = requirement, name) do
    assert requirement =~ ~r/^~> 0\.\d+\.\d+$/, Atom.to_string(name)
  end

  defp assert_published_shape("~> " <> _ = requirement, name) do
    assert [_, major, minor, floor] =
             Regex.run(~r/^~> ([1-9]\d*)\.(\d+) and >= (\d+\.\d+\.\d+)$/, requirement),
           Atom.to_string(name)

    assert Version.match?(floor, "~> #{major}.#{minor}"), Atom.to_string(name)
  end

  defp assert_published_shape(requirement, name) do
    assert [_, floor, ceiling] =
             Regex.run(~r/^>= (\d+\.\d+\.\d+) and < (\d+\.\d+\.\d+)$/, requirement),
           Atom.to_string(name)

    floor = Version.parse!(floor)
    ceiling = Version.parse!(ceiling)
    assert Version.compare(floor, ceiling) == :lt, Atom.to_string(name)

    if floor.major >= 1 do
      assert ceiling == Version.parse!("#{floor.major + 1}.0.0"), Atom.to_string(name)
    else
      assert ceiling.major == 0, Atom.to_string(name)
    end
  end
end
