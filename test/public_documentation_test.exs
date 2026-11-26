defmodule RequestSeal.PublicDocumentationTest do
  use ExUnit.Case, async: false

  test "package attribution names the licenses of shipped code components" do
    licenses = Mix.Project.config() |> Keyword.fetch!(:package) |> Keyword.fetch!(:licenses)
    assert "Apache-2.0" in licenses
    assert "BSD-3-Clause" in licenses
    notice = File.read!("NOTICE")
    assert String.contains?(notice, "IETF Trust")
    assert String.contains?(notice, "Redistribution and use in source and binary forms")
  end

  test "package names every public guide instead of including documentation trees" do
    project = Mix.Project.config()
    files = project |> Keyword.fetch!(:package) |> Keyword.fetch!(:files)
    extras = public_extras()

    refute "lib" in files, "recursive library inclusion can ship non-code planning files"
    refute "docs" in files, "a directory inclusion can publish unreviewed documents"
    refute "livebooks" in files, "each notebook and guide needs an explicit inclusion"
    assert Enum.all?(extras, &(&1 in files)), "every public guide must ship in the package"
    assert Enum.all?(extras, &(Path.type(&1) == :relative and File.regular?(&1)))

    assert Enum.all?(extras, fn path ->
             Enum.all?(Path.split(path), &(not String.starts_with?(&1, ".")))
           end),
           "private and parent paths must never be exported"

    assert Enum.uniq(extras) == extras
    assert "README.md" in extras, "the public inventory must include the entry guide"
    assert "docs/guides/verifying-releases.md" in extras
    refute "docs/operations/releases.md" in extras
    refute "docs/operations/releases.md" in files

    assert Regex.match?(
             project[:docs][:groups_for_extras][:Guides],
             "docs/guides/verifying-releases.md"
           )
  end

  test "package versions derive scoped source refs and consumer requirements" do
    source = File.read!("mix.exs")
    quoted = Code.string_to_quoted!(source)
    # Evaluate the actual project functions without registering another Mix project.
    {:defmodule, _, [_, [do: {:__block__, _, body}]]} = quoted
    body = Enum.reject(body, &match?({:use, _, [{:__aliases__, _, [:Mix, :Project]}]}, &1))

    cases = "test/fixtures/release_versions.json" |> File.read!() |> :json.decode()

    for %{
          "version" => version,
          "source_ref" => expected,
          "development" => development?,
          "install_requirement" => requirement
        } <- cases do
      stable =
        version |> Version.parse!() |> Map.put(:pre, []) |> Map.put(:build, nil) |> to_string()

      assert Version.match?(if(development?, do: stable, else: version), requirement)

      {derived, 0} =
        System.cmd(System.find_executable("python3"), [
          "scripts/release.py",
          "--install-requirement",
          "--for-version",
          version
        ])

      assert String.trim(derived) == requirement

      module =
        Module.concat(__MODULE__, "Version#{String.replace(version, ~r/[^a-zA-Z0-9]/, "_")}")

      changed =
        Macro.prewalk({:__block__, [], body}, fn
          {:@, meta, [{:version, inner, [_]}]} -> {:@, meta, [{:version, inner, [version]}]}
          node -> node
        end)

      Module.create(module, changed, Macro.Env.location(__ENV__))
      project = module.project()
      assert project[:version] == version
      assert project[:docs][:source_ref] == expected

      :code.purge(module)
      :code.delete(module)
    end
  end

  defp public_extras do
    Mix.Project.config()
    |> Keyword.fetch!(:docs)
    |> Keyword.fetch!(:extras)
    |> Enum.map(fn
      {path, _options} -> path
      path -> path
    end)
  end
end
