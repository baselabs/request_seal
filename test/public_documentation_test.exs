defmodule RequestSeal.PublicDocumentationTest do
  use ExUnit.Case, async: true

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
