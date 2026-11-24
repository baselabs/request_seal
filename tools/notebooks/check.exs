defmodule RequestSeal.NotebookCheck do
  def validate!(notebook) do
    for section <- [notebook.setup_section | notebook.sections] do
      if section.parent_id != nil, do: raise("Branched sections require explicit execution")

      for cell <- section.cells do
        case cell do
          %Livebook.Notebook.Cell.Markdown{} -> :ok
          %Livebook.Notebook.Cell.Code{language: :elixir} -> :ok
          _ -> raise "Unsupported executable cell; refusing silent omission"
        end
      end
    end
  end

  def code_cells(notebook) do
    for section <- [notebook.setup_section | notebook.sections],
        cell <- section.cells,
        match?(%Livebook.Notebook.Cell.Code{}, cell),
        String.trim(cell.source) != "",
        do: cell
  end

  def verify_export!(cells, source) do
    if cells == [], do: raise("Notebook must contain nonempty Elixir code")

    Enum.reduce(cells, source, fn cell, remaining ->
      case :binary.match(remaining, "\n" <> cell.source <> "\n") do
        {offset, length} ->
          binary_part(remaining, offset + length, byte_size(remaining) - offset - length)

        :nomatch ->
          raise "Notebook export omitted or reordered a code cell"
      end
    end)

    :ok
  end

  def export!(markdown) do
    if String.contains?(markdown, ["\"hub_id\"", "\"stamp\"", "\"file_entries\""]) do
      raise "Notebook requires a service-backed import"
    end

    {notebook, info} = Livebook.LiveMarkdown.Import.notebook_from_livemd(markdown)
    if info.warnings != [], do: raise("Livebook import warnings: #{inspect(info.warnings)}")
    validate!(notebook)
    cells = code_cells(notebook)
    source = Livebook.Notebook.Export.Elixir.notebook_to_elixir(notebook)
    verify_export!(cells, source)
    {source, length(cells)}
  end

  def install_requirement(root, version \\ nil) do
    python =
      System.get_env("REQUESTSEAL_PYTHON") || System.find_executable("python3") ||
        raise("Python interpreter unavailable: python3 is required to derive notebook installs")

    args = [Path.join(root, "scripts/release.py"), "--install-requirement"]
    args = if version, do: args ++ ["--for-version", version], else: args

    case System.cmd(python, args) do
      {requirement, 0} -> String.trim(requirement)
      _ -> raise "Cannot derive the notebook install requirement"
    end
  end

  def local_source!(source, root, version \\ nil, packed_source \\ nil) do
    if String.contains?(source, "Mix.install") and String.contains?(source, ":request_seal") do
      # RequestSeal is the first dependency; optional integrations may follow it.
      install = "Mix.install([" <> inspect({:request_seal, install_requirement(root, version)})

      unless length(String.split(source, install)) == 2 do
        raise "Notebook must contain exactly one matching Hex install cell"
      end

      String.replace(
        source,
        install,
        "Mix.install([" <> inspect({:request_seal, [path: packed_source || root]})
      )
    else
      source
    end
  end

  def rejects!(name, expectation, operation) do
    try do
      operation.()
    rescue
      error in RuntimeError ->
        unless String.contains?(Exception.message(error), expectation),
          do: reraise(error, __STACKTRACE__)

        IO.puts("PASS rejection: #{name}")
    else
      _ -> raise "Runner accepted mutation: #{name}"
    end
  end

  def self_test!(markdown) do
    {source, _} = export!(markdown)
    {notebook, _} = Livebook.LiveMarkdown.Import.notebook_from_livemd(markdown)
    cells = code_cells(notebook)
    empty = Regex.replace(~r/```elixir\n.*?\n```/s, markdown, "")
    rejects!("empty notebook", "nonempty", fn -> export!(empty) end)
    omitted = String.replace(source, List.last(cells).source, "", global: false)
    rejects!("omitted code cell", "omitted", fn -> verify_export!(cells, omitted) end)
    section = hd(notebook.sections)

    branch = %{
      notebook
      | sections: [%{section | parent_id: "mutated-parent"} | tl(notebook.sections)]
    }

    rejects!("branched section", "Branched", fn -> validate!(branch) end)
    unsupported = %{section | cells: [%{hd(cells) | language: :python}]}

    rejects!("unsupported cell", "Unsupported", fn ->
      validate!(%{notebook | sections: [unsupported]})
    end)

    rejects!("import warning", "warnings", fn ->
      export!(markdown <> "\n<!-- livebook:{\"livebook_object\":\"cell_input\"} -->\n")
    end)

    rejects!("repeated cell omitted", "omitted", fn ->
      verify_export!(cells ++ [hd(cells)], source)
    end)

    rejects!("reordered code", "omitted", fn -> verify_export!(Enum.reverse(cells), source) end)

    quoted =
      "# Export coverage\n\n## Quoted code\n\n```elixir\nIO.puts(\"actual code\")\n```\n\nIO.puts(\"actual code\")\n"

    {quoted_source, _} = export!(quoted)
    {quoted_notebook, _} = Livebook.LiveMarkdown.Import.notebook_from_livemd(quoted)

    commented_only =
      String.replace(quoted_source, "\nIO.puts(\"actual code\")\n", "\n", global: false)

    rejects!("commented Markdown cannot satisfy code coverage", "omitted", fn ->
      verify_export!(code_cells(quoted_notebook), commented_only)
    end)

    IO.puts("PASS: official notebook importer/exporter rejection checks")
  end
end

# Official Livebook parsing/export, with no Livebook application/server startup.
{:ok, _} = Application.ensure_all_started(:crypto)
root = Path.expand("../..", __DIR__)
directory = System.get_env("REQUESTSEAL_NOTEBOOK_DIR") || Path.join(root, "livebooks")
files = Path.wildcard(Path.join(directory, "*.livemd")) |> Enum.sort()

expected =
  Regex.scan(~r/\]\(([^)]+\.livemd)\)/, File.read!(Path.join(root, "livebooks/overview.md")))
  |> Enum.map(fn [_, path] -> Path.basename(path) end)
  |> Enum.sort()

unless "rfc-ed25519.livemd" in expected, do: raise("Known notebook missing from navigation")

if Enum.map(files, &Path.basename/1) != expected do
  raise "Notebook inventory differs from the documented curriculum"
end

if "--self-test" in System.argv() do
  RequestSeal.NotebookCheck.self_test!(
    File.read!(Path.join(root, "livebooks/rfc-ed25519.livemd"))
  )

  {source, _} =
    RequestSeal.NotebookCheck.export!(File.read!(Path.join(root, "livebooks/environment.livemd")))

  local = RequestSeal.NotebookCheck.local_source!(source, root)

  unless local != source and String.contains?(local, inspect({:request_seal, [path: root]})),
    do: raise("Local notebook execution must select the actual checkout")

  packed = Path.join(root, "packed-notebook-source")
  packed_local = RequestSeal.NotebookCheck.local_source!(source, root, nil, packed)

  unless String.contains?(packed_local, inspect({:request_seal, [path: packed]})) and
           not String.contains?(packed_local, inspect({:request_seal, [path: root]})),
         do: raise("Notebook consumer must install the selected packed source")

  for {name, changed} <- [
        {"duplicate install", source <> source},
        {"install version drift", String.replace(source, "~> ", "== ")},
        {"missing install cell", String.replace(source, "Mix.install([", "Mix.install( [")}
      ] do
    RequestSeal.NotebookCheck.rejects!(name, "matching Hex install cell", fn ->
      RequestSeal.NotebookCheck.local_source!(changed, root)
    end)
  end

  current_version =
    root
    |> Path.join("mix.exs")
    |> File.read!()
    |> then(&Regex.run(~r/@version "([^"]+)"/, &1))
    |> Enum.at(1)
    |> Version.parse!()

  bumped = "#{current_version.major}.#{current_version.minor + 1}.0-dev"

  RequestSeal.NotebookCheck.rejects!(
    "bumped version with stale install",
    "matching Hex install cell",
    fn ->
      RequestSeal.NotebookCheck.local_source!(source, root, bumped)
    end
  )

  previous_path = System.fetch_env("PATH")
  previous_python = System.fetch_env("REQUESTSEAL_PYTHON")

  try do
    System.put_env("PATH", "")
    System.delete_env("REQUESTSEAL_PYTHON")

    RequestSeal.NotebookCheck.rejects!("missing python3", "Python interpreter unavailable", fn ->
      RequestSeal.NotebookCheck.install_requirement(root)
    end)
  after
    for {name, previous} <- [{"PATH", previous_path}, {"REQUESTSEAL_PYTHON", previous_python}] do
      case previous do
        {:ok, value} -> System.put_env(name, value)
        :error -> System.delete_env(name)
      end
    end
  end

  hex_install = inspect({:request_seal, RequestSeal.NotebookCheck.install_requirement(root)})

  with_integration =
    String.replace(source, hex_install <> "])", hex_install <> ", {:plug, \"~> 1.20.4\"}])")

  integration_local = RequestSeal.NotebookCheck.local_source!(with_integration, root)

  unless with_integration != source and
           String.contains?(
             integration_local,
             inspect({:request_seal, [path: root]}) <> ", {:plug, \"~> 1.20.4\"}])"
           ),
         do: raise("Local notebook execution must keep integration dependencies")

  IO.puts("PASS: Hex install cell validation and explicit local execution selection")
else
  [scratch] = System.argv()
  packed_source = System.fetch_env!("REQUESTSEAL_PACKED_SOURCE")

  unless File.regular?(Path.join(packed_source, "mix.exs")) and
           not File.exists?(Path.join(packed_source, "mix.lock")),
         do: raise("Notebook consumer requires an unpacked archive without a seed lock")

  manifest =
    for {file, index} <- Enum.with_index(files) do
      {source, count} = RequestSeal.NotebookCheck.export!(File.read!(file))
      directory = Path.join(scratch, Integer.to_string(index))
      File.mkdir!(directory)
      script = Path.join(directory, "notebook.exs")
      completion = "REQUESTSEAL_COMPLETED_" <> Base.encode16(:crypto.strong_rand_bytes(24))
      local_source = RequestSeal.NotebookCheck.local_source!(source, root, nil, packed_source)
      File.write!(script, local_source <> "\nIO.puts(" <> inspect("\n" <> completion) <> ")\n")

      %{
        "script" => Path.relative_to(script, scratch),
        "completion" => completion,
        "notebook" => Path.basename(file),
        "cells" => count
      }
    end

  File.write!(Path.join(scratch, "manifest.json"), Jason.encode!(manifest))
  IO.puts("PASS #{length(files)} notebooks validated and exported for execution")
end
