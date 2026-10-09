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

  def local_source!(source, root) do
    if String.contains?(source, "Mix.install") and String.contains?(source, ":request_seal") do
      [_, version] = Regex.run(~r/\bversion: "([^"]+)"/, File.read!(Path.join(root, "mix.exs")))
      install = "Mix.install([" <> inspect({:request_seal, "~> " <> version}) <> "])"

      unless length(String.split(source, install)) == 2 do
        raise "Notebook must contain exactly one matching Hex install cell"
      end

      String.replace(
        source,
        install,
        "Mix.install([" <> inspect({:request_seal, [path: root]}) <> "])"
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
  Regex.scan(~r/\]\(([^)]+\.livemd)\)/, File.read!(Path.join(root, "livebooks/README.md")))
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

  for {name, changed} <- [
        {"duplicate install", source <> source},
        {"install version drift", String.replace(source, "~> ", "== ")},
        {"missing install cell", String.replace(source, "Mix.install([", "Mix.install( [")}
      ] do
    RequestSeal.NotebookCheck.rejects!(name, "matching Hex install cell", fn ->
      RequestSeal.NotebookCheck.local_source!(changed, root)
    end)
  end

  IO.puts("PASS: Hex install cell validation and explicit local execution selection")
else
  for file <- files do
    {source, count} = RequestSeal.NotebookCheck.export!(File.read!(file))

    temporary =
      Path.join(
        System.tmp_dir!(),
        "requestseal-notebook-" <>
          Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
      )

    File.mkdir!(temporary)

    try do
      script = Path.join(temporary, "notebook.exs")
      completion = "REQUESTSEAL_COMPLETED_" <> Base.encode16(:crypto.strong_rand_bytes(24))
      local_source = RequestSeal.NotebookCheck.local_source!(source, root)
      File.write!(script, local_source <> "\nIO.puts(" <> inspect("\n" <> completion) <> ")\n")

      {output, status} =
        System.cmd(
          System.get_env("REQUESTSEAL_PYTHON") || System.find_executable("python3") ||
            raise("Python interpreter unavailable"),
          [Path.join(root, "scripts/check.py"), "--execute-notebook", script, completion],
          stderr_to_stdout: true
        )

      lines = String.split(output, "\n")
      IO.write(Enum.reject(lines, &(&1 == completion)) |> Enum.join("\n"))
      if status != 0, do: raise("Notebook failed: #{Path.basename(file)} (#{status})")

      unless Enum.count(lines, &(&1 == completion)) == 1,
        do: raise("Notebook did not complete: #{Path.basename(file)}")

      IO.puts(
        "PASS #{Path.basename(file)}: #{count} nonempty Elixir cells exported; completion receipt verified"
      )
    after
      File.rm_rf!(temporary)
    end
  end

  IO.puts("PASS #{length(files)} notebooks; no external peer or UI acceptance claimed")
end
