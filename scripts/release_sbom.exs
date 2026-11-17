defmodule RequestSeal.ReleaseSBOM do
  def lock! do
    quoted =
      Mix.Project.config()[:lockfile]
      |> File.read!()
      |> Code.string_to_quoted!(emit_warnings: false)

    unless Macro.quoted_literal?(quoted), do: Mix.raise("SBOM lockfile must contain literal data")
    {lock, []} = Code.eval_quoted(quoted)
    unless is_map(lock), do: Mix.raise("SBOM lockfile must contain a map")
    lock
  end

  def reject_paths!(value) when is_map(value) do
    Enum.each(value, fn {_key, item} -> reject_paths!(item) end)
  end

  def reject_paths!(value) when is_list(value), do: Enum.each(value, &reject_paths!/1)

  def reject_paths!(value) when is_binary(value) do
    value = Regex.replace(~r{https?://[^\s<>"']+}i, value, "")

    if Regex.match?(
         ~r{(?:^|[^A-Za-z0-9_.~/-])(?:/|[A-Za-z]:[\\/]|\\\\|~[^/\\\s]*[/\\])|file://|\$(?:HOME|TMPDIR)\b|\$\{(?:HOME|TMPDIR)\}|%USERPROFILE%|(?:^|[\s/\\])(?:home|tmp|temp|runner|_work)(?:[/\\]|$)}i,
         value
       ) do
      Mix.raise("Release SBOM contains a filesystem path")
    end
  end

  def reject_paths!(_value), do: :ok
end

unless Mix.env() == :prod, do: Mix.raise("Release SBOM requires MIX_ENV=prod")

case System.argv() do
  ["--prepare", directory] ->
    unless File.regular?(Path.join(directory, "mix.exs")) and
             not File.exists?(Path.join(directory, "mix.lock")) and
             not File.exists?(Path.join(directory, "deps")) do
      Mix.raise("Release SBOM requires a freshly unpacked package directory")
    end

    dependencies = Mix.Project.deps_paths()

    # A library's lockfile also contains developer tools. Supply the generator
    # with the package bytes and Mix's resolved production closure, including
    # every optional integration, at the versions selected by this release.
    lock = RequestSeal.ReleaseSBOM.lock!() |> Map.take(Map.keys(dependencies))
    File.write!(Path.join(directory, "mix.lock"), inspect(lock, pretty: true, limit: :infinity))
    File.mkdir_p!(Path.join(directory, "deps"))

    for {app, path} <- dependencies do
      File.ln_s!(path, Path.join([directory, "deps", Atom.to_string(app)]))
    end

  ["--verify", path] ->
    bom = path |> File.read!() |> :json.decode()
    RequestSeal.ReleaseSBOM.reject_paths!(bom)
    config = Mix.Project.config()
    root = bom["metadata"]["component"]

    unless bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6" and
             root["name"] == "request_seal" and root["version"] == config[:version] and
             root["type"] == "library" and
             is_binary(bom["serialNumber"]) and
             Regex.match?(
               ~r/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
               bom["serialNumber"]
             ) do
      Mix.raise("Release SBOM must describe this library and version in CycloneDX 1.6")
    end

    components = Map.new(bom["components"], &{&1["name"], &1})
    dependencies = Mix.Project.deps_paths()
    expected = MapSet.new(dependencies, fn {app, _} -> Atom.to_string(app) end)
    actual = components |> Map.keys() |> MapSet.new()

    unless actual == expected and map_size(components) == length(bom["components"]) do
      Mix.raise(
        "Release SBOM dependency mismatch: missing=#{inspect(MapSet.difference(expected, actual))} " <>
          "extra=#{inspect(MapSet.difference(actual, expected))}; components must be unique"
      )
    end

    lock = RequestSeal.ReleaseSBOM.lock!()

    for {app, _} <- dependencies do
      name = Atom.to_string(app)
      version = lock |> Map.fetch!(app) |> elem(2)

      unless components[name]["version"] == version,
        do: Mix.raise("Release SBOM version mismatch for #{name}")
    end

    references = MapSet.new([root | bom["components"]], & &1["bom-ref"])

    for dependency <- bom["dependencies"],
        reference <- [dependency["ref"] | Map.get(dependency, "dependsOn", [])] do
      unless MapSet.member?(references, reference),
        do: Mix.raise("Release SBOM contains an unresolved dependency reference")
    end

    unless components["telemetry"]["scope"] == "required",
      do: Mix.raise("Release SBOM must retain required telemetry")

    IO.puts("PASS: release SBOM matches the complete locked prod dependency set")

    for {name, component} <- Enum.sort(components),
        do: IO.puts("#{name} #{component["version"]} #{component["scope"]}")

  _ ->
    Mix.raise("Expected --prepare DIRECTORY or --verify SBOM")
end
