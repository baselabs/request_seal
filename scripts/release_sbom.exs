unless Mix.env() == :prod, do: Mix.raise("Release SBOM requires MIX_ENV=prod")

case System.argv() do
  ["--prepare", directory] ->
    unless File.regular?(Path.join(directory, "mix.exs")) and
             not File.exists?(Path.join(directory, "mix.lock")) and
             not File.exists?(Path.join(directory, "deps")) do
      Mix.raise("Release SBOM requires a freshly unpacked package directory")
    end

    dependencies = Mix.Dep.cached()

    # A library's lockfile also contains developer tools. Supply the generator
    # with the package bytes and Mix's resolved production closure, including
    # every optional integration, at the versions selected by this release.
    lock = Mix.Dep.Lock.read() |> Map.take(Enum.map(dependencies, & &1.app))
    File.write!(Path.join(directory, "mix.lock"), inspect(lock, pretty: true, limit: :infinity))
    File.mkdir_p!(Path.join(directory, "deps"))

    for dependency <- dependencies do
      File.ln_s!(
        dependency.opts[:dest],
        Path.join([directory, "deps", Atom.to_string(dependency.app)])
      )
    end

  ["--verify", path] ->
    bom = path |> File.read!() |> :json.decode()
    config = Mix.Project.config()
    root = bom["metadata"]["component"]

    unless bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6" and
             root["name"] == "request_seal" and root["version"] == config[:version] and
             root["type"] == "library" do
      Mix.raise("Release SBOM must describe this library and version in CycloneDX 1.6")
    end

    components = Map.new(bom["components"], &{&1["name"], &1})
    dependencies = Mix.Dep.cached()
    expected = MapSet.new(dependencies, &Atom.to_string(&1.app))
    actual = components |> Map.keys() |> MapSet.new()

    unless actual == expected and map_size(components) == length(bom["components"]) do
      Mix.raise(
        "Release SBOM dependency mismatch: missing=#{inspect(MapSet.difference(expected, actual))} " <>
          "extra=#{inspect(MapSet.difference(actual, expected))}; components must be unique"
      )
    end

    lock = Mix.Dep.Lock.read()

    for dependency <- dependencies do
      name = Atom.to_string(dependency.app)
      version = lock |> Map.fetch!(dependency.app) |> elem(2)

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
