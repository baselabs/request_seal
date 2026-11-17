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

  def scopes(dependencies, lock) do
    roots =
      dependencies
      |> Enum.map(fn
        {app, options} when is_list(options) -> {app, options}
        {app, _requirement} -> {app, []}
        {app, _requirement, options} -> {app, options}
      end)
      |> Enum.filter(fn {_app, options} ->
        :prod in List.wrap(Keyword.get(options, :only, :prod))
      end)

    prod = closure(Enum.map(roots, &elem(&1, 0)), lock, MapSet.new())

    required =
      roots
      |> Enum.reject(fn {_app, options} -> Keyword.get(options, :optional, false) end)
      |> Enum.map(&elem(&1, 0))
      |> closure(lock, MapSet.new())

    Map.new(prod, &{&1, if(MapSet.member?(required, &1), do: "required", else: "optional")})
  end

  defp closure([], _lock, visited), do: visited

  defp closure([app | rest], lock, visited) do
    if MapSet.member?(visited, app) do
      closure(rest, lock, visited)
    else
      {:hex, _name, _version, _checksum, _managers, edges, _repo, _outer} = Map.fetch!(lock, app)

      children =
        for {child, _requirement, options} <- edges,
            not Keyword.get(options, :optional, false),
            do: child

      closure(children ++ rest, lock, MapSet.put(visited, app))
    end
  end

  def components!(bom, scopes) do
    components = Map.new(bom["components"], &{&1["name"], &1})
    expected = MapSet.new(scopes, fn {app, _} -> Atom.to_string(app) end)
    actual = components |> Map.keys() |> MapSet.new()

    unless actual == expected and map_size(components) == length(bom["components"]) do
      Mix.raise(
        "Release SBOM dependency mismatch: missing=#{inspect(MapSet.difference(expected, actual))} " <>
          "extra=#{inspect(MapSet.difference(actual, expected))}; components must be unique"
      )
    end

    components
  end

  def rewrite_scopes!(bom, scopes) do
    components!(bom, scopes)
    by_name = Map.new(scopes, fn {app, scope} -> {Atom.to_string(app), scope} end)

    Map.update!(bom, "components", fn components ->
      Enum.map(components, &Map.put(&1, "scope", Map.fetch!(by_name, &1["name"])))
    end)
  end

  def verify_scopes!(bom, scopes) do
    components = components!(bom, scopes)

    for {app, scope} <- scopes do
      name = Atom.to_string(app)

      unless components[name]["scope"] == scope,
        do: Mix.raise("Release SBOM scope mismatch for #{name}: expected #{scope}")
    end

    :ok
  end

  def reject_paths!(value, path \\ "")

  def reject_paths!(value, path) when is_map(value) do
    Enum.each(value, fn {key, item} ->
      reject_paths!(item, if(path == "", do: key, else: path <> "." <> key))
    end)
  end

  def reject_paths!(value, path) when is_list(value) do
    value
    |> Enum.with_index()
    |> Enum.each(fn {item, index} -> reject_paths!(item, "#{path}[#{index}]") end)
  end

  def reject_paths!(value, path) when is_binary(value) do
    # A URI's path is public protocol data unless it uses the file scheme.
    candidate =
      Regex.replace(
        ~r{\b(?!file:|[a-z]:[\\/])[a-z][a-z0-9+.-]*:[^\s<>"']+}i,
        value,
        ""
      )

    if Regex.match?(
         ~r{(?:^|[^A-Za-z0-9_.~/-])(?:/|[A-Za-z]:[\\/]|\\\\|~[^/\\\s]*[/\\])|\bfile:|\$(?:HOME|TMPDIR)\b|\$\{(?:HOME|TMPDIR)\}|%USERPROFILE%}i,
         candidate
       ) do
      Mix.raise("Release SBOM contains a filesystem path at #{path}: #{inspect(value)}")
    end

    :ok
  end

  def reject_paths!(_value, _path), do: :ok
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

    scopes =
      RequestSeal.ReleaseSBOM.scopes(Mix.Project.config()[:deps], RequestSeal.ReleaseSBOM.lock!())

    unless MapSet.new(Map.keys(dependencies)) == MapSet.new(Map.keys(scopes)),
      do: Mix.raise("Release SBOM prod closure disagrees with Mix dependencies")

    # A library's lockfile also contains developer tools. Supply the generator
    # with the package bytes and Mix's resolved production closure, including
    # every optional integration, at the versions selected by this release.
    lock = RequestSeal.ReleaseSBOM.lock!() |> Map.take(Map.keys(dependencies))
    File.write!(Path.join(directory, "mix.lock"), inspect(lock, pretty: true, limit: :infinity))
    File.mkdir_p!(Path.join(directory, "deps"))

    for {app, path} <- dependencies do
      File.ln_s!(path, Path.join([directory, "deps", Atom.to_string(app)]))
    end

  ["--rewrite-scopes", path] ->
    scopes =
      RequestSeal.ReleaseSBOM.scopes(Mix.Project.config()[:deps], RequestSeal.ReleaseSBOM.lock!())

    bom =
      path |> File.read!() |> :json.decode() |> RequestSeal.ReleaseSBOM.rewrite_scopes!(scopes)

    File.write!(path, :json.encode(bom))

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

    lock = RequestSeal.ReleaseSBOM.lock!()
    scopes = RequestSeal.ReleaseSBOM.scopes(config[:deps], lock)
    components = RequestSeal.ReleaseSBOM.components!(bom, scopes)
    RequestSeal.ReleaseSBOM.verify_scopes!(bom, scopes)

    for {app, _} <- scopes do
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

    IO.puts("PASS: release SBOM matches the complete locked prod dependency set")

    for {name, component} <- Enum.sort(components),
        do: IO.puts("#{name} #{component["version"]} #{component["scope"]}")

  _ ->
    Mix.raise("Expected --prepare DIRECTORY, --rewrite-scopes SBOM or --verify SBOM")
end
