defmodule RequestSeal.Conformance do
  @moduledoc false
  alias RequestSeal.Conformance.{Canonical, Surfaces, StructuredFields}

  def run(root, opts \\ []) do
    {:ok, modules} = :application.get_key(:request_seal, :modules)
    Enum.each(modules, &Code.ensure_loaded!/1)

    try do
      raw = File.read!(Path.join(root, "index.json"))

      require!(
        sha(raw) == Keyword.get(opts, :index_sha256, RequestSeal.Conformance.Pin.sha256()),
        :index_digest
      )

      index = json(raw)
      require!(Canonical.encode(index) == raw, :canonical_index)
      require!(index["format"] == "request-seal-conformance-corpus-index/1", :index_format)
      verify_files!(root, index)
      cases = index["cases"]
      require!(is_list(cases) and cases != [], :case_inventory)
      require!(length(cases) == MapSet.size(MapSet.new(cases, & &1["id"])), :duplicate_case)
      manifests = Enum.map(cases, & &1["manifest"])
      require!(length(manifests) == MapSet.size(MapSet.new(manifests)), :duplicate_manifest)

      listed =
        Enum.map(index["files"], & &1["path"]) |> Enum.filter(&String.starts_with?(&1, "cases/"))

      require!(Enum.sort(manifests) == Enum.sort(listed), :case_inventory)

      case_ids = MapSet.new(cases, & &1["id"])

      Enum.each(cases, fn entry ->
        case_ = json(read_file(root, entry["manifest"]))

        if Map.has_key?(case_, "positive") do
          require!(
            case_["positive"] != entry["id"] and
              MapSet.member?(case_ids, case_["positive"]),
            :positive_reference
          )

          require!(case_["evidence_class"] == "reviewed_derivation", :positive_evidence)
        end
      end)

      marker = index["known_positive"]

      require!(
        is_binary(marker) and
          Enum.any?(cases, &(&1["id"] == marker and &1["class"] in ["byte_exact", "verify_only"])),
        :known_positive
      )

      initial = %{
        singles: 0,
        batches: 0,
        batch_items: 0,
        not_applicable: 0,
        not_applicable_declared: 0,
        executed: 0,
        disagreements: [],
        ids: MapSet.new()
      }

      report =
        Enum.reduce(cases, initial, fn entry, state ->
          try do
            execute_case(root, entry, state)
          rescue
            error -> raise ArgumentError, "#{entry["id"]}: #{Exception.message(error)}"
          end
        end)

      require!(MapSet.member?(report.ids, marker), :known_positive)
      require!(report.not_applicable == report.not_applicable_declared, :not_applicable_count)

      require!(
        report.executed + report.not_applicable == report.singles + report.batch_items,
        :cardinality
      )

      if report.disagreements == [],
        do: {:ok, Map.delete(report, :ids)},
        else:
          {:error, {:disagreements, Enum.reverse(report.disagreements), Map.delete(report, :ids)}}
    rescue
      error -> {:error, {:invalid_corpus, Exception.message(error)}}
    catch
      {:corpus, reason} -> {:error, reason}
    end
  end

  def sha(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  def json(bytes) do
    {value, _, rest} = :json.decode(bytes, nil, %{null: nil})
    require!(String.trim(rest) == "", :json_trailing_bytes)
    value
  end

  def int(%{"int" => value} = tag) when map_size(tag) == 1, do: String.to_integer(value)

  def bytes(%{"b64" => value} = tag) when map_size(tag) == 1 do
    decoded = Base.url_decode64!(value, padding: false)
    require!(Base.url_encode64(decoded, padding: false) == value, :byte_encoding)
    decoded
  end

  def bytes(value) when is_binary(value), do: value
  def b64(value), do: %{"b64" => Base.url_encode64(value, padding: false)}
  def number(value), do: %{"int" => Integer.to_string(value)}
  def require!(true, _), do: :ok
  def require!(_, reason), do: throw({:corpus, reason})

  def load(root, %{"ref" => %{"file" => file, "pointer" => pointer}}) do
    data = read_file(root, file) |> json()

    case pointer do
      "" ->
        data

      "/" <> path ->
        Enum.reduce(String.split(path, "/"), data, fn key, value ->
          key = key |> String.replace("~1", "/") |> String.replace("~0", "~")

          if is_list(value),
            do: Enum.fetch!(value, String.to_integer(key)),
            else: Map.fetch!(value, key)
        end)
    end
  end

  def load(_, value), do: value

  def read_file(root, path) do
    require!(
      (is_binary(path) and String.starts_with?(path, "sources/")) or
        (is_binary(path) and String.starts_with?(path, "cases/")),
      :unsafe_path
    )

    require!(Enum.all?(Path.split(path), &(&1 not in ["..", ".", ""])), :unsafe_path)
    file = Path.join(root, path)
    require!(File.lstat!(file).type != :symlink, :unsafe_path)
    File.read!(file)
  end

  defp verify_files!(root, index) do
    files = index["files"]
    paths = Enum.map(files, & &1["path"])

    require!(
      paths == Enum.sort(paths) and length(paths) == MapSet.size(MapSet.new(paths)),
      :file_inventory
    )

    require!(Enum.sort(File.ls!(root)) == ["cases", "index.json", "sources"], :unlisted_file)

    require!(
      Enum.all?(
        ["index.json", "cases", "sources"],
        &(File.lstat!(Path.join(root, &1)).type != :symlink)
      ),
      :unsafe_path
    )

    tree = Path.wildcard(Path.join([root, "**", "*"]), match_dot: true)
    require!(Enum.all?(tree, &(File.lstat!(&1).type != :symlink)), :unsafe_path)

    actual =
      for folder <- ["sources", "cases"],
          file <- Path.wildcard(Path.join([root, folder, "**", "*"]), match_dot: true),
          not File.dir?(file),
          do: Path.relative_to(file, root)

    require!(Enum.all?(paths, &(&1 in actual)), :missing_file)
    require!(Enum.sort(actual) == paths, :unlisted_file)

    Enum.each(files, fn f ->
      require!(sha(read_file(root, f["path"])) == f["sha256"], {:file_digest, f["path"]})
    end)
  end

  defp execute_case(root, entry, state) do
    raw = read_file(root, entry["manifest"])
    case_ = json(raw)
    require!(Canonical.encode(case_) == raw, :canonical_manifest)
    require!(Enum.all?(["id", "surface", "class"], &(case_[&1] == entry[&1])), :case_metadata)

    require!(
      case_["evidence_class"] in ["published_vector", "reviewed_derivation"] and
        is_map(case_["source"]),
      :evidence
    )

    require!(
      case_["evidence_class"] != "reviewed_derivation" or is_binary(case_["derivation"]),
      :derivation
    )

    state = %{state | ids: MapSet.put(state.ids, entry["id"])}

    case case_["format"] do
      "request-seal-conformance-case/1" ->
        require!(case_["class"] in ["byte_exact", "verify_only", "rejection"], :case_class)
        actual = Surfaces.run(root, case_)
        matches = compare(actual, case_["expected"], case_["class"])
        state = %{state | singles: state.singles + 1, executed: state.executed + 1}
        disagreement(state, matches, entry["id"], actual)

      "request-seal-conformance-batch/1" ->
        require!(case_["class"] == "mixed", :case_class)
        batch = case_["batch"]
        require!(batch["count"] == entry["count"], :batch_count)
        declared = batch["not_applicable"]

        require!(
          match?(%{"int" => value} when is_binary(value), declared) and
            map_size(declared) == 1 and Regex.match?(~r/^(0|[1-9][0-9]*)$/, declared["int"]) and
            declared == entry["not_applicable"],
          :not_applicable_count
        )

        items = batch_items(root, batch)
        require!(length(items) == int(batch["count"]), :batch_count)

        # Source array positions identify items; upstream display names may repeat.
        if batch["item_format"] == "httpwg-structured-fields/1" do
          can_fail =
            Enum.filter(items, fn {_, v} -> v["can_fail"] == true end)
            |> Enum.map(fn {_, v} -> v["name"] end)
            |> Enum.sort()

          require!(Enum.sort(Map.keys(case_["pins"])) == can_fail, :pins)
        end

        overrides = Map.get(case_, "overrides", %{})
        require!(is_map(overrides), :overrides)
        item_names = MapSet.new(items, fn {_, item} -> item_name(item) end)
        require!(Enum.all?(Map.keys(overrides), &MapSet.member?(item_names, &1)), :overrides)

        Enum.each(overrides, fn {_, override} ->
          require!(
            case override do
              %{"outcome" => "reject", "rule_id" => rule, "clause" => clause} ->
                map_size(override) == 3 and is_binary(rule) and rule != "" and is_binary(clause) and
                  clause != ""

              %{"outcome" => "not_applicable", "reason" => reason} ->
                map_size(override) == 2 and is_binary(reason) and reason != ""

              _ ->
                false
            end,
            :overrides
          )
        end)

        state = %{
          state
          | batches: state.batches + 1,
            batch_items: state.batch_items + length(items),
            not_applicable_declared: state.not_applicable_declared + int(declared)
        }

        counted =
          Enum.reduce(Enum.with_index(items), state, fn {{group, item}, position}, state ->
            override = overrides[item_name(item)]

            if override && override["outcome"] == "not_applicable" do
              %{state | not_applicable: state.not_applicable + 1}
            else
              actual = batch_item(root, batch["item_format"], group, item, case_, override)
              id = entry["id"] <> "/" <> Integer.to_string(position)
              disagreement(%{state | executed: state.executed + 1}, actual == true, id, actual)
            end
          end)

        require!(
          counted.not_applicable - state.not_applicable == int(declared),
          :not_applicable_count
        )

        counted

      _ ->
        throw({:corpus, :case_format})
    end
  end

  defp disagreement(state, true, _, _), do: state

  defp disagreement(state, false, id, actual),
    do: %{state | disagreements: [{id, actual} | state.disagreements]}

  defp compare({:error, error}, %{"rule_id" => expected}, "rejection"),
    do: rule_id(error) == expected

  defp compare({:ok, actual}, expected, class) when class in ["byte_exact", "verify_only"],
    do: Canonical.encode(actual) == Canonical.encode(expected)

  defp compare(_, _, _), do: false

  defp batch_items(root, batch) do
    data = read_file(root, batch["file"]) |> json()

    case batch["item_format"] do
      "rfc9421-signature-bases/1" ->
        Enum.flat_map(data, fn item ->
          transformations =
            Enum.map(item["transformations"] || [], fn transformation ->
              {nil, Map.merge(Map.take(item, ["parameters", "base"]), transformation)}
            end)

          [{nil, item} | transformations]
        end)

      _ ->
        if is_list(data),
          do: Enum.map(data, &{nil, &1}),
          else: for(g <- data["testGroups"], t <- g["tests"], do: {g, t})
    end
  end

  defp batch_item(_, "httpwg-structured-fields/1", _, item, case_, _),
    do: StructuredFields.item(item, case_["pins"])

  defp batch_item(root, "rfc9421-signature-bases/1", _, item, _, _),
    do: Surfaces.signature_base_item(root, item)

  defp batch_item(_, "wycheproof-aes-gcm/1", group, item, _, override),
    do: Surfaces.aes_gcm_item(group, item, override)

  defp batch_item(_, "wycheproof-rsa-oaep/1", group, item, _, override),
    do: Surfaces.rsa_oaep_item(group, item, override)

  defp batch_item(_, "wycheproof-ed25519/1", group, item, _, override),
    do: Surfaces.ed25519_item(group, item, override)

  defp batch_item(_, "wycheproof-ecdsa/1", group, item, _, override),
    do: Surfaces.ecdsa_item(group, item, override)

  defp batch_item(_, _, _, _, _, _), do: throw({:corpus, :item_format})

  defp item_name(%{"tcId" => id}), do: Integer.to_string(id)
  defp item_name(item), do: item["name"]

  def rule_id(%{__struct__: struct, reason: reason} = error) do
    kind =
      Map.fetch!(
        %{
          RequestSeal.Error => "core",
          RequestSeal.Message.Error => "message",
          RequestSeal.StructuredFields.Error => "structured_fields",
          RequestSeal.SignatureBase.Error => "signature_base",
          RequestSeal.Digest.Error => "digest",
          RequestSeal.Crypto.Error => "crypto",
          RequestSeal.Custody.Error => "custody",
          RequestSeal.Discovery.Error => "discovery",
          RequestSeal.JOSE.Error => "jose",
          RequestSeal.Replay.Error => "replay",
          RequestSeal.Adapter.Error => "adapter"
        },
        struct
      )

    kind <>
      "/" <>
      if(kind in ["core", "jose"], do: Atom.to_string(error.layer) <> ".", else: "") <>
      Atom.to_string(reason)
  end
end
