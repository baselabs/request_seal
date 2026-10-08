defmodule RequestSeal.SignatureBase do
  @moduledoc """
  Exact ordered RFC 9421 Section 2 signature-base construction.

  `build/3` consumes a validated `RequestSeal.Message` and one signature's
  parameterized Inner List, either serialized bytes or a
  `RequestSeal.StructuredFields.Value` of type `:inner_list`. It returns
  `{:ok, bytes}` or a bounded `RequestSeal.SignatureBase.Error`, never a partial
  base. Components and all parameters retain their order; equivalent component
  identifiers with reordered parameters reject. The final `"@signature-params"`
  line has no trailing newline. This function performs no signing, verification,
  key operation, body read, network request, or authorization.

  All nine derived components are supported. `@request-target`, `@path`, and
  `@query` preserve percent-encoded octets. `@target-uri` assembles the preserved
  target URI without normalizing it. Only `@authority` and `@scheme` normalize
  host/scheme case and the HTTP(S) default port. Origin-form requests need the
  caller's explicit `:scheme`/`:authority` for these three origin components;
  absolute-form requests provide them in the raw target. Host and Forwarded
  fields never supply missing origin facts. Authority/asterisk-form target URIs
  have empty paths (RFC 9110 Section 7.1); `@path` normalizes an empty path to `/`.
  `req` requires a response with its validated original `:related_request`.

  `@query-param` requires the canonical encoded `name`, rejects duplicate decoded
  names, and preserves empty values. Parsing uses UTF-8 form semantics; encoding
  uses RFC 9421 Section 2.2.8's percent-encode-after-encoding operation and its
  published vectors (`%20` for spaces, uppercase hex, no double decoding), under
  the January 2024 URL Standard referenced by that RFC. Invalid UTF-8 rejects.

  Field values trim only HTTP OWS, preserve internal bytes, and combine ordered
  occurrences with comma-space. Capture must already have removed HTTP/1.1
  obsolete folding: `Message` rejects CR/LF. `bs` wraps each trimmed occurrence
  separately, including non-ASCII octets. Without `bs`, non-ASCII bytes reject.
  `tr` selects only trailers; unavailable or pending trailers reject. For fields
  whose unquoted commas make occurrence boundaries significant, callers must
  select `bs` (RFC 9421 Sections 2.1.3 and 7.5.6).

  Options:

  * `:field_schemas` — map of lowercase field names to explicit Structured Fields
    schemas, default `%{}`. `sf` and `key` require this knowledge. `key` requires
    a Dictionary schema and strictly serializes only the selected member. Schemas
    apply equally to headers, trailers, and the related request; the field's
    public specification selects its revision, never the input's syntax.
  * `:max_components` — positive ceiling, default/maximum 256.
  * `:max_bytes` — positive ceiling for the final base, default/maximum 1,048,576.

  The Structured Fields parser's documented ceilings also apply to signature
  parameters and `sf`/`key` fields (including 65,536 serialized bytes).
  Unknown/duplicate options, malformed direct values, unknown or incompatible
  component parameters, wrong parameter types, and unavailable components reject.
  Extension signature metadata retains RFC 8941 types; registered `created` and
  `expires` require Integers, and `nonce`, `alg`, `keyid`, and `tag` require Strings.
  Successful construction establishes bytes only, not authentication.
  """
  alias RequestSeal.Message
  alias RequestSeal.Message.Validation
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}
  alias RequestSeal.SignatureBase.Error

  @derived ~w(@method @target-uri @authority @scheme @request-target @path @query @query-param @status)
  @schema %Schema{
    revision: :rfc8941,
    type: :list,
    item_types: [:string],
    parameter_types: [:integer, :decimal, :string, :token, :bytes, :boolean],
    inner_lists: true
  }

  @doc "Build one ASCII signature base from preserved message facts and ordered parameters."
  @spec build(Message.t(), binary() | Value.t(), keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def build(message, parameters, opts \\ []) do
    ensure(Message.validate(message) == :ok, :invalid_message)
    options = options(opts)
    {parameters, serialized} = parameters(parameters)
    metadata(parameters.parameters)
    ensure(length(parameters.value) <= options.max_components, :limit)

    {output, size, _seen, _cache} =
      Enum.reduce(parameters.value, {[], 0, MapSet.new(), %{}}, fn component,
                                                                   {output, size, seen, cache} ->
        {name, params} = component(component)
        identity = {name, Enum.sort(component.parameters)}
        ensure(not MapSet.member?(seen, identity), :duplicate_component)
        source = context(message, params)
        {value, cache} = value(source, name, params, options, cache)
        ensure(ascii?(value), :non_ascii)
        identifier = serialize(component, %{@schema | type: :item}, :invalid_signature_parameters)
        line = [identifier, ": ", value, "\n"]
        size = size + IO.iodata_length(line)
        ensure(size <= options.max_bytes, :limit)
        {[line | output], size, MapSet.put(seen, identity), cache}
      end)

    final = ["\"@signature-params\": ", serialized]
    ensure(size + IO.iodata_length(final) <= options.max_bytes, :limit)
    {:ok, IO.iodata_to_binary([Enum.reverse(output), final])}
  catch
    {:signature_base, reason} -> {:error, %Error{reason: reason}}
  end

  defp ensure(true, _), do: :ok
  defp ensure(_, reason), do: fail(reason)
  defp fail(reason), do: throw({:signature_base, reason})

  defp options(opts) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)

    ensure(
      length(opts) <= 3 and length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))),
      :invalid_options
    )

    ensure(
      Enum.all?(opts, fn {key, _} -> key in [:field_schemas, :max_components, :max_bytes] end),
      :invalid_options
    )

    options =
      Map.merge(%{field_schemas: %{}, max_components: 256, max_bytes: 1_048_576}, Map.new(opts))

    ensure(
      is_integer(options.max_components) and options.max_components in 1..256 and
        is_integer(options.max_bytes) and options.max_bytes in 1..1_048_576,
      :invalid_options
    )

    schemas = options.field_schemas

    ensure(
      is_map(schemas) and map_size(schemas) <= 1024 and
        Enum.all?(schemas, fn {name, schema} ->
          field_name?(name) and Schema.validate(schema) == :ok
        end),
      :invalid_options
    )

    options
  end

  defp parameters(bytes) when is_binary(bytes) do
    case SF.parse(bytes, @schema) do
      {:ok, %Value{value: [%Value{type: :inner_list} = parameters]}} -> parameters(parameters)
      {:error, %{reason: :limit}} -> fail(:limit)
      _ -> fail(:invalid_signature_parameters)
    end
  end

  defp parameters(%Value{type: :inner_list} = parameters) do
    wrapper = %Value{type: :list, value: [parameters]}
    serialized = serialize(wrapper, @schema, :invalid_signature_parameters)
    {parameters, serialized}
  end

  defp parameters(_), do: fail(:invalid_signature_parameters)

  defp metadata(params) do
    Enum.each(params, fn
      {key, {type, _}} when key in ["created", "expires"] ->
        ensure(type == :integer, :invalid_signature_parameters)

      {key, {type, _}} when key in ["nonce", "alg", "keyid", "tag"] ->
        ensure(type == :string, :invalid_signature_parameters)

      _ ->
        :ok
    end)
  end

  defp component(%Value{type: :item, value: {:string, name}, parameters: parameters}) do
    ensure(
      name in @derived or field_name?(name),
      if(String.starts_with?(name, "@"), do: :unknown_component, else: :invalid_component)
    )

    allowed =
      if name in @derived,
        do: if(name == "@query-param", do: ["req", "name"], else: ["req"]),
        else: ["sf", "key", "bs", "tr", "req"]

    ensure(
      Enum.all?(parameters, fn
        {key, {:boolean, true}} -> key in allowed and key in ["sf", "bs", "tr", "req"]
        {key, {:string, _}} -> key in allowed and key in ["key", "name"]
        _ -> false
      end),
      :invalid_component_parameters
    )

    params = Map.new(parameters)
    ensure(name != "@query-param" or Map.has_key?(params, "name"), :invalid_component_parameters)

    ensure(
      not (Map.has_key?(params, "bs") and
             (Map.has_key?(params, "sf") or Map.has_key?(params, "key"))),
      :incompatible_parameters
    )

    {name, params}
  end

  defp component(_), do: fail(:invalid_signature_parameters)
  defp field_name?(name), do: Validation.token?(name, 256) and name == String.downcase(name)

  defp context(message, params) do
    if Map.has_key?(params, "req") do
      ensure(message.kind == :response, :wrong_message_kind)
      ensure(message.related_request != nil, :missing_request_context)
      message.related_request
    else
      message
    end
  end

  defp value(message, "@status", _, _, cache) do
    ensure(message.kind == :response, :wrong_message_kind)
    {Integer.to_string(message.status), cache}
  end

  defp value(message, "@query-param", params, _, cache) do
    ensure(message.kind == :request, :wrong_message_kind)
    query_parameter(message, params, cache)
  end

  defp value(message, "@" <> _ = name, _params, _, cache) do
    ensure(message.kind == :request, :wrong_message_kind)

    value =
      case name do
        "@method" ->
          message.method

        "@request-target" ->
          message.raw_target

        "@target-uri" ->
          target_uri(message)

        "@authority" ->
          authority(message)

        "@scheme" ->
          message |> origin() |> elem(0) |> String.downcase()

        "@path" ->
          case path_query(message) |> elem(0) do
            "" -> "/"
            path -> path
          end

        "@query" ->
          "?" <> (path_query(message) |> elem(1) || "")
      end

    {value, cache}
  end

  defp value(message, name, params, options, cache) do
    section = if Map.has_key?(params, "tr"), do: :trailers, else: :headers
    fields = if section == :trailers, do: message.trailers, else: message.fields
    ensure(is_list(fields), :unavailable_trailers)
    occurrences = Enum.filter(fields, &(String.downcase(&1.name) == name))
    ensure(occurrences != [], :missing_field)

    cond do
      Map.has_key?(params, "bs") ->
        value =
          Enum.map_join(occurrences, ", ", &(":" <> Base.encode64(trim_ows(&1.value)) <> ":"))

        {value, cache}

      Map.has_key?(params, "sf") or Map.has_key?(params, "key") ->
        key = {section, name, source_key(params)}
        structured(occurrences, name, params, options.field_schemas, cache, key)

      true ->
        {Enum.map_join(occurrences, ", ", &trim_ows(&1.value)), cache}
    end
  end

  defp source_key(params), do: if(Map.has_key?(params, "req"), do: :request, else: :self)

  defp cached(cache, key, parse) do
    case Map.fetch(cache, key) do
      {:ok, value} ->
        {value, cache}

      :error ->
        value = parse.()
        {value, Map.put(cache, key, value)}
    end
  end

  defp structured(occurrences, name, params, schemas, cache, key) do
    schema = Map.get(schemas, name)
    ensure(schema != nil, :unknown_field_schema)
    ensure(not Map.has_key?(params, "key") or schema.type == :dictionary, :invalid_field_schema)

    {parsed, cache} =
      cached(cache, key, fn ->
        bytes = Enum.map_join(occurrences, ", ", &trim_ows(&1.value))

        case SF.parse(bytes, schema) do
          {:ok, value} -> value
          {:error, %{reason: :limit}} -> fail(:limit)
          _ -> fail(:invalid_structured_field)
        end
      end)

    value =
      if Map.has_key?(params, "key") do
        {:string, key} = params["key"]
        member = List.keyfind(parsed.value, key, 0)
        ensure(member != nil, :missing_dictionary_key)
        {_, value} = member
        # SF top-level lists serialize Items and Inner Lists by the same member rule.
        serialize(
          %Value{type: :list, value: [value]},
          %{schema | type: :list},
          :invalid_structured_field
        )
      else
        serialize(parsed, schema, :invalid_structured_field)
      end

    {value, cache}
  end

  defp serialize(value, schema, reason) do
    case SF.serialize(value, schema) do
      {:ok, bytes} -> bytes
      {:error, %{reason: :limit}} -> fail(:limit)
      _ -> fail(reason)
    end
  end

  defp origin(%{target_form: :absolute, raw_target: raw}) do
    [_, scheme, authority] = Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?]+)/, raw)
    {scheme, authority}
  end

  defp origin(message) do
    ensure(message.scheme != nil and message.authority != nil, :unavailable_origin)
    {message.scheme, message.authority}
  end

  defp target_uri(%{target_form: :absolute, raw_target: raw}), do: raw

  defp target_uri(message) do
    {scheme, authority} = origin(message)
    tail = if message.target_form == :origin, do: message.raw_target, else: ""
    scheme <> "://" <> authority <> tail
  end

  defp authority(message) do
    {scheme, authority} = origin(message)
    [_, host | port] = Regex.run(~r/\A(\[[^\]]+\]|[^:]+)(?::([0-9]+))?\z/, authority)
    normalized = String.downcase(host)

    case port do
      [port] ->
        default =
          case String.downcase(scheme) do
            "http" -> 80
            "https" -> 443
            _ -> nil
          end

        if String.to_integer(port) == default, do: normalized, else: normalized <> ":" <> port

      [] ->
        normalized
    end
  end

  defp path_query(message) do
    tail =
      case message.target_form do
        :origin ->
          message.raw_target

        :absolute ->
          Regex.replace(~r/\A[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/?]+/, message.raw_target, "")

        _ ->
          ""
      end

    case :binary.split(tail, "?") do
      [path, query] -> {path, query}
      [path] -> {path, nil}
    end
  end

  defp query_parameter(message, params, cache) do
    {:string, name} = params["name"]
    ensure(encode_query(decode_query(name)) == name, :noncanonical_query_name)
    {query, cache} = cached(cache, {:query, source_key(params)}, fn -> parse_query(message) end)
    matches = Map.get(query, name, [])

    ensure(matches != [], :missing_query_parameter)
    ensure(length(matches) == 1, :ambiguous_query_parameter)
    {matches |> hd() |> decode_query() |> encode_query(), cache}
  end

  defp parse_query(message) do
    query = path_query(message) |> elem(1) || ""

    query
    |> :binary.split("&", [:global])
    |> Enum.reject(&(&1 == ""))
    |> Enum.reduce(%{}, fn entry, parsed ->
      {raw_name, value} =
        case :binary.split(entry, "=") do
          [key, value] -> {key, value}
          [key] -> {key, ""}
        end

      name = encode_query(decode_query(raw_name))
      Map.update(parsed, name, [value], &[value | &1])
    end)
  end

  defp decode_query(bytes) do
    # Message validation already rejects malformed percent escapes in the target.
    # The name is caller-supplied, so reject invalid escapes there as well.
    ensure(Validation.uri_bytes?(bytes), :invalid_query_encoding)
    decoded = bytes |> String.replace("+", " ") |> URI.decode()
    ensure(String.valid?(decoded), :invalid_query_encoding)
    decoded
  end

  defp encode_query(bytes) do
    for <<byte <- bytes>>, into: "" do
      if byte in ?a..?z or byte in ?A..?Z or byte in ?0..?9 or byte in ~c"*-._" do
        <<byte>>
      else
        "%" <> (byte |> Integer.to_string(16) |> String.upcase() |> String.pad_leading(2, "0"))
      end
    end
  end

  defp trim_ows(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.drop_while(&(&1 in [32, 9]))
    |> Enum.reverse()
    |> Enum.drop_while(&(&1 in [32, 9]))
    |> Enum.reverse()
    |> :binary.list_to_bin()
  end

  defp ascii?(bytes), do: ascii_bytes?(bytes)
  defp ascii_bytes?(""), do: true

  defp ascii_bytes?(<<byte, rest::binary>>) when byte == 9 or byte in 32..126,
    do: ascii_bytes?(rest)

  defp ascii_bytes?(_), do: false
end
