defmodule RequestSeal.SignatureBase do
  @moduledoc """
  Exact ordered RFC 9421 Section 2 signature-base construction.

  `build/3` turns a validated `RequestSeal.Message` and one signature's
  parameterized Inner List into the exact signature base, never a partial base.
  Components and all parameters retain their order; equivalent component
  identifiers with reordered parameters reject. The final `"@signature-params"`
  line has no trailing newline. Construction performs no signing, verification,
  key operation, body read, network request, or authorization.

  Two component rules are deliberately stricter than a plain RFC 9421 reading,
  and cross-implementation peers should know them before relying on the edges
  (RFC 9421 Section 2.5): duplicate component identity is exact — the same
  component name with the same parameters in a different order rejects as
  `:duplicate_component` rather than coalescing — and duplicate identifiers
  that differ only in parameter order never merge.

  All nine derived components are supported. `@request-target`, `@path`, and
  `@query` preserve percent-encoded octets. `@target-uri` assembles the preserved
  target URI without normalizing it: percent-escape hex case and IPvFuture
  literal case pass through exactly, unlike `@authority`, which lowercases
  host and IPvFuture case — signers targeting both components from one target
  must send the bytes they signed for each. Only `@authority` and `@scheme`
  normalize host/scheme case and the HTTP(S) default port. Origin-form requests need the
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

  Structured Fields (`sf`) and dictionary member (`key`) components need an
  explicit schema for the field; `key` requires a Dictionary schema and
  strictly serializes only the selected member. Schemas apply equally to
  headers, trailers, and the related request; the field's public
  specification selects its revision, never the input's syntax. The
  Structured Fields parser's documented ceilings also apply to signature
  parameters and `sf`/`key` fields (including 65,536 serialized bytes).
  Extension signature metadata retains RFC 8941 types; registered `created` and
  `expires` require Integers, and `nonce`, `alg`, `keyid`, and `tag` require Strings.
  Successful construction establishes bytes only, not authentication.
  """
  alias RequestSeal.{Message, SignatureFields}
  alias RequestSeal.Message.Validation
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}
  alias RequestSeal.SignatureBase.Error

  @field_separator ", "
  @schema %Schema{
    revision: :rfc8941,
    type: :list,
    item_types: [:string],
    parameter_types: [:integer, :decimal, :string, :token, :bytes, :boolean],
    inner_lists: true
  }

  @doc """
  Build one ASCII signature base from preserved message facts and ordered parameters.

  ## Parameters

    * `message` - a `RequestSeal.Message`; it is validated first.
    * `parameters` - one signature's parameterized Inner List: serialized
      bytes such as `~s[("@method" "@path");created=1700000000]`, or a
      `RequestSeal.StructuredFields.Value` of type `:inner_list`.
    * `opts` - keyword list of the options below. Unknown and duplicate
      options reject with `:invalid_options`.

  ## Options

    * `:field_schemas` - map of at most 1,024 lowercase field names to
      explicit `RequestSeal.StructuredFields.Schema` values, required for
      `sf` and `key` components. Default `%{}`.
    * `:max_components` - component ceiling, 1 to 256. Default 256.
    * `:max_bytes` - ceiling for the final base, 1 to 1,048,576. Default 1,048,576.

  ## Returns

    * `{:ok, bytes}` - the signature base: one `identifier: value` line per
      component in order, then the `"@signature-params"` line.
    * `{:error, %RequestSeal.SignatureBase.Error{}}` - reasons this function
      can return: `:invalid_message`, `:invalid_options`,
      `:invalid_signature_parameters`, `:limit`; component reasons
      `:invalid_component`, `:unknown_component`, `:duplicate_component`,
      `:invalid_component_parameters`, `:incompatible_parameters`; context
      reasons `:wrong_message_kind`, `:missing_request_context`,
      `:unavailable_origin`, `:unavailable_trailers`, `:missing_field`; field
      reasons `:non_ascii`, `:unknown_field_schema`, `:invalid_field_schema`,
      `:invalid_structured_field`, `:missing_dictionary_key`; query reasons
      `:noncanonical_query_name`, `:invalid_query_encoding`,
      `:missing_query_parameter`, `:ambiguous_query_parameter`.
      Meanings: `RequestSeal.SignatureBase.Error`.

  ## Examples

      iex> {:ok, message} =
      ...>   RequestSeal.Message.request(
      ...>     "POST",
      ...>     "https://Telemetry.Example:443/v1/metrics?batch=7",
      ...>     [{"Content-Type", " application/json "}],
      ...>     "{}"
      ...>   )
      iex> {:ok, base} =
      ...>   RequestSeal.SignatureBase.build(
      ...>     message,
      ...>     ~s[("@method" "@authority" "@path" "@query-param";name="batch" "content-type");created=1700000000]
      ...>   )
      iex> String.split(base, "\\n")
      [
        ~s["@method": POST],
        ~s["@authority": telemetry.example],
        ~s["@path": /v1/metrics],
        ~s["@query-param";name="batch": 7],
        ~s["content-type": application/json],
        ~s["@signature-params": ("@method" "@authority" "@path" "@query-param";name="batch" "content-type");created=1700000000]
      ]
      iex> RequestSeal.SignatureBase.build(message, ~s[("@status")])
      {:error, %RequestSeal.SignatureBase.Error{reason: :wrong_message_kind}}
      iex> RequestSeal.SignatureBase.build(message, ~s[("x-sensor-id")])
      {:error, %RequestSeal.SignatureBase.Error{reason: :missing_field}}
  """
  @spec build(Message.t(), binary() | Value.t(), keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def build(message, parameters, opts \\ []) do
    ensure(Message.validate(message) == :ok, :invalid_message)
    build_validated(message, parameters, opts)
  catch
    {:signature_base, reason} -> {:error, %Error{reason: reason}}
  end

  # Internal fast path: the calling entry point has validated the message once.
  @doc false
  def build_validated(message, parameters, opts) do
    with {:ok, parts} <- derive(message, parameters, opts) do
      {:ok, rebuild(parts)}
    end
  end

  @doc """
  Inspect the ordered component values used by `build/3`.

  Takes the same message, parameters, and options as `build/3`, with the same
  validation, resource ceilings, and errors. Returns `{:ok, %{components:
  [{identifier, value}], signature_params: bytes}}`; identifiers include their
  serialized parameters. Both entry points use the same derivation. This
  establishes bytes only, without authenticating their source.

  ## Examples

      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
      iex> RequestSeal.SignatureBase.components(message, ~s[("@method")])
      {:ok, %{components: [{~s["@method"], "GET"}], signature_params: ~s[("@method")]}}
  """
  @spec components(Message.t(), binary() | Value.t(), keyword()) ::
          {:ok, %{components: [{binary(), binary()}], signature_params: binary()}}
          | {:error, Error.t()}
  def components(message, parameters, opts \\ []) do
    ensure(Message.validate(message) == :ok, :invalid_message)
    derive(message, parameters, opts)
  catch
    {:signature_base, reason} -> {:error, %Error{reason: reason}}
  end

  @doc """
  Parse a serialized RFC 9421 Section 2.5 signature base for inspection.

  Accepts at most 1,048,576 binary bytes. Component values must be printable
  ASCII or horizontal tabs. The final `"@signature-params"` line must contain a canonical RFC 8941
  Inner List of strings with parameters, within Structured Fields ceilings.
  Its ordered items must exactly match the preceding serialized identifiers.
  At most 256 component lines are scanned. Duplicate identifiers, invalid
  derived values, and a nonce over 1,024 bytes reject. LF separates lines.
  CRLF and a trailing LF reject.

  Contextual checks require the original message. These include the message
  kind and related request, field availability, structured field schemas,
  query occurrence counts, and equality with values derived from that message.

  Returns the ordered `components`, canonical `signature_params` bytes, and
  parsed `inner_list`. This performs no signature check and does not establish
  where any value came from. A binary above the byte ceiling returns `:limit`;
  every other invalid input or internal exception returns `:malformed`.

  ## Examples

      iex> base = ~s["@method": GET] <> "\\n" <> ~s["@signature-params": ("@method")]
      iex> {:ok, parsed} = RequestSeal.SignatureBase.parse(base)
      iex> parsed.components
      [{~s["@method"], "GET"}]
      iex> RequestSeal.SignatureBase.parse(base <> "\\n")
      {:error, %RequestSeal.SignatureBase.Error{reason: :malformed}}
  """
  @spec parse(term()) ::
          {:ok,
           %{
             components: [{binary(), binary()}],
             signature_params: binary(),
             inner_list: Value.t()
           }}
          | {:error, Error.t()}
  def parse(bytes) when is_binary(bytes) and byte_size(bytes) > 1_048_576,
    do: {:error, %Error{reason: :limit}}

  def parse(bytes) do
    {:ok, parse_base(bytes)}
  rescue
    _ -> {:error, %Error{reason: :malformed}}
  catch
    _, _ -> {:error, %Error{reason: :malformed}}
  end

  defp parse_base(bytes) when is_binary(bytes) do
    {lines, final} = base_lines(bytes, 256, [])
    <<"\"@signature-params\": ", serialized::binary>> = final
    {:ok, %Value{value: [%Value{type: :inner_list} = inner]}} = SF.parse(serialized, @schema)
    {:ok, ^serialized} = SF.serialize(%Value{type: :list, value: [inner]}, @schema)
    true = SignatureFields.valid_inner?(inner) and consistent_context?(inner.value)
    true = SignatureFields.nonce_valid?(SignatureFields.parameters(inner)["nonce"])
    {:ok, identifiers} = SignatureFields.identifiers(inner.value)
    true = length(lines) == length(identifiers)

    pairs =
      Enum.zip_with([lines, identifiers, inner.value], fn [line, identifier, item] ->
        prefix = identifier <> ": "
        true = String.starts_with?(line, prefix)
        value = binary_part(line, byte_size(prefix), byte_size(line) - byte_size(prefix))
        true = wire_value?(item, value)
        {identifier, value}
      end)

    parts = %{components: pairs, signature_params: serialized}
    ^bytes = rebuild(parts)
    Map.put(parts, :inner_list, inner)
  end

  defp base_lines(bytes, remaining, acc) do
    case :binary.split(bytes, "\n") do
      [final] -> {Enum.reverse(acc), final}
      [line, rest] when remaining > 0 -> base_lines(rest, remaining - 1, [line | acc])
      _ -> fail(:malformed)
    end
  end

  defp consistent_context?(items) do
    response? =
      Enum.any?(items, fn item ->
        item.value == {:string, "@status"} or List.keymember?(item.parameters, "req", 0)
      end)

    not response? or
      Enum.all?(items, fn %Value{value: {:string, name}, parameters: params} ->
        not SignatureFields.request_component?(name) or List.keymember?(params, "req", 0)
      end)
  end

  defp wire_value?(%Value{value: {:string, name}, parameters: params}, value),
    do: ascii?(value) and canonical_value?(name, Map.new(params), value)

  defp canonical_value?(name, params, value) do
    case name do
      "@method" ->
        Validation.token?(value, 256)

      "@status" ->
        case value do
          <<a, b, c>> when a in ?0..?9 and b in ?0..?9 and c in ?0..?9 ->
            Validation.status?(String.to_integer(value))

          _ ->
            false
        end

      "@scheme" ->
        Validation.scheme?(value) and value == String.downcase(value)

      "@authority" ->
        Validation.authority?(value) and value == String.downcase(value)

      "@path" ->
        String.starts_with?(value, "/") and :binary.match(value, "?") == :nomatch and
          uri_path_query?(value, 16_384)

      "@query" ->
        String.starts_with?(value, "?") and uri_path_query?(value, 16_383)

      "@query-param" ->
        {:string, name_param} = params["name"]
        query_component_wire?(name_param, value)

      "@target-uri" ->
        target_uri_wire?(value)

      "@request-target" ->
        byte_size(value) in 1..16_384 and Validation.uri_bytes?(value) and
          (value == "*" or
             (String.starts_with?(value, "/") and Validation.path_query?(value)) or
             Validation.absolute_form?(value) or Validation.authority?(value, true))

      _ ->
        field_wire?(params, value)
    end
  end

  defp target_uri_wire?(value) do
    byte_size(value) <= 17_475 and Validation.uri_bytes?(value) and
      Validation.absolute_form?(value) and
      (byte_size(value) <= 16_384 or
         case Regex.run(~r/\A[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/?]+(\/.*)\z/, value) do
           [_, path] -> byte_size(path) <= 16_384
           _ -> false
         end)
  end

  defp query_component_wire?(name, value) do
    # A shortest witness uses an origin-form target beginning with "/?".
    # Nonempty names can omit "=" when the value is empty.
    separator = if name == "" or value != "", do: 1, else: 0

    canonical_query?(name) and canonical_query?(value) and
      2 + separator + query_wire_size(name, false, 0) + query_wire_size(value, true, 0) <= 16_384
  end

  defp query_wire_size(<<>>, _, count), do: count

  defp query_wire_size(<<?%, digits::binary-size(2), rest::binary>>, value?, count) do
    byte = String.to_integer(digits, 16)
    # A raw plus decodes to a space. Ampersand always separates members;
    # equals separates the name but can appear literally in the value.
    literal? = byte in ~c" ~:/?@!$'(),;" or (value? and byte == ?=)
    query_wire_size(rest, value?, count + if(literal?, do: 1, else: 3))
  end

  defp query_wire_size(<<_, rest::binary>>, value?, count),
    do: query_wire_size(rest, value?, count + 1)

  defp field_wire?(%{"bs" => _}, value), do: byte_sequences?(value, 1024)

  defp field_wire?(%{"key" => {:string, key}}, value) do
    # A dictionary member is serialized through the same singleton List
    # schema as live derivation. Parse the key separately so its length is
    # independent of the serialized member's byte ceiling.
    schema = wire_schema(:list)

    with {:ok, %Value{value: [{^key, _}]}} <- SF.parse(key, %{schema | type: :dictionary}),
         {:ok, %Value{value: [_]} = parsed} <- SF.parse(value, schema),
         {:ok, ^value} <- SF.serialize(parsed, schema) do
      true
    else
      _ -> false
    end
  end

  defp field_wire?(%{"sf" => _}, value) do
    Enum.any?([:item, :list, :dictionary], fn type ->
      schema = wire_schema(type)

      with {:ok, parsed} <- SF.parse(value, schema),
           {:ok, ^value} <- SF.serialize(parsed, schema) do
        true
      else
        _ -> false
      end
    end)
  end

  defp field_wire?(_, value), do: combined_field?(value, 1024)

  defp wire_schema(type) do
    types = Schema.types(:rfc9651)

    %Schema{
      revision: :rfc9651,
      type: type,
      item_types: types,
      parameter_types: types,
      inner_lists: type != :item
    }
  end

  defp combined_field?(_, 0), do: false
  defp combined_field?(<<byte, _::binary>>, _) when byte in [32, 9], do: false

  defp combined_field?(value, remaining) do
    if canonical_occurrence?(value) do
      true
    else
      # Use the last allowable separator to minimize the number of occurrences.
      scope = {0, min(byte_size(value), 65_538)}

      separator =
        value
        |> :binary.matches(@field_separator, scope: scope)
        |> Enum.reverse()
        |> Enum.find(fn {at, width} ->
          left = at == 0 or :binary.at(value, at - 1) not in [32, 9]
          right = at + width == byte_size(value) or :binary.at(value, at + width) not in [32, 9]
          left and right
        end)

      case separator do
        {at, width} ->
          tail = binary_part(value, at + width, byte_size(value) - at - width)
          combined_field?(tail, remaining - 1)

        nil ->
          false
      end
    end
  end

  defp canonical_occurrence?(value),
    do: byte_size(value) <= 65_536 and trim_ows(value) == value

  defp byte_sequence(value), do: ":" <> Base.encode64(trim_ows(value)) <> ":"

  defp byte_sequences?(_, 0), do: false

  defp byte_sequences?(value, remaining) do
    case :binary.split(value, @field_separator) do
      [item] -> canonical_byte_sequence?(item)
      [item, rest] -> canonical_byte_sequence?(item) and byte_sequences?(rest, remaining - 1)
    end
  end

  defp canonical_byte_sequence?(<<?:, rest::binary>>) when byte_size(rest) > 0 do
    case rest do
      <<encoded::binary-size(byte_size(rest) - 1), ?:>> ->
        with {:ok, decoded} <- Base.decode64(encoded),
             true <- Validation.field_value?(decoded) and canonical_occurrence?(decoded) do
          byte_sequence(decoded) == ":" <> rest
        else
          _ -> false
        end

      _ -> false
    end
  end

  defp canonical_byte_sequence?(_), do: false

  defp uri_path_query?(value, max),
    do: byte_size(value) <= max and Validation.uri_bytes?(value) and Validation.path_query?(value)

  defp rebuild(parts) do
    lines = Enum.map(parts.components, fn {id, value} -> [id, ": ", value, "\n"] end)
    IO.iodata_to_binary([lines, "\"@signature-params\": ", parts.signature_params])
  end

  defp derive(message, parameters, opts) do
    options = options(opts)
    {parameters, serialized} = parameters(parameters)
    metadata(parameters.parameters)
    ensure(SignatureFields.nonce_valid?(SignatureFields.parameters(parameters)["nonce"]), :limit)
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
        if String.starts_with?(name, "@") and name != "@query-param" do
          ensure(canonical_value?(name, params, value), :invalid_component_parameters)
        end

        identifier = serialize(component, %{@schema | type: :item}, :invalid_signature_parameters)
        size = size + byte_size(identifier) + byte_size(value) + 3
        ensure(size <= options.max_bytes, :limit)
        {[{identifier, value} | output], size, MapSet.put(seen, identity), cache}
      end)

    final = ["\"@signature-params\": ", serialized]
    ensure(size + IO.iodata_length(final) <= options.max_bytes, :limit)
    {:ok, %{components: Enum.reverse(output), signature_params: serialized}}
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
      SignatureFields.component_name?(name),
      if(String.starts_with?(name, "@"), do: :unknown_component, else: :invalid_component)
    )

    ensure(name != "@status" or parameters != [{"req", {:boolean, true}}], :wrong_message_kind)
    ensure(SignatureFields.component_parameters?(name, parameters), :invalid_component_parameters)
    ensure(not SignatureFields.incompatible_parameters?(parameters), :incompatible_parameters)

    {name, Map.new(parameters)}
  end

  defp component(_), do: fail(:invalid_signature_parameters)
  defp field_name?(name), do: SignatureFields.field_name?(name)

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
          Enum.map_join(occurrences, @field_separator, &byte_sequence(&1.value))

        {value, cache}

      Map.has_key?(params, "sf") or Map.has_key?(params, "key") ->
        key = {section, name, source_key(params)}
        structured(occurrences, name, params, options.field_schemas, cache, key)

      true ->
        {Enum.map_join(occurrences, @field_separator, &trim_ows(&1.value)), cache}
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
        bytes = Enum.map_join(occurrences, @field_separator, &trim_ows(&1.value))

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
    ensure(canonical_query?(name), :noncanonical_query_name)
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

  defp canonical_query?(bytes), do: encode_query(decode_query(bytes)) == bytes

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

  # Binary-part trim: no integer-list round-trip, two bounded scans.
  defp trim_ows(value) do
    prefix = ows_prefix(value, 0)
    size = byte_size(value)
    suffix = ows_suffix(value, size, prefix)
    binary_part(value, prefix, suffix - prefix)
  end

  defp ows_prefix(<<byte, rest::binary>>, count) when byte in [32, 9],
    do: ows_prefix(rest, count + 1)

  defp ows_prefix(_, count), do: count

  defp ows_suffix(value, index, floor) when index > floor do
    case binary_part(value, index - 1, 1) do
      <<byte>> when byte in [32, 9] -> ows_suffix(value, index - 1, floor)
      _ -> index
    end
  end

  defp ows_suffix(_value, index, _floor), do: index

  defp ascii?(bytes), do: ascii_bytes?(bytes)
  defp ascii_bytes?(""), do: true

  defp ascii_bytes?(<<byte, rest::binary>>) when byte == 9 or byte in 32..126,
    do: ascii_bytes?(rest)

  defp ascii_bytes?(_), do: false
end
