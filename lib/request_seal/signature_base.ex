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
  @field_wire_schema %Schema{
    revision: :rfc9651,
    type: :list,
    item_types: Schema.types(:rfc9651),
    parameter_types: Schema.types(:rfc9651),
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
      `:invalid_signature_parameters`, `:malformed`, `:limit`; component reasons
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
  Parse and validate a canonical RFC 9421 Section 2.5 signature base.

  Accepts at most 1,048,576 binary bytes and 256 component lines. The final
  `"@signature-params"` line must contain a canonical RFC 8941 Inner List.
  Its ordered items must exactly match the preceding serialized identifiers.
  The builder's component, modifier, applicability and wire value rules apply.
  Ordinary field values preserve interior horizontal tabs. LF separates lines.
  CRLF and a trailing LF reject.

  The original message establishes field availability, schema selection,
  request linkage and equality with the values derived from that message.

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
    metadata(inner.parameters)
    true = length(lines) == length(inner.value)
    identities = Enum.map(inner.value, &{&1.value, Enum.sort(&1.parameters)})
    true = length(Enum.uniq(identities)) == length(identities)

    components =
      Enum.zip_with(lines, inner.value, fn line, item ->
        {name, params} = component(item)
        {:ok, identifier} = SF.serialize(item, %{@schema | type: :item})
        prefix = identifier <> ": "
        true = String.starts_with?(line, prefix)
        value = binary_part(line, byte_size(prefix), byte_size(line) - byte_size(prefix))
        true = ascii?(value) and protocol_value?(name, params, value)
        {identifier, name, params, value}
      end)

    facts = Enum.map(components, fn {_, name, params, value} -> {name, params, value} end)
    true = Enum.any?([:request, :response], &matches_kind?(facts, &1))
    true = consistent_components?(facts)
    pairs = Enum.map(components, fn {identifier, _, _, value} -> {identifier, value} end)
    parts = %{components: pairs, signature_params: serialized}
    ^bytes = rebuild(parts)
    Map.put(parts, :inner_list, inner)
  end

  defp base_lines(bytes, remaining, reversed) do
    case :binary.split(bytes, "\n") do
      [final] -> {Enum.reverse(reversed), final}
      [line, rest] when remaining > 0 -> base_lines(rest, remaining - 1, [line | reversed])
      _ -> fail(:malformed)
    end
  end

  defp protocol_value?("@method", _, value), do: Validation.token?(value, 256)
  defp protocol_value?("@status", _, value), do: Regex.match?(~r/\A[1-5][0-9]{2}\z/, value)

  defp protocol_value?("@scheme", _, value),
    do: Validation.scheme?(value) and value == String.downcase(value)

  defp protocol_value?("@authority", _, value),
    do: Validation.authority?(value) and value == String.downcase(value)

  defp protocol_value?("@path", _, "/" <> _ = value),
    do:
      byte_size(value) <= 16_384 and path_query_bytes?(value) and
        :binary.match(value, "?") == :nomatch

  defp protocol_value?("@query", _, "?" <> value),
    do: byte_size(value) <= 16_382 and path_query_bytes?(value)

  defp protocol_value?("@query-param", %{"name" => {:string, name}}, value),
    do: encode_query(decode_query(name)) == name and encode_query(decode_query(value)) == value

  defp protocol_value?("@target-uri", _, value) do
    absolute_target?(value) and
      (byte_size(value) <= 16_384 or origin_form_tail?(absolute_tail(value)))
  end

  defp protocol_value?("@request-target", _, "/" <> _ = value),
    do: byte_size(value) <= 16_384 and path_query_bytes?(value)
  defp protocol_value?("@request-target", _, "*"), do: true

  defp protocol_value?("@request-target", _, value),
    do:
      Validation.authority?(value, true) or
        (byte_size(value) <= 16_384 and absolute_target?(value))

  defp protocol_value?(name, _, _) when name in @derived, do: false

  defp protocol_value?(_, params, value), do: field_wire?(field_kind(params), params, value)

  defp origin_form_tail?("/" <> _ = tail), do: byte_size(tail) <= 16_384
  defp origin_form_tail?(_), do: false

  defp field_kind(%{"bs" => _}), do: :bytes
  defp field_kind(%{"key" => _}), do: :member
  defp field_kind(%{"sf" => _}), do: :structured
  defp field_kind(_), do: :plain

  defp field_wire?(:plain, _, value), do: is_integer(plain_occurrence_count(value, 0))

  defp field_wire?(:bytes, _, value), do: match?({:ok, _}, byte_sequences(value))

  defp field_wire?(:member, %{"key" => {:string, key}}, value),
    do: structured_matches?(named_member({key, value}), nil, [{key, value}])

  defp field_wire?(:structured, _, value), do: structured_matches?(value, value, [])

  defp byte_sequences(value) do
    members = :binary.split(value, ", ", [:global])

    if length(members) <= 1_024 do
      Enum.reduce_while(members, {:ok, []}, fn member, {:ok, reversed} ->
        case decode_byte_sequence(member) do
          {:ok, bytes} -> {:cont, {:ok, [bytes | reversed]}}
          :error -> {:halt, :error}
        end
      end)
    else
      :error
    end
  end

  defp decode_byte_sequence(":" <> rest = wire) when byte_size(rest) > 0 do
    with ?: <- :binary.last(rest),
         {:ok, bytes} <- Base.decode64(binary_part(rest, 0, byte_size(rest) - 1)),
         true <- Validation.field_value?(bytes) and byte_sequence(bytes) == wire do
      {:ok, bytes}
    else
      _ -> :error
    end
  end

  defp decode_byte_sequence(_), do: :error

  defp structured_matches?(source, complete, members) do
    types = if members == [], do: [:item, :list, :dictionary], else: [:dictionary]

    Enum.any?(types, fn type ->
      schema = %{@field_wire_schema | type: type}

      with {:ok, parsed} <- SF.parse(source, schema) do
        (complete == nil or SF.serialize(parsed, schema) == {:ok, complete}) and
          Enum.all?(members, fn {key, value} ->
            case member(parsed, key) do
              nil -> false
              selected -> SF.serialize(selected, @field_wire_schema) == {:ok, value}
            end
          end)
      else
        _ -> false
      end
    end)
  end

  defp field_facts?(components) do
    fields =
      components
      |> Enum.reject(fn {name, _, _} -> name in @derived end)
      |> Enum.group_by(fn {name, params, _} -> {name, Map.has_key?(params, "tr")} end)

    Enum.reduce_while(fields, {0, 0}, fn {{name, _}, field}, {count, bytes} ->
      case field_group(field, byte_size(name)) do
        {occurrences, minimum_bytes}
        when count + occurrences <= 1_024 and bytes + minimum_bytes <= 1_048_576 ->
          {:cont, {count + occurrences, bytes + minimum_bytes}}

        _ ->
          {:halt, false}
      end
    end) != false
  end

  defp field_group(field, name_bytes) do
    values = Map.new(field, fn {_, params, value} -> {field_kind(params), value} end)

    members =
      for {_, %{"key" => {:string, key}}, value} <- field, uniq: true, do: {key, value}

    plain = values[:plain]
    complete = values[:structured]
    occurrences = byte_occurrences(values[:bytes])
    combined = if occurrences != nil, do: Enum.join(occurrences, ", ")
    source = combined || plain || complete

    if matches_fact?(combined, plain) and consistent_structured_field?(source, complete, members) do
      minimum_field_size(occurrences, plain, name_bytes)
    end
  end

  defp consistent_structured_field?(_, nil, []), do: true

  defp consistent_structured_field?(nil, nil, members) do
    source = Enum.map_join(members, ", ", &named_member/1)
    structured_matches?(source, nil, members)
  end

  defp consistent_structured_field?(source, complete, members),
    do: structured_matches?(source, complete, members)

  defp byte_occurrences(nil), do: nil

  defp byte_occurrences(wire) do
    {:ok, reversed} = byte_sequences(wire)
    Enum.reverse(reversed)
  end

  defp minimum_field_size(nil, nil, name_bytes), do: {1, name_bytes}

  defp minimum_field_size(nil, plain, name_bytes) do
    count = plain_occurrence_count(plain, 0)
    # Bound one-byte names conservatively because extra separators save bytes.
    name_overhead = if name_bytes == 1, do: -1_024, else: count * (name_bytes - 2)
    {count, max(name_bytes, byte_size(plain) + name_overhead + 2)}
  end

  defp minimum_field_size(occurrences, _, name_bytes) do
    count = length(occurrences)
    {count, count * name_bytes + IO.iodata_length(occurrences)}
  end

  defp named_member({key, "?1" <> parameters}), do: key <> parameters
  defp named_member({key, value}), do: key <> "=" <> value

  defp member(parsed, key) do
    case List.keyfind(parsed.value, key, 0) do
      {^key, value} -> %Value{type: :list, value: [value]}
      nil -> nil
    end
  end

  # An empty last occurrence leaves the separator's space at the end.
  defp plain_occurrence_count(_, 1_024), do: nil

  defp plain_occurrence_count(value, count) do
    cond do
      String.ends_with?(value, ", ") ->
        plain_occurrence_count(binary_part(value, 0, byte_size(value) - 2), count + 1)

      value != trim_ows(value) ->
        nil

      byte_size(value) <= 65_536 ->
        count + 1

      true ->
        # Use the last legal separator within the field occurrence bound.
        prefix = binary_part(value, 0, min(byte_size(value), 65_538))

        case Enum.find(Enum.reverse(:binary.matches(prefix, ", ")), &ows_boundary?(value, &1)) do
          {offset, 2} ->
            rest = binary_part(value, offset + 2, byte_size(value) - offset - 2)
            plain_occurrence_count(rest, count + 1)

          nil ->
            nil
        end
    end
  end

  defp ows_boundary?(value, {offset, 2}) do
    (offset == 0 or :binary.at(value, offset - 1) not in [9, 32]) and
      :binary.at(value, offset + 2) not in [9, 32]
  end

  defp matches_kind?(components, kind) do
    Enum.all?(components, fn
      {name, %{"req" => _}, _} -> kind == :response and source_kind?(name, :request)
      {name, _, _} -> source_kind?(name, kind)
    end)
  end

  defp consistent_components?(components) do
    components
    |> Enum.group_by(fn {_, params, _} -> source_key(params) end)
    |> Enum.all?(fn {_, source} -> request_facts?(source) and field_facts?(source) end)
  end

  defp request_facts?(components) do
    derived = Map.new(components, fn {name, _, value} -> {name, value} end)
    target = derived["@request-target"]
    uri = derived["@target-uri"]
    method = derived["@method"]
    declared_path = derived["@path"]
    declared_query = derived["@query"]

    with true <- compatible_target_method?(target, method),
         true <- compatible_target_facts?(target, uri),
         true <- compatible_origin?(target, uri, derived["@scheme"], derived["@authority"]),
         {:ok, path, query} <- target_parts(target, uri, method) do
      matches_fact?(path, declared_path) and matches_fact?(query, declared_query) and
        query_parameters_match?(query || declared_query, path || declared_path || "/", components)
    end
  end

  defp compatible_target_method?(nil, _), do: true
  defp compatible_target_method?(_, nil), do: true
  defp compatible_target_method?("*", method), do: method == "OPTIONS"

  defp compatible_target_method?(target, method),
    do: Validation.authority?(target, true) == (method == "CONNECT")

  defp compatible_target_facts?(nil, _), do: true
  defp compatible_target_facts?(_, nil), do: true

  defp compatible_target_facts?("/" <> _ = target, uri), do: absolute_tail(uri) == target

  defp compatible_target_facts?(target, uri) do
    if absolute_target?(target), do: target == uri, else: absolute_tail(uri) == ""
  end

  defp compatible_origin?(target, uri, scheme, authority) do
    origin = uri || if(is_binary(target) and absolute_target?(target), do: target)

    cond do
      is_binary(origin) ->
        {actual_scheme, actual_authority} = origin(%{target_form: :absolute, raw_target: origin})

        matches_fact?(String.downcase(actual_scheme), scheme) and
          matches_fact?(canonical_authority(actual_scheme, actual_authority), authority) and
          (not Validation.authority?(target, true) or target == actual_authority)

      Validation.authority?(target, true) ->
        Enum.any?([scheme || "http", scheme || "https", scheme || "other"], fn scheme ->
          matches_fact?(canonical_authority(scheme, target), authority)
        end)

      scheme != nil and authority != nil ->
        canonical_authority(scheme, authority) == authority

      true ->
        true
    end
  end

  defp target_parts("/" <> _ = target, _, _), do: parts_from_tail(target)

  defp target_parts(nil, nil, method) when method != "CONNECT", do: {:ok, nil, nil}

  defp target_parts(target, uri, method) when target == "*" or method == "CONNECT" do
    cond do
      uri == nil ->
        {:ok, "/", "?"}

      absolute_tail(uri) != "" ->
        :error

      method != "CONNECT" ->
        {:ok, "/", "?"}

      true ->
        {_, authority} = origin(%{target_form: :absolute, raw_target: uri})
        if Validation.authority?(authority, true), do: {:ok, "/", "?"}, else: :error
    end
  end

  defp target_parts(nil, uri, _), do: parts_from_tail(absolute_tail(uri))

  defp target_parts(target, _, _) do
    if absolute_target?(target), do: parts_from_tail(absolute_tail(target)), else: {:ok, "/", "?"}
  end

  defp parts_from_tail(tail) do
    {path, query} = split_tail(tail)
    {:ok, if(path == "", do: "/", else: path), "?" <> (query || "")}
  end

  defp matches_fact?(actual, declared), do: actual == nil or declared == nil or actual == declared

  defp query_parameters_match?(nil, path, components) do
    # Measure the shortest raw target that could produce these projected values.
    projected =
      for {"@query-param", %{"name" => {:string, name}}, value} <- components do
        separator = if name == "" or value != "", do: 1, else: 0
        raw_query_size(name, [?&, ?=]) + separator + raw_query_size(value, [?&])
      end

    projected == [] or byte_size(path) + length(projected) + Enum.sum(projected) <= 16_384
  end

  defp query_parameters_match?("?", _, components),
    do: Enum.all?(components, fn {name, _, _} -> name != "@query-param" end)

  defp query_parameters_match?("?" <> query, path, components) do
    projections =
      for {"@query-param", %{"name" => {:string, name}}, value} <- components, do: {name, value}

    byte_size(path) + 1 + byte_size(query) <= 16_384 and
      (projections == [] or query_values_match?(parse_query_values(query), projections))
  end

  defp query_values_match?(parsed, projections) do
    Enum.all?(projections, fn {name, value} ->
      case Map.get(parsed, name) do
        [raw] -> encode_query(decode_query(raw)) == value
        _ -> false
      end
    end)
  end

  defp raw_query_size(encoded, delimiters) do
    for <<byte <- decode_query(encoded)>>, reduce: 0 do
      size ->
        width =
          if byte == 32 or (byte not in [?+ | delimiters] and path_query_bytes?(<<byte>>)),
            do: 1,
            else: 3

        size + width
    end
  end

  defp source_kind?("@status", kind), do: kind == :response
  defp source_kind?(name, kind) when name in @derived, do: kind == :request
  defp source_kind?(_, _), do: true

  defp absolute_target?(value) do
    case Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?]+)([\/?].*)?\z/, value) do
      [_, scheme, authority | tail] ->
        Validation.scheme?(scheme) and Validation.authority?(authority) and
          Enum.all?(tail, &path_query_bytes?/1)

      _ ->
        false
    end
  end

  defp path_query_bytes?(value),
    do: Validation.uri_bytes?(value) and :binary.match(value, ["[", "]"]) == :nomatch

  defp rebuild(parts) do
    lines = Enum.map(parts.components, fn {id, value} -> [id, ": ", value, "\n"] end)
    IO.iodata_to_binary([lines, "\"@signature-params\": ", parts.signature_params])
  end

  defp derive(message, parameters, opts) do
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
        ensure(source_kind?(name, source.kind), :wrong_message_kind)
        {value, cache} = value(source, name, params, options, cache)
        ensure(ascii?(value), :non_ascii)
        ensure(protocol_value?(name, params, value), :malformed)
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
    {Integer.to_string(message.status), cache}
  end

  defp value(message, "@query-param", params, _, cache) do
    query_parameter(message, params, cache)
  end

  defp value(message, "@" <> _ = name, _params, _, cache) do
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

    case field_kind(params) do
      :bytes ->
        value = Enum.map_join(occurrences, ", ", &byte_sequence(&1.value))
        {value, cache}

      kind when kind in [:structured, :member] ->
        key = {section, name, source_key(params)}
        structured(occurrences, name, params, options.field_schemas, cache, key)

      :plain ->
        {Enum.map_join(occurrences, ", ", &trim_ows(&1.value)), cache}
    end
  end

  defp byte_sequence(value), do: ":" <> Base.encode64(trim_ows(value)) <> ":"

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
        selected = member(parsed, key)
        ensure(selected != nil, :missing_dictionary_key)
        # SF top-level lists serialize Items and Inner Lists by the same member rule.
        serialize(selected, %{schema | type: :list}, :invalid_structured_field)
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
    canonical_authority(scheme, authority)
  end

  defp canonical_authority(scheme, authority) do
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
          absolute_tail(message.raw_target)

        _ ->
          ""
      end

    split_tail(tail)
  end

  defp absolute_tail(raw), do: Regex.replace(~r/\A[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/?]+/, raw, "")

  defp split_tail(tail) do
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
    parse_query_values(query)
  end

  defp parse_query_values(query) do
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
