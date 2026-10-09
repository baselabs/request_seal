defmodule RequestSeal.StructuredFields do
  @moduledoc """
  Bounded RFC 8941 / RFC 9651 parsing and canonical serialization.

  All entry points require a `RequestSeal.StructuredFields.Schema`. Values retain
  dictionary and parameter order; duplicates follow the RFC's last-value,
  first-position rule. No type is authorized by recognizing its syntax. Errors
  contain only bounded reasons and never return a partially parsed value.

  Limits (keyword options) may only lower these ceilings: `:max_bytes` 65,536
  (input or output), `:max_members` 1,024 (top-level encounters, including
  duplicates), `:max_inner_items` 256 (per inner list), `:max_parameters` 256
  (per item/list, including duplicates), `:max_key_bytes` 256,
  `:max_value_bytes` 16,384 (decoded strings/bytes or token bytes), and
  `:max_nodes` 4,096 (containers, items, and parameter encounters combined).
  These are library resource ceilings, not protocol maximums.
  All limits are positive integers. Grammar depth is fixed: top-level container,
  optional inner list, item; inner lists cannot nest. Numeric syntax has the
  RFC's 15-digit integer and 12+3-digit decimal bounds, including leading zeros.

  Byte sequences reject nonzero unused base64 pad bits under the canonical
  encoding rule in [RFC 4648 Section 3.5](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5).
  Missing padding is synthesized before decoding; invalid encodings fail parsing
  as described in [RFC 8941 Section 4.2.7](https://www.rfc-editor.org/rfc/rfc8941.html#section-4.2.7).

  `parse_field/5` consumes the existing lossless `RequestSeal.Message` model,
  combining matching occurrences in one explicitly selected section in order
  with comma-space. It never merges headers with trailers or reads a body.
  Its optional limits apply to both the combined bytes and the complete parse.
  Missing fields and unavailable sections remain explicit failures.

  Serializing an empty list or dictionary returns `{:ok, ""}`. The empty binary
  means the caller must omit both the field name and field value from the HTTP
  message, as specified by [RFC 9651 Section 4.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.1).
  It must not be emitted as an empty HTTP field. This keeps the serialization
  result binary while leaving field emission to the caller.

      iex> alias RequestSeal.StructuredFields, as: SF
      iex> {:ok, schema} = SF.Schema.new(%{revision: :rfc8941, type: :item, item_types: [:integer]})
      iex> {:ok, value} = SF.parse("42", schema)
      iex> SF.serialize(value, schema)
      {:ok, "42"}
      iex> SF.parse("@42", schema)
      {:error, %RequestSeal.StructuredFields.Error{reason: :revision_type}}

  The example integer is RFC 8941 Section 2's Foo-Example. This module performs
  no network, storage, cryptographic, authentication, or authorization operation.
  """
  alias RequestSeal.StructuredFields.{Error, Schema, Value}
  alias RequestSeal.Message

  @ceilings %{
    max_bytes: 65_536,
    max_members: 1024,
    max_inner_items: 256,
    max_parameters: 256,
    max_key_bytes: 256,
    max_value_bytes: 16_384,
    max_nodes: 4096
  }

  @doc "Parse complete ASCII field bytes under an explicit schema and bounded work."
  @spec parse(binary(), Schema.t(), keyword()) :: {:ok, Value.t()} | {:error, Error.t()}
  def parse(bytes, schema, opts \\ []) do
    protect(fn -> parse_bytes(bytes, schema, setup(schema, opts)) end)
  end

  @doc false
  def parse_unique(bytes, schema, opts),
    do:
      protect(fn ->
        parse_bytes(
          bytes,
          schema,
          setup(schema, [unique_keys: :all, unique_parameters: true] ++ opts, true)
        )
      end)

  defp parse_bytes(bytes, schema, state) do
    ensure(is_binary(bytes), :syntax)
    ensure(byte_size(bytes) <= state.limits.max_bytes, :limit)
    {value, rest, state} = top(sp(bytes), schema, consume_node(state))
    ensure(sp(rest) == "", :syntax)
    ensure(not state.duplicate_key, :duplicate_key)
    ensure(not state.duplicate_parameter, :duplicate_parameter)
    {:ok, value}
  end

  @doc "Serialize canonically; an empty binary means omit the field. Invalid values reject."
  @spec serialize(Value.t(), Schema.t(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def serialize(value, schema, opts \\ []) do
    protect(fn ->
      state = setup(schema, opts) |> Map.merge(%{output: [], bytes: 0})
      ensure(valid_shape?(value), :invalid_value)
      ensure(value.type == schema.type, :schema_type)
      state = write_top(value, schema, consume_node(state))
      {:ok, state.output |> Enum.reverse() |> IO.iodata_to_binary()}
    end)
  end

  @doc """
  Combine ordered header or trailer occurrences and parse under optional lowered limits.

  `:unique_keys` optionally lists dictionary keys (or `:all`) whose repeats reject with
  `:duplicate_key` before deduplication, including across field occurrences.
  It defaults to `[]`; keys must use valid dictionary-key syntax, fit the key
  byte ceiling, and number no more than `:max_members`. Other keys retain the
  last-value, first-position rule. `:unique_parameters` defaults to false; true
  rejects repeated parameter names on any member or inner item with
  `:duplicate_parameter`, after the bounded parse completes.
  """
  @spec parse_field(Message.t(), binary(), Schema.t(), :headers | :trailers, keyword()) ::
          {:ok, Value.t()} | {:error, Error.t()}
  def parse_field(message, name, schema, section \\ :headers, opts \\ []) do
    protect(fn ->
      state = setup(schema, opts, true)
      ensure(Message.validate(message) == :ok, :invalid_message)
      ensure(RequestSeal.Message.Validation.token?(name, 256), :invalid_field)
      ensure(section in [:headers, :trailers], :invalid_field)
      fields = if section == :headers, do: message.fields, else: message.trailers
      ensure(is_list(fields), :unavailable_section)
      selected = Enum.filter(fields, &(String.downcase(&1.name) == String.downcase(name)))
      ensure(selected != [], :missing_field)

      {_size, values} =
        Enum.reduce(selected, {0, []}, fn field, {size, values} ->
          size = size + byte_size(field.value) + if(values == [], do: 0, else: 2)
          ensure(size <= state.limits.max_bytes, :limit)
          {size, [field.value | values]}
        end)

      parse_bytes(Enum.join(Enum.reverse(values), ", "), schema, state)
    end)
  end

  defp protect(fun) do
    fun.()
  catch
    {:structured_fields, reason} -> {:error, %Error{reason: reason}}
  end

  defp fail(reason), do: throw({:structured_fields, reason})
  defp ensure(true, _), do: :ok
  defp ensure(_, reason), do: fail(reason)

  defp setup(schema, opts, allow_unique_keys? \\ false) do
    ensure(Schema.validate(schema) == :ok, :invalid_schema)
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_limits)

    ensure(
      length(opts) <= map_size(@ceilings) + if(allow_unique_keys?, do: 2, else: 0),
      :invalid_limits
    )

    ensure(length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))), :invalid_limits)

    limits =
      if allow_unique_keys?,
        do: Keyword.drop(opts, [:unique_keys, :unique_parameters]),
        else: opts

    Enum.each(limits, fn {key, value} ->
      ensure(
        Map.has_key?(@ceilings, key) and is_integer(value) and value > 0 and
          value <= Map.get(@ceilings, key),
        :invalid_limits
      )
    end)

    limits = Map.merge(@ceilings, Map.new(limits))
    # Field-only dictionary policy, separate from caller-lowered resource limits.
    unique_keys = if allow_unique_keys?, do: Keyword.get(opts, :unique_keys, []), else: []
    ensure(valid_unique_keys?(unique_keys, limits.max_members), :invalid_limits)

    unique_parameters =
      if allow_unique_keys?, do: Keyword.get(opts, :unique_parameters, false), else: false

    ensure(is_boolean(unique_parameters), :invalid_limits)

    %{
      limits: limits,
      nodes: 0,
      unique_keys: unique_keys,
      seen_keys: MapSet.new(),
      duplicate_key: false,
      unique_parameters: unique_parameters,
      duplicate_parameter: false
    }
  end

  defp valid_unique_keys?(:all, _), do: true
  defp valid_unique_keys?([], _), do: true

  defp valid_unique_keys?([key | rest], remaining) when remaining > 0 do
    is_binary(key) and byte_size(key) <= @ceilings.max_key_bytes and
      String.match?(key, ~r/\A[a-z*][a-z0-9_.*-]*\z/) and
      valid_unique_keys?(rest, remaining - 1)
  end

  defp valid_unique_keys?(_, _), do: false

  defp consume_node(state) do
    ensure(state.nodes < state.limits.max_nodes, :limit)
    %{state | nodes: state.nodes + 1}
  end

  defp sp(<<32, rest::binary>>), do: sp(rest)
  defp sp(rest), do: rest
  defp ows(<<c, rest::binary>>) when c in [32, 9], do: ows(rest)
  defp ows(rest), do: rest

  defp top(bytes, %{type: :item} = schema, state), do: item(bytes, schema, state)

  defp top(bytes, schema, state) do
    {members, rest, state} = members(bytes, schema, state, [], 0)
    value = %Value{type: schema.type, value: members}
    {value, rest, state}
  end

  defp members("", _, state, acc, _), do: {Enum.reverse(acc), "", state}

  defp members(bytes, schema, state, acc, count) do
    ensure(count < state.limits.max_members, :limit)

    {entry, rest, state} =
      case schema.type do
        :list ->
          member(bytes, schema, state)

        :dictionary ->
          {key, rest} = key(bytes, state)
          state = unique_key(key, state)

          {value, rest, state} =
            case rest do
              "=" <> tail ->
                member(tail, schema, state)

              _ ->
                check_type(:boolean, schema, :item)
                {params, tail, state} = parameters(rest, schema, consume_node(state), [], 0)
                {%Value{type: :item, value: {:boolean, true}, parameters: params}, tail, state}
            end

          {{key, value}, rest, state}
      end

    acc = if schema.type == :dictionary, do: ordered_put(acc, entry), else: [entry | acc]

    case ows(rest) do
      "" ->
        {Enum.reverse(acc), "", state}

      "," <> tail ->
        tail = ows(tail)
        ensure(tail != "", :syntax)
        members(tail, schema, state, acc, count + 1)

      _ ->
        fail(:syntax)
    end
  end

  defp unique_key(key, %{unique_keys: :all} = state) do
    # Finish the bounded walk before duplicate rejection so encounter ceilings
    # take precedence even for repeated labels.
    %{
      state
      | duplicate_key: state.duplicate_key or MapSet.member?(state.seen_keys, key),
        seen_keys: MapSet.put(state.seen_keys, key)
    }
  end

  defp unique_key(key, state) do
    if key in state.unique_keys do
      ensure(not MapSet.member?(state.seen_keys, key), :duplicate_key)
      %{state | seen_keys: MapSet.put(state.seen_keys, key)}
    else
      state
    end
  end

  # Accumulators are reversed; replacement preserves the first encounter's position.
  defp ordered_put(acc, {key, value} = entry) do
    if List.keymember?(acc, key, 0),
      do: List.keyreplace(acc, key, 0, {key, value}),
      else: [entry | acc]
  end

  defp member("(" <> rest, schema, state) do
    ensure(schema.inner_lists, :schema_type)
    {items, rest, state} = inner(sp(rest), schema, consume_node(state), [], 0)
    {params, rest, state} = parameters(rest, schema, state, [], 0)
    {%Value{type: :inner_list, value: items, parameters: params}, rest, state}
  end

  defp member(bytes, schema, state), do: item(bytes, schema, consume_node(state))
  defp inner(")" <> rest, _, state, acc, _), do: {Enum.reverse(acc), rest, state}

  defp inner(bytes, schema, state, acc, count) do
    ensure(count < state.limits.max_inner_items, :limit)
    {value, rest, state} = item(bytes, schema, consume_node(state))

    case rest do
      ")" <> _ -> inner(rest, schema, state, [value | acc], count + 1)
      " " <> tail -> inner(sp(tail), schema, state, [value | acc], count + 1)
      _ -> fail(:syntax)
    end
  end

  defp item(bytes, schema, state) do
    {value, rest} = bare(bytes, schema, :item, state)
    {params, rest, state} = parameters(rest, schema, state, [], 0)
    {%Value{type: :item, value: value, parameters: params}, rest, state}
  end

  defp parameters(";" <> rest, schema, state, acc, count) do
    ensure(count < state.limits.max_parameters, :limit)
    state = consume_node(state)
    {key, rest} = key(sp(rest), state)

    {value, rest} =
      case rest do
        "=" <> tail ->
          bare(tail, schema, :parameter, state)

        _ ->
          check_type(:boolean, schema, :parameter)
          {{:boolean, true}, rest}
      end

    state = %{
      state
      | duplicate_parameter:
          state.duplicate_parameter or
            (state.unique_parameters and List.keymember?(acc, key, 0))
    }

    parameters(rest, schema, state, ordered_put(acc, {key, value}), count + 1)
  end

  defp parameters(rest, _, state, acc, _), do: {Enum.reverse(acc), rest, state}

  defp key(<<c, _::binary>> = bytes, state) when c in ?a..?z or c == ?* do
    take(bytes, &key_char?/1, state.limits.max_key_bytes)
  end

  defp key(_, _), do: fail(:syntax)
  defp key_char?(c), do: c in ?a..?z or c in ?0..?9 or c in ~c"_-.*"
  defp token_char?(c), do: c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in ~c"!#$%&'*+-.^_`|~:/"

  defp take(bytes, predicate, max) do
    count = scan(bytes, predicate, max, 0)
    <<value::binary-size(^count), rest::binary>> = bytes
    {value, rest}
  end

  defp scan(<<c, rest::binary>>, predicate, max, count) do
    if predicate.(c) do
      ensure(count < max, :limit)
      scan(rest, predicate, max, count + 1)
    else
      count
    end
  end

  defp scan("", _, _, count), do: count

  # Stop at the first forbidden digit count without throwing a resource-limit error.
  defp take_digits(bytes, max) do
    count = count_digits(bytes, max, 0)
    <<value::binary-size(^count), rest::binary>> = bytes
    {value, rest}
  end

  defp count_digits(_, max, max), do: max

  defp count_digits(<<c, rest::binary>>, max, count) when c in ?0..?9,
    do: count_digits(rest, max, count + 1)

  defp count_digits(_, _, count), do: count

  defp bare(bytes, schema, context, state) do
    {value, rest} = parse_bare(bytes, state)
    check_type(elem(value, 0), schema, context)
    {value, rest}
  end

  defp check_type(type, schema, context) do
    ensure(type in Schema.types(schema.revision), :revision_type)
    allowed = if context == :parameter, do: schema.parameter_types, else: schema.item_types
    ensure(type in allowed, :schema_type)
  end

  defp parse_bare(<<c, _::binary>> = bytes, _) when c == ?- or c in ?0..?9, do: number(bytes)

  defp parse_bare("@" <> rest, _) do
    case number(rest) do
      {{:integer, n}, tail} -> {{:date, n}, tail}
      _ -> fail(:syntax)
    end
  end

  defp parse_bare("?1" <> rest, _), do: {{:boolean, true}, rest}
  defp parse_bare("?0" <> rest, _), do: {{:boolean, false}, rest}

  defp parse_bare("\"" <> rest, state) do
    {value, rest} = quoted(rest, [], 0, state.limits.max_value_bytes)
    {{:string, value}, rest}
  end

  defp parse_bare("%\"" <> rest, state) do
    {value, rest} = display(rest, [], 0, state.limits.max_value_bytes)
    {{:display_string, value}, rest}
  end

  defp parse_bare(":" <> rest, state) do
    {encoded, tail} = take(rest, &(&1 != ?:), state.limits.max_bytes)
    ensure(String.match?(encoded, ~r/\A[A-Za-z0-9+\/]*={0,2}\z/), :syntax)
    ensure(match?(":" <> _, tail), :syntax)
    encoded = encoded <> String.duplicate("=", rem(4 - rem(byte_size(encoded), 4), 4))
    ensure(zero_pad_bits?(encoded), :syntax)

    case Base.decode64(encoded) do
      {:ok, value} ->
        ensure(byte_size(value) <= state.limits.max_value_bytes, :limit)
        ":" <> rest = tail
        {{:bytes, value}, rest}

      :error ->
        fail(:syntax)
    end
  end

  defp parse_bare(<<c, _::binary>> = bytes, state) when c in ?a..?z or c in ?A..?Z or c == ?* do
    {value, rest} = take(bytes, &token_char?/1, state.limits.max_value_bytes)
    {{:token, value}, rest}
  end

  defp parse_bare(_, _), do: fail(:syntax)

  defp zero_pad_bits?(encoded) do
    size = byte_size(encoded)

    cond do
      size >= 4 and binary_part(encoded, size - 2, 2) == "==" ->
        # One output byte: the second sextet has four unused low bits.
        :binary.at(encoded, size - 3) in ~c"AQgw"

      size >= 4 and :binary.last(encoded) == ?= ->
        # Two output bytes: the third sextet has two unused low bits.
        :binary.at(encoded, size - 2) in ~c"AEIMQUYcgkosw048"

      true ->
        true
    end
  end

  defp number(bytes) do
    {sign, bytes} =
      case bytes do
        "-" <> rest -> {-1, rest}
        _ -> {1, bytes}
      end

    {whole, rest} = take_digits(bytes, 16)
    ensure(byte_size(whole) in 1..15, :syntax)

    case rest do
      "." <> tail ->
        ensure(byte_size(whole) <= 12, :syntax)
        {fraction, rest} = take_digits(tail, 4)
        ensure(byte_size(fraction) in 1..3, :syntax)
        {{:decimal, {sign * String.to_integer(whole <> fraction), byte_size(fraction)}}, rest}

      _ ->
        {{:integer, sign * String.to_integer(whole)}, rest}
    end
  end

  defp quoted("\"" <> rest, acc, _, _), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp quoted("\\" <> <<c, rest::binary>>, acc, count, max) when c in [?", ?\\] do
    ensure(count < max, :limit)
    quoted(rest, [c | acc], count + 1, max)
  end

  defp quoted(<<c, rest::binary>>, acc, count, max) when c in 32..126 and c != ?\\ do
    ensure(count < max, :limit)
    quoted(rest, [c | acc], count + 1, max)
  end

  defp quoted(_, _, _, _), do: fail(:syntax)

  defp display("\"" <> rest, acc, _, _) do
    value = acc |> Enum.reverse() |> IO.iodata_to_binary()
    ensure(String.valid?(value), :syntax)
    {value, rest}
  end

  defp display("%" <> <<a, b, rest::binary>>, acc, count, max) do
    ensure(count < max, :limit)
    ensure(a in ?0..?9 or a in ?a..?f, :syntax)
    ensure(b in ?0..?9 or b in ?a..?f, :syntax)
    byte = String.to_integer(<<a, b>>, 16)
    display(rest, [byte | acc], count + 1, max)
  end

  defp display(<<c, rest::binary>>, acc, count, max) when c in 32..126 and c not in [?%, ?"] do
    ensure(count < max, :limit)
    display(rest, [c | acc], count + 1, max)
  end

  defp display(_, _, _, _), do: fail(:syntax)

  defp valid_shape?(%Value{} = value),
    do: Enum.sort(Map.keys(value)) == Enum.sort(Map.keys(%Value{}))

  defp valid_shape?(_), do: false

  defp emit(state, bytes) do
    size = state.bytes + IO.iodata_length(bytes)
    ensure(size <= state.limits.max_bytes, :limit)
    %{state | bytes: size, output: [bytes | state.output]}
  end

  defp write_top(%{type: :item} = value, schema, state), do: write_item(value, schema, state)

  defp write_top(%{type: type, value: values, parameters: []}, schema, state)
       when type in [:list, :dictionary] do
    write_members(values, type, schema, state, 0, MapSet.new())
  end

  defp write_top(_, _, _), do: fail(:invalid_value)
  defp write_members([], _, _, state, _, _), do: state

  defp write_members([entry | rest], type, schema, state, count, keys) do
    ensure(count < state.limits.max_members, :limit)
    state = if count > 0, do: emit(state, ", "), else: state

    {state, keys} =
      if type == :dictionary do
        ensure(is_tuple(entry) and tuple_size(entry) == 2, :invalid_value)
        {key, value} = entry
        valid_key(key, state)
        ensure(not MapSet.member?(keys, key), :invalid_value)
        state = emit(state, key)

        state =
          if valid_shape?(value) and value.type == :item and value.value == {:boolean, true} do
            check_type(:boolean, schema, :item)
            write_params(value.parameters, schema, consume_node(state), 0, MapSet.new())
          else
            write_member(value, schema, emit(state, "="))
          end

        {state, MapSet.put(keys, key)}
      else
        {write_member(entry, schema, state), keys}
      end

    write_members(rest, type, schema, state, count + 1, keys)
  end

  defp write_members(_, _, _, _, _, _), do: fail(:invalid_value)

  defp write_member(value, schema, state) do
    ensure(valid_shape?(value), :invalid_value)
    state = consume_node(state)

    case value.type do
      :item ->
        write_item(value, schema, state)

      :inner_list ->
        ensure(schema.inner_lists, :schema_type)
        state = write_inner(value.value, schema, emit(state, "("), 0)
        write_params(value.parameters, schema, emit(state, ")"), 0, MapSet.new())

      _ ->
        fail(:invalid_value)
    end
  end

  defp write_inner([], _, state, _), do: state

  defp write_inner([value | rest], schema, state, count) do
    ensure(count < state.limits.max_inner_items, :limit)
    ensure(valid_shape?(value) and value.type == :item, :invalid_value)
    state = if count > 0, do: emit(state, " "), else: state
    state = write_item(value, schema, consume_node(state))
    write_inner(rest, schema, state, count + 1)
  end

  defp write_inner(_, _, _, _), do: fail(:invalid_value)

  defp write_item(value, schema, state) do
    state = write_bare(value.value, schema, :item, state)
    write_params(value.parameters, schema, state, 0, MapSet.new())
  end

  defp write_params([], _, state, _, _), do: state

  defp write_params([{key, value} | rest], schema, state, count, keys) do
    ensure(count < state.limits.max_parameters, :limit)
    valid_key(key, state)
    ensure(not MapSet.member?(keys, key), :invalid_value)
    state = consume_node(state) |> emit([";", key])

    state =
      if value == {:boolean, true} do
        check_type(:boolean, schema, :parameter)
        state
      else
        write_bare(value, schema, :parameter, emit(state, "="))
      end

    write_params(rest, schema, state, count + 1, MapSet.put(keys, key))
  end

  defp write_params(_, _, _, _, _), do: fail(:invalid_value)

  defp valid_key(key, state) do
    ensure(is_binary(key), :invalid_value)
    ensure(byte_size(key) <= state.limits.max_key_bytes, :limit)
    ensure(String.match?(key, ~r/\A[a-z*][a-z0-9_.*-]*\z/), :invalid_value)
  end

  defp write_bare({type, value}, schema, context, state) do
    check_type(type, schema, context)
    emit(state, encode(type, value, state))
  end

  defp write_bare(_, _, _, _), do: fail(:invalid_value)

  defp encode(type, n, _) when type in [:integer, :date] do
    ensure(
      is_integer(n) and n >= -999_999_999_999_999 and n <= 999_999_999_999_999,
      :invalid_value
    )

    prefix = if type == :date, do: "@", else: ""
    prefix <> Integer.to_string(n)
  end

  defp encode(:decimal, {coefficient, scale}, _) do
    ensure(
      is_integer(coefficient) and abs(coefficient) < Integer.pow(10, 30) and is_integer(scale) and
        scale in 0..18,
      :invalid_value
    )

    n = abs(coefficient)

    thousandths =
      if scale <= 3 do
        n * Integer.pow(10, 3 - scale)
      else
        divisor = Integer.pow(10, scale - 3)
        rounded = div(n, divisor)
        remainder = rem(n, divisor)

        if remainder * 2 > divisor or (remainder * 2 == divisor and rem(rounded, 2) == 1),
          do: rounded + 1,
          else: rounded
      end

    ensure(thousandths <= 999_999_999_999_999, :invalid_value)
    sign = if coefficient < 0 and thousandths != 0, do: "-", else: ""

    fractional =
      rem(thousandths, 1000)
      |> Integer.to_string()
      |> String.pad_leading(3, "0")
      |> String.trim_trailing("0")

    sign <>
      Integer.to_string(div(thousandths, 1000)) <>
      "." <> if(fractional == "", do: "0", else: fractional)
  end

  defp encode(:boolean, true, _), do: "?1"
  defp encode(:boolean, false, _), do: "?0"

  defp encode(type, bytes, state) when type in [:string, :token, :bytes, :display_string] do
    ensure(is_binary(bytes), :invalid_value)
    ensure(byte_size(bytes) <= state.limits.max_value_bytes, :limit)

    case type do
      :bytes ->
        [":", Base.encode64(bytes), ":"]

      :string ->
        ensure(String.match?(bytes, ~r/\A[\x20-\x7e]*\z/), :invalid_value)
        ["\"", bytes |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\""), "\""]

      :token ->
        ensure(
          String.match?(bytes, ~r/\A[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:\/]*\z/),
          :invalid_value
        )

        bytes

      :display_string ->
        ensure(String.valid?(bytes), :invalid_value)

        encoded =
          for <<byte <- bytes>> do
            if byte in [37, 34] or byte < 32 or byte > 126,
              do: [
                "%",
                byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(2, "0")
              ],
              else: <<byte>>
          end

        ["%\"", encoded, "\""]
    end
  end

  defp encode(_, _, _), do: fail(:invalid_value)
end
