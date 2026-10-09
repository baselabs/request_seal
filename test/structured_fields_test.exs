defmodule RequestSeal.StructuredFieldsTest do
  use ExUnit.Case, async: true
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}

  @root Path.join(__DIR__, "fixtures/structured_fields")
  @types [:integer, :decimal, :string, :token, :bytes, :boolean, :date, :display_string]

  for wire <- [":iZ==:", ":iZ=:", ":iZ:", ":QR:", ":QUJ=:", ":uuueGVsbG8=:"] do
    @wire wire
    test "nonzero base64 pad bits reject in #{@wire}" do
      for revision <- [:rfc8941, :rfc9651] do
        assert {:error, %{reason: :syntax}} = SF.parse(@wire, schema("item", revision))
      end
    end
  end

  test "zero base64 pad bits accept with complete, partial, or absent padding" do
    for revision <- [:rfc8941, :rfc9651],
        {wire, bytes} <- [
          {":iQ==:", <<137>>},
          {":iQ=:", <<137>>},
          {":iQ:", <<137>>},
          {":QQ:", "A"},
          {":QUI=:", "AB"},
          {":QUI:", "AB"},
          {":QUJD:", "ABC"},
          {"::", ""}
        ] do
      assert {:ok, %Value{value: {:bytes, ^bytes}}} = SF.parse(wire, schema("item", revision))
    end
  end

  for file <- Path.wildcard(Path.join(@root, "**/*.json")) do
    @fixture_path file
    test "HTTP WG #{Path.relative_to(file, @root)}" do
      vectors = :json.decode(File.read!(@fixture_path))
      assert vectors != []
      Enum.each(vectors, &assert_vector/1)
    end
  end

  defp assert_vector(v) do
    schema = schema(v["header_type"])

    if Map.has_key?(v, "raw") do
      result = SF.parse(Enum.join(v["raw"], ", "), schema)

      cond do
        v["must_fail"] == true ->
          assert {:error, _} = result

        v["can_fail"] == true and match?({:error, _}, result) ->
          :ok

        true ->
          assert {:ok, parsed} = result
          assert_equivalent(parsed, expected(v["expected"], v["header_type"]))
          assert {:ok, canonical} = SF.serialize(parsed, schema)
          assert canonical == Enum.join(Map.get(v, "canonical", v["raw"]), ", ")
      end
    end

    if Map.has_key?(v, "expected") do
      result = SF.serialize(expected(v["expected"], v["header_type"]), schema)

      if v["must_fail"] == true do
        assert {:error, _} = result
      else
        assert {:ok, canonical} = result
        assert canonical == Enum.join(Map.get(v, "canonical", Map.get(v, "raw", [])), ", ")
      end
    end
  rescue
    error in ExUnit.AssertionError ->
      reraise %{error | message: "HTTP WG #{v["name"]}: #{error.message}"}, __STACKTRACE__
  end

  test "vendored vector inventory matches immutable upstream hashes" do
    lines = File.read!(Path.join(@root, "SHA256SUMS")) |> String.split("\n", trim: true)

    entries =
      Enum.map(lines, fn line ->
        [hash, file] = String.split(line, "  ", parts: 2)
        {file, hash}
      end)

    files = Path.wildcard(Path.join(@root, "**/*.json")) |> Enum.map(&Path.relative_to(&1, @root))
    assert "date.json" in files
    assert Enum.sort(Enum.map(entries, &elem(&1, 0))) == Enum.sort(["LICENSE" | files])

    for {file, hash} <- entries do
      assert Base.encode16(:crypto.hash(:sha256, File.read!(Path.join(@root, file))),
               case: :lower
             ) == hash
    end

    count =
      Enum.reduce(files, 0, fn file, acc ->
        acc + length(:json.decode(File.read!(Path.join(@root, file))))
      end)

    assert count == 2137
  end

  test "malformed direct schemas and values return bounded errors" do
    v = expected(vector("list.json", "basic list")["expected"], "list")
    s = schema("list")

    for bad <- [
          Map.delete(s, :item_types),
          Map.put(Map.delete(s, :item_types), :extra, true),
          %{s | item_types: [:integer | :invalid]},
          %{s | parameter_types: [:boolean | :invalid]}
        ] do
      assert {:error, %{reason: :invalid_schema}} = SF.parse("", bad)
      assert {:error, %{reason: :invalid_schema}} = SF.serialize(v, bad)
    end

    for bad <- [
          Map.delete(v, :value),
          Map.put(Map.delete(v, :value), :extra, true),
          %{v | value: [hd(v.value) | :invalid]},
          %{v | parameters: [:invalid]}
        ] do
      assert {:error, %{reason: :invalid_value}} = SF.serialize(bad, s)
    end

    assert {:error, %{reason: :invalid_limits}} = SF.parse("", s, max_bytes: 1, max_bytes: 2)
    assert {:error, %{reason: :invalid_limits}} = SF.parse("", s, [:invalid])
  end

  test "key and decoded value ceilings apply in both directions" do
    for {name, limit, length} <- [
          {"large dictionary key", :max_key_bytes, 64},
          {"large token", :max_value_bytes, 512},
          {"large byte sequence", :max_value_bytes, 16_384},
          {"large string", :max_value_bytes, 1024}
        ] do
      v = vector("large-generated.json", name)
      raw = Enum.join(v["raw"], ", ")
      s = schema(v["header_type"])
      assert {:ok, parsed} = SF.parse(raw, s, [{limit, length}])
      assert {:ok, _} = SF.serialize(parsed, s, [{limit, length}])
      assert {:error, %{reason: :limit}} = SF.parse(raw, s, [{limit, length - 1}])
      assert {:error, %{reason: :limit}} = SF.serialize(parsed, s, [{limit, length - 1}])
    end
  end

  test "RFC 8941 rejects dates and display strings in every value position" do
    for file <- ["date.json", "display-string.json"],
        v <- :json.decode(File.read!(Path.join(@root, file))),
        v["must_fail"] != true do
      raw = Enum.join(v["raw"], ", ")
      value = expected(v["expected"], "item")
      assert {:error, %{reason: :revision_type}} = SF.parse(raw, schema("item", :rfc8941))
      assert {:error, %{reason: :revision_type}} = SF.serialize(value, schema("item", :rfc8941))

      parameterized = %Value{
        type: :item,
        value: {:boolean, true},
        parameters: [{"a", value.value}]
      }

      for {wrapped, type, wrapped_value} <- [
            {"?1;a=" <> raw, "list", %Value{type: :list, value: [parameterized]}},
            {"a=" <> raw, "dictionary", %Value{type: :dictionary, value: [{"a", value}]}},
            {"(" <> raw <> ")", "list",
             %Value{type: :list, value: [%Value{type: :inner_list, value: [value]}]}},
            {"(?1);a=" <> raw, "list",
             %Value{
               type: :list,
               value: [
                 %Value{
                   type: :inner_list,
                   value: [%Value{type: :item, value: {:boolean, true}}],
                   parameters: [{"a", value.value}]
                 }
               ]
             }}
          ] do
        assert {:ok, _} = SF.serialize(wrapped_value, schema(type))
        assert {:error, %{reason: :revision_type}} = SF.parse(wrapped, schema(type, :rfc8941))

        assert {:error, %{reason: :revision_type}} =
                 SF.serialize(wrapped_value, schema(type, :rfc8941))
      end
    end
  end

  test "explicit field types and parameter types apply to parsing and serialization" do
    # RFC 9651 Section 3.1 example, independently published in examples.json.
    v = vector("examples.json", "Example-ListListParam")
    raw = Enum.join(v["raw"], ", ")
    {:ok, value} = SF.parse(raw, schema("list"))

    for restrictions <- [
          %{item_types: [:integer]},
          %{inner_lists: false},
          %{parameter_types: [:boolean]}
        ] do
      s = struct(schema("list"), restrictions)
      assert {:error, %{reason: :schema_type}} = SF.parse(raw, s)
      assert {:error, %{reason: :schema_type}} = SF.serialize(value, s)
    end

    assert {:error, %{reason: :invalid_schema}} = Schema.new(%{type: :item})
    assert {:error, _} = SF.parse(raw, %{type: :list})
    assert {:error, _} = SF.serialize(value, %{type: :list})
  end

  test "byte, member, inner-item, parameter and node bounds include duplicates" do
    for {file, name, type, limit, good} <- [
          {"list.json", "basic list", "list", :max_members, 2},
          {"dictionary.json", "basic dictionary", "dictionary", :max_members, 2},
          {"param-list.json", "basic parameterised list", "list", :max_parameters, 3},
          {"listlist.json", "basic list of lists", "list", :max_inner_items, 2}
        ] do
      v = vector(file, name)
      raw = Enum.join(v["raw"], ", ")
      assert {:ok, parsed} = SF.parse(raw, schema(type), [{limit, good}])
      assert {:ok, _} = SF.serialize(parsed, schema(type), [{limit, good}])
      assert {:error, %{reason: :limit}} = SF.parse(raw, schema(type), [{limit, good - 1}])
      assert {:error, %{reason: :limit}} = SF.serialize(parsed, schema(type), [{limit, good - 1}])
    end

    v = vector("param-list.json", "duplicate parameter with different positions")
    raw = Enum.join(v["raw"], ", ")
    assert {:error, %{reason: :limit}} = SF.parse(raw, schema("list"), max_parameters: 1)
    raw = Enum.join(vector("dictionary.json", "duplicate key dictionary")["raw"], ", ")
    assert {:error, %{reason: :limit}} = SF.parse(raw, schema("dictionary"), max_members: 1)
    raw = Enum.join(vector("list.json", "basic list")["raw"], ", ")
    assert {:ok, value} = SF.parse(raw, schema("list"), max_bytes: byte_size(raw))

    assert {:error, %{reason: :limit}} =
             SF.parse(raw, schema("list"), max_bytes: byte_size(raw) - 1)

    assert {:error, %{reason: :limit}} =
             SF.serialize(value, schema("list"), max_bytes: byte_size(raw) - 1)

    assert {:error, %{reason: :limit}} = SF.parse(raw, schema("list"), max_nodes: 1)
    assert {:error, %{reason: :limit}} = SF.serialize(value, schema("list"), max_nodes: 1)

    for bad <- [[max_bytes: 65_537], [max_nodes: 0], [unknown: 1], [max_bytes: -1]] do
      assert {:error, %{reason: :invalid_limits}} = SF.parse(raw, schema("list"), bad)
      assert {:error, %{reason: :invalid_limits}} = SF.serialize(value, schema("list"), bad)
    end
  end

  test "published bytes mutated at every position remain bounded and never raise" do
    for file <- ["examples.json", "display-string.json", "dictionary.json"],
        v <- :json.decode(File.read!(Path.join(@root, file))),
        raw <- v["raw"],
        offset <- 0..byte_size(raw),
        byte <- [0, 9, 10, 13, 32, 34, 37, 40, 41, 44, 59, 127, 255] do
      <<left::binary-size(^offset), right::binary>> = raw
      result = SF.parse(left <> <<byte>> <> right, schema(v["header_type"]))
      assert match?({:ok, %Value{}}, result) or match?({:error, %{reason: _}}, result)
      if byte in [0, 10, 13, 127, 255], do: assert(match?({:error, _}, result))
    end
  end

  test "field occurrences combine in order and keep headers and trailers separate" do
    v = vector("param-list.json", "two lines parameterised list")

    fields =
      Enum.map(v["raw"], fn raw ->
        {:ok, f} =
          RequestSeal.FieldOccurrence.new(%{
            name: "Example-ParamListHeader",
            value: raw,
            section: :headers
          })

        f
      end)

    {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
    {:ok, transport} = RequestSeal.TransportFacts.new(%{})

    {:ok, message} =
      RequestSeal.Message.new(%{
        kind: :request,
        method: "GET",
        raw_target: "/",
        target_form: :origin,
        fields: fields,
        trailers: [],
        body: body,
        transport: transport
      })

    assert {:ok, parsed} =
             SF.parse_field(message, "example-paramlistheader", schema("list"), :headers)

    assert_equivalent(parsed, expected(v["expected"], "list"))

    combined_bytes = byte_size(Enum.join(v["raw"], ", "))

    assert {:ok, _} =
             SF.parse_field(message, "example-paramlistheader", schema("list"), :headers,
               max_bytes: combined_bytes
             )

    assert {:error, %{reason: :limit}} =
             SF.parse_field(message, "example-paramlistheader", schema("list"), :headers,
               max_bytes: combined_bytes - 1
             )

    assert {:error, %{reason: :limit}} =
             SF.parse_field(message, "example-paramlistheader", schema("list"), :headers,
               max_members: 1
             )

    assert {:error, %{reason: :invalid_limits}} =
             SF.parse_field(message, "example-paramlistheader", schema("list"), :headers,
               max_bytes: 65_537
             )

    assert {:error, %{reason: :missing_field}} =
             SF.parse_field(message, "example-paramlistheader", schema("list"), :trailers)

    assert {:error, _} =
             SF.parse_field(
               %{message | trailers: :unavailable},
               "example-paramlistheader",
               schema("list"),
               :trailers
             )

    assert {:error, _} =
             SF.parse_field(
               %{message | fields: [%{hd(fields) | value: <<0>>}]},
               "example-paramlistheader",
               schema("list"),
               :headers
             )
  end

  test "field unique-key policy rejects repeats only when requested" do
    v = vector("dictionary.json", "duplicate key dictionary")

    {:ok, field} =
      RequestSeal.FieldOccurrence.new(%{
        name: "Example",
        value: Enum.join(v["raw"], ", "),
        section: :headers
      })

    {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
    {:ok, transport} = RequestSeal.TransportFacts.new(%{})

    {:ok, message} =
      RequestSeal.Message.new(%{
        kind: :request,
        method: "GET",
        raw_target: "/",
        target_form: :origin,
        fields: [field],
        trailers: [],
        body: body,
        transport: transport
      })

    assert {:error, %{reason: :duplicate_key}} =
             SF.parse_field(message, "Example", schema("dictionary"), :headers,
               unique_keys: ["a"]
             )

    assert {:ok, parsed} = SF.parse_field(message, "Example", schema("dictionary"), :headers)
    assert_equivalent(parsed, expected(v["expected"], "dictionary"))
  end

  test "parse rejects the field-only unique-key option" do
    assert {:error, %{reason: :invalid_limits}} =
             SF.parse("a=1", schema("dictionary"), unique_keys: ["a"])
  end

  test "serialize rejects the field-only unique-key option" do
    assert {:ok, parsed} = SF.parse("a=1", schema("dictionary"))

    assert {:error, %{reason: :invalid_limits}} =
             SF.serialize(parsed, schema("dictionary"), unique_keys: ["a"])
  end

  test "field unique-key policy rejects invalid option shapes and excess keys" do
    {:ok, field} =
      RequestSeal.FieldOccurrence.new(%{name: "Example", value: "a=1", section: :headers})

    {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
    {:ok, transport} = RequestSeal.TransportFacts.new(%{})

    {:ok, message} =
      RequestSeal.Message.new(%{
        kind: :request,
        method: "GET",
        raw_target: "/",
        target_form: :origin,
        fields: [field],
        trailers: [],
        body: body,
        transport: transport
      })

    for unique_keys <- [nil, "a", :a, %{"a" => true}, [:a], [1], [""], ["A"], ["a" | :bad]] do
      assert {:error, %{reason: :invalid_limits}} =
               SF.parse_field(message, "Example", schema("dictionary"), :headers,
                 unique_keys: unique_keys
               )
    end

    assert {:error, %{reason: :invalid_limits}} =
             SF.parse_field(message, "Example", schema("dictionary"), :headers,
               unique_keys: Enum.map(1..1025, &("a" <> Integer.to_string(&1)))
             )

    assert {:error, %{reason: :invalid_limits}} =
             SF.parse_field(message, "Example", schema("dictionary"), :headers,
               max_members: 1,
               unique_keys: ["a", "b"]
             )
  end

  test "signature parsing rejects duplicate parameters while generic RFC parsing retains last wins" do
    for {first, last} <- [{"a", "fresh"}, {"fresh", "a"}] do
      wire = ~s[s=("@method");nonce="#{first}";nonce="#{last}"]
      assert {:ok, parsed} = SF.parse(wire, schema("dictionary"))

      assert hd(parsed.value) |> elem(1) |> Map.fetch!(:parameters) == [
               {"nonce", {:string, last}}
             ]

      assert {:error, %{reason: :duplicate_parameter}} =
               SF.parse_unique(wire, schema("dictionary"), [])
    end

    for wire <- [~s[s=:YWJj:;nonce="a";nonce="b"], ~s[s=("signature";key="a";key="b")]] do
      assert {:error, %{reason: :duplicate_parameter}} =
               SF.parse_unique(wire, schema("dictionary"), [])
    end

    assert {:error, %{reason: :limit}} =
             SF.parse_unique(~s[s=();nonce="a";nonce="b"], schema("dictionary"),
               max_parameters: 1
             )

    assert {:error, %{reason: :syntax}} =
             SF.parse_unique(~s[s=();nonce="a";nonce="b", (], schema("dictionary"), [])

    assert {:ok, _} =
             SF.parse_unique(~s[s=();nonce="a", t=();nonce="b"], schema("dictionary"), [])
  end

  test "direct values cannot bypass depth, key uniqueness, numeric or schema guards" do
    {:ok, v} =
      SF.parse(
        Enum.join(vector("listlist.json", "basic list of lists")["raw"], ", "),
        schema("list")
      )

    nested = %{hd(v.value) | value: [hd(v.value)]}
    assert {:error, _} = SF.serialize(%{v | value: [nested]}, schema("list"))
    assert {:error, _} = SF.serialize(%{v | value: :invalid}, schema("list"))
    assert {:error, _} = SF.serialize(Map.put(v, :extra, true), schema("list"))

    for file <- ["number.json", "date.json"],
        x <- :json.decode(File.read!(Path.join(@root, file))),
        x["must_fail"] == true do
      assert {:error, _} = SF.parse(Enum.join(x["raw"], ", "), schema(x["header_type"]))
    end

    params = [{"a", {:boolean, true}}, {"a", {:boolean, false}}]

    assert {:error, _} =
             SF.serialize(
               %Value{type: :item, value: {:boolean, true}, parameters: params},
               schema("item")
             )
  end

  for {kind, inputs} <- [
        {"integer", ["12345678901234567", "1234567890123456", String.duplicate("1", 1024)]},
        {"fraction", ["1.23456", "1.2345", "1." <> String.duplicate("1", 1024)]}
      ] do
    @numeric_inputs inputs
    test "#{kind} digit-count violations are syntax errors rather than resource limits" do
      for sign <- ["", "-"], raw <- @numeric_inputs do
        assert {:error, %{reason: :syntax}} = SF.parse(sign <> raw, schema("item"))
        assert {:error, %{reason: :syntax}} = SF.parse("@" <> sign <> raw, schema("item"))
      end
    end
  end

  test "vector assertion diagnostics expose parsed and expected values" do
    v = vector("list.json", "basic list")
    {:ok, parsed} = SF.parse(Enum.join(v["raw"], ", "), schema("list"))
    mismatched = expected([], "list")

    error =
      assert_raise ExUnit.AssertionError, fn -> assert_vector(Map.put(v, "expected", [])) end

    assert error.message =~ "HTTP WG #{v["name"]}"
    assert error.message =~ "parsed: #{inspect(parsed, structs: false)}"
    assert error.message =~ "expected: #{inspect(mismatched, structs: false)}"
  end

  test "fixture float conversion handles exponent notation exactly" do
    assert bare(1.0e-5) == {:decimal, {10, 6}}
    assert bare(-1.0e-5) == {:decimal, {-10, 6}}
    assert bare(1.0e20) == {:decimal, {100_000_000_000_000_000_000, 0}}
    assert bare(-1.25e20) == {:decimal, {-125_000_000_000_000_000_000, 0}}
    assert bare(1.25) == {:decimal, {125, 2}}
  end

  defp schema(type, revision \\ :rfc9651) do
    {:ok, s} =
      Schema.new(%{
        type: String.to_existing_atom(type),
        revision: revision,
        item_types:
          if(revision == :rfc8941, do: @types -- [:date, :display_string], else: @types),
        inner_lists: true
      })

    s
  end

  defp vector(file, name) do
    vectors = :json.decode(File.read!(Path.join(@root, file)))

    Enum.find(vectors, &(&1["name"] == name)) ||
      raise "Unknown published vector: #{file}: #{name}"
  end

  defp expected(values, "dictionary"),
    do: %Value{type: :dictionary, value: Enum.map(values, fn [k, v] -> {k, member(v)} end)}

  defp expected(values, "list"), do: %Value{type: :list, value: Enum.map(values, &member/1)}
  defp expected(value, "item"), do: member(value)

  defp member([values, params]) when is_list(values),
    do: %Value{
      type: :inner_list,
      value: Enum.map(values, &member/1),
      parameters: parameters(params)
    }

  defp member([value, params]),
    do: %Value{type: :item, value: bare(value), parameters: parameters(params)}

  defp parameters(params), do: Enum.map(params, fn [k, v] -> {k, bare(v)} end)

  defp bare(%{"__type" => "binary", "value" => value}),
    do: {:bytes, Base.decode32!(value, padding: true)}

  defp bare(%{"__type" => "displaystring", "value" => value}), do: {:display_string, value}
  defp bare(%{"__type" => type, "value" => value}), do: {String.to_existing_atom(type), value}
  defp bare(value) when is_boolean(value), do: {:boolean, value}
  defp bare(value) when is_integer(value), do: {:integer, value}
  defp bare(value) when is_binary(value), do: {:string, value}

  defp bare(value) when is_float(value) do
    {mantissa, exponent} =
      case String.split(Float.to_string(value), "e", parts: 2) do
        [mantissa] -> {mantissa, 0}
        [mantissa, exponent] -> {mantissa, String.to_integer(exponent)}
      end

    [whole, fractional] = String.split(mantissa, ".")
    coefficient = String.to_integer(whole <> fractional)
    scale = byte_size(fractional) - exponent

    if scale < 0,
      do: {:decimal, {coefficient * Integer.pow(10, -scale), 0}},
      else: {:decimal, {coefficient, scale}}
  end

  defp assert_equivalent(parsed, expected) do
    assert equivalent(parsed, expected),
           "parsed: #{inspect(parsed, structs: false)}\nexpected: #{inspect(expected, structs: false)}"
  end

  defp equivalent(%Value{type: t, value: a, parameters: ap}, %Value{
         type: t,
         value: b,
         parameters: bp
       }),
       do: equivalent(a, b) and equivalent(ap, bp)

  defp equivalent({:decimal, {a, x}}, {:decimal, {b, y}}),
    do: a * Integer.pow(10, y) == b * Integer.pow(10, x)

  defp equivalent({k, a}, {k, b}), do: equivalent(a, b)

  defp equivalent(a, b) when is_list(a) and is_list(b),
    do: length(a) == length(b) and Enum.zip(a, b) |> Enum.all?(fn {x, y} -> equivalent(x, y) end)

  defp equivalent(a, b), do: a == b
end
