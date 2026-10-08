defmodule RequestSeal.DigestTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Body, Digest, FieldOccurrence, Message, StructuredFields, TransportFacts}

  # Independent input and expected bytes: RFC 9530 Appendices B and D.
  @json ~s({"hello": "world"})
  @full @json <> "\n"
  @sha256 "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:"
  @empty "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
  @partial "sha-256=:jjcgBDWNAtbYUXI37CVG3gRuGOAjaaDRGpIUFsdyepQ=:"
  @sha512 "sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:"

  test "published SHA-256 and SHA-512 values compute from exact bytes" do
    {:ok, dictionary} = Digest.compute(body(@json), ["sha-256", "sha-512"])

    assert {:ok,
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"} =
             Digest.serialize(dictionary)

    assert {:ok, _} = Digest.check(message(@full, @sha256 <> ", " <> @sha512), :content)
    assert {:ok, empty} = Digest.compute(body(""), ["sha-256"], max_bytes: 0)
    assert {:ok, @empty} = Digest.serialize(empty)
  end

  test "changed truncated and disagreeing digests reject" do
    for bytes <- [@json, ~s({"hello": "World"}) <> "\n", ""] do
      assert {:error, %{reason: :mismatch}} = Digest.check(message(bytes, @sha256), :content)
    end

    assert {:error, %{reason: :mismatch}} =
             Digest.check(
               message(@full, @sha256 <> ", " <> String.replace(@sha512, "YMAa", "WMAa")),
               :content
             )
  end

  test "stream chunks hash incrementally without transfer framing" do
    {:ok, stream} = Digest.init(:content, ["sha-256", "sha-512"])

    stream =
      Enum.reduce([~s({"hello"), ~s(: "world), "\"}\n"], stream, fn chunk, state ->
        {:ok, state} = Digest.update(state, chunk)
        state
      end)

    msg = message(@full, @sha256 <> ", " <> @sha512)

    assert {:ok, %{bytes: 19, checked: ["sha-256", "sha-512"], unsupported: 0}} =
             Digest.check_stream(stream, %{msg | body: streaming()})

    {:ok, incomplete} = Digest.init(:content, ["sha-256"])
    {:ok, incomplete} = Digest.update(incomplete, @json)
    assert {:error, %{reason: :mismatch}} = Digest.check_stream(incomplete, msg)
    # RFC 9530 B.11: the caller removes transfer framing; framed bytes hash differently.
    assert {:error, %{reason: :mismatch}} =
             Digest.check(message("8\r\n" <> @full, @sha256), :content)
  end

  test "stream and content limits reject before hashing beyond the bound" do
    {:ok, stream} = Digest.init(:content, ["sha-256"], max_bytes: 18)
    assert {:error, %{reason: :limit}} = Digest.update(stream, @full)
    {:ok, stream} = Digest.update(stream, @json)
    assert {:error, %{reason: :limit}} = Digest.update(stream, "\n")
    assert {:error, %{reason: :limit}} = Digest.compute(body(@full), ["sha-256"], max_bytes: 18)
    assert {:error, %{reason: :invalid_chunk}} = Digest.update(stream, [@json])
    assert {:error, %{reason: :invalid_state}} = Digest.update(%{stream | bytes: -1}, @json)
    assert {:error, %{reason: :invalid_state}} = Digest.finish(%{stream | hashes: []})
  end

  test "invalid algorithms kinds options and states return bounded errors" do
    for algorithms <- [
          [],
          ["sha-256", "sha-256"],
          ["md5"],
          ["sha"],
          ["SHA-256"],
          ["sha-256" | :bad],
          :bad
        ] do
      assert {:error, %{reason: :unsupported_algorithm}} = Digest.init(:content, algorithms)
    end

    for options <- [
          [max_bytes: -1],
          [max_bytes: 1.5],
          [max_bytes: 1, max_bytes: 2],
          [unknown: true],
          :bad
        ] do
      assert {:error, %{reason: :invalid_options}} = Digest.init(:content, ["sha-256"], options)
    end

    assert {:error, %{reason: :invalid_kind}} = Digest.init(:digest, ["sha-256"])
    assert {:error, %{reason: :invalid_state}} = Digest.finish(:bad)

    assert {:error, %{reason: :invalid_state}} =
             Digest.check_stream(:bad, message(@full, @sha256))
  end

  test "only caller-fed streams can opt in above the 16 MiB retained-body ceiling" do
    ceiling = 16_777_216
    maximum = 20 * 1_048_576
    chunk = :binary.copy("a", 1_048_576)

    for kind <- [:content, :representation] do
      {:ok, default} = Digest.init(kind, ["sha-256", "sha-512"])
      assert default.max_bytes == ceiling
      {:ok, stream} = Digest.init(kind, ["sha-256", "sha-512"], max_bytes: maximum)

      stream =
        Enum.reduce(1..20, stream, fn _, state ->
          {:ok, next} = Digest.update(state, chunk)
          next
        end)

      assert stream.bytes == maximum
      assert {:error, %{reason: :limit}} = Digest.update(stream, "a")
      assert {:ok, dictionary} = Digest.finish(stream)

      for {name, algorithm} <- [{"sha-256", :sha256}, {"sha-512", :sha512}] do
        expected = :crypto.hash(algorithm, :binary.copy(chunk, 20))
        assert {^name, %{value: {:bytes, ^expected}}} = List.keyfind(dictionary.value, name, 0)
      end

      default =
        Enum.reduce(1..16, default, fn _, state ->
          {:ok, next} = Digest.update(state, chunk)
          next
        end)

      assert {:error, %{reason: :limit}} = Digest.update(default, "a")
    end

    {:ok, retained} =
      Body.new(%{state: :retained, bytes: :binary.copy(chunk, 16), max_bytes: ceiling})

    assert {:ok, _} = Digest.compute(retained, ["sha-256"])
    oversized = %{retained | bytes: retained.bytes <> "a", max_bytes: ceiling + 1}
    assert {:error, %{reason: :limit}} = Digest.compute(oversized, ["sha-256"])

    for retained <- [retained, oversized] do
      assert {:error, %{reason: :invalid_options}} =
               Digest.compute(retained, ["sha-256"], max_bytes: maximum)
    end

    assert {:error, %{reason: :invalid_options}} =
             Digest.check(message(@full, @sha256), :content, max_bytes: maximum)
  end

  test "finish rejects contexts mislabeled with another supported algorithm" do
    for {name, wrong_algorithm} <- [{"sha-256", :sha512}, {"sha-512", :sha256}] do
      {:ok, state} = Digest.init(:content, [name])
      wrong_context = :crypto.hash_update(:crypto.hash_init(wrong_algorithm), @full)

      assert {:error, %{reason: :invalid_state}} =
               Digest.finish(%{state | hashes: [{name, wrong_context}]})
    end
  end

  test "preferences reject invalid sections with the digest option error" do
    msg = message(@full, @sha256, [{"Want-Repr-Digest", "sha-256=10"}])

    for section <- [:both, nil, "headers"] do
      assert {:error, %Digest.Error{reason: :invalid_options}} =
               Digest.preferences(msg, "Want-Repr-Digest", section)
    end
  end

  test "checks reject repeated supported keys before dictionary deduplication" do
    {:ok, stream} = Digest.init(:content, ["sha-256", "sha-512"])
    {:ok, stream} = Digest.update(stream, @full)

    for {good, tampered} <- [
          {@sha256, String.replace(@sha256, "RK/0", "SK/0")},
          {@sha512, String.replace(@sha512, "YMAa", "WMAa")}
        ],
        values <- [[tampered, good], [good, tampered], [good, good]],
        section <- [:headers, :trailers],
        kind <- [:content, :representation] do
      name = if kind == :content, do: "Content-Digest", else: "Repr-Digest"
      options = [section: section]
      options = if kind == :content, do: options, else: [representation: body(@full)] ++ options

      for occurrences <- [
            [field(name, Enum.join(values, ", "), section)],
            [
              field(name, hd(values), section),
              field(String.downcase(name), List.last(values), section)
            ]
          ] do
        msg =
          Map.put(
            message(@full, @sha256),
            if(section == :headers, do: :fields, else: :trailers),
            occurrences
          )

        assert {:error, %Digest.Error{reason: :conflicting_digest}} =
                 Digest.check(msg, kind, options)

        assert {:error, %Digest.Error{reason: :conflicting_digest}} =
                 Digest.check_stream(%{stream | kind: kind}, msg, section: section)
      end
    end
  end

  test "duplicate rejection counts dictionary keys rather than parameters or quoted text" do
    wire = @sha256 <> ~s(;sha-256=:AA==:;note=", sha-256=:AA==:")
    assert {:ok, _} = Digest.check(message(@full, wire), :content)

    unknown_duplicates = @sha256 <> ", unixsum=:GQU=:, unixsum=:AA==:"
    assert {:ok, %{unsupported: 1}} = Digest.check(message(@full, unknown_duplicates), :content)

    msg = %{message(@full, @sha256) | trailers: [field("Content-Digest", @sha256, :trailers)]}
    assert {:ok, _} = Digest.check(msg, :content)
    assert {:ok, _} = Digest.check(msg, :content, section: :trailers)
  end

  test "directly modified stream states and checksum dictionaries reject" do
    {:ok, stream} = Digest.init(:content, ["sha-256"])

    for state <- [
          Map.from_struct(stream),
          Map.put(stream, :unknown, true),
          %{stream | kind: :digest},
          %{stream | bytes: 1, max_bytes: 0},
          %{stream | max_bytes: -1},
          %{stream | hashes: stream.hashes ++ stream.hashes},
          %{stream | hashes: [{"md5", make_ref()}]},
          %{stream | hashes: [{"sha-256", nil}]},
          %{stream | hashes: [{"sha-256", make_ref()}]},
          %{stream | hashes: :bad}
        ] do
      assert {:error, %{reason: :invalid_state}} = Digest.finish(state)
    end

    {:ok, dictionary} = StructuredFields.parse("sha-256=:AA==:", byte_schema())
    assert {:error, %{reason: :invalid_digest_length}} = Digest.serialize(dictionary)
    assert {:error, %{reason: :invalid_preference}} = Digest.parse_preferences("sha-256=-1")
    assert {:error, %{reason: :invalid_preference}} = Digest.parse_preferences("sha-256=11")
  end

  test "range and HEAD require entire explicit representation" do
    {:ok, request} =
      Message.new(%{
        kind: :request,
        method: "HEAD",
        raw_target: "/items/123",
        target_form: :origin,
        fields: [],
        trailers: [],
        body: body(""),
        transport: transport()
      })

    head = %{message("", @empty, [{"Repr-Digest", @sha256}]) | related_request: request}

    range = %{
      message("\"world\"}\n", @partial, [
        {"Repr-Digest", @sha256},
        {"Content-Range", "bytes 10-18/19"}
      ])
      | status: 206
    }

    for msg <- [head, range] do
      assert {:ok, _} = Digest.check(msg, :content)
      assert {:error, %{reason: :representation_required}} = Digest.check(msg, :representation)
      assert {:ok, _} = Digest.check(msg, :representation, representation: body(@full))

      assert {:error, %{reason: :mismatch}} =
               Digest.check(msg, :representation, representation: msg.body)
    end

    assert {:error, %{reason: :invalid_options}} =
             Digest.check(head, :content, representation: body(@full))

    {:ok, stream} = Digest.init(:representation, ["sha-256"])
    {:ok, stream} = Digest.update(stream, @full)
    assert {:ok, %{kind: :representation}} = Digest.check_stream(stream, range)
  end

  test "gzip bytes remain encoded for content and representation digests" do
    # RFC 9530 Appendix A Figure 2, not locally generated compression.
    gzip =
      Base.decode16!(
        "1F8B08008841376400FFAB56CA48CDC9C957B252502ACF2FCA4951AAE50200D9E431E713000000"
      )

    assert :zlib.gunzip(gzip) == @full
    {:ok, computed} = Digest.compute(body(gzip), ["sha-256", "sha-512"])
    {:ok, wire} = Digest.serialize(computed)
    msg = message(gzip, wire, [{"Repr-Digest", wire}, {"Content-Encoding", "gzip"}])
    assert {:ok, _} = Digest.check(msg, :content)
    assert {:ok, _} = Digest.check(msg, :representation, representation: body(gzip))
    assert {:error, %{reason: :mismatch}} = Digest.check(%{msg | body: body(@full)}, :content)

    assert {:error, %{reason: :mismatch}} =
             Digest.check(msg, :representation, representation: body(@full))
  end

  test "explicit trailers are checked after streaming with no header substitution" do
    msg = message(@full, @empty)
    trailer = field("Content-Digest", @sha256, :trailers)
    msg = %{msg | trailers: [trailer], body: streaming()}
    {:ok, stream} = Digest.init(:content, ["sha-256"])
    {:ok, stream} = Digest.update(stream, @full)
    assert {:ok, _} = Digest.check_stream(stream, msg, section: :trailers)
    assert {:error, %{reason: :mismatch}} = Digest.check_stream(stream, msg)

    assert {:error, %{reason: :unavailable_section}} =
             Digest.check_stream(stream, %{msg | trailers: :pending}, section: :trailers)

    assert {:error, %{reason: :invalid_options}} =
             Digest.check_stream(stream, msg, section: :both)

    assert {:error, %{reason: :uncomputed_algorithm}} =
             Digest.check_stream(stream, message(@full, @sha512))

    repr = %{message(@full, @sha256) | trailers: [field("Repr-Digest", @sha256, :trailers)]}

    assert {:ok, _} =
             Digest.check(repr, :representation, section: :trailers, representation: body(@full))
  end

  test "unknown weak empty malformed and legacy-only fields cannot establish a match" do
    for wire <- [
          "md5=:Sd/dVLAcvNLSq16eXua5uQ==:",
          "sha=:07CavjDP4u3/TungoUHJO/Wzr4c=:",
          "unixsum=:GQU=:",
          ""
        ] do
      assert {:error, %{reason: :unsupported_algorithm}} =
               Digest.check(message(@json, wire), :content)
    end

    assert {:ok, %{unsupported: 1, checked: ["sha-256"]}} =
             Digest.check(message(@full, @sha256 <> ", unixsum=:GQU=:"), :content)

    for {wire, reason} <- [
          {"sha-256=1", :schema_type},
          {"sha-256=(:AA==:)", :schema_type},
          {"sha-256=:AA==:", :invalid_digest_length},
          {"sha-256=:!:", :syntax}
        ] do
      assert {:error, %{reason: ^reason}} = Digest.check(message(@full, wire), :content)
    end

    assert {:error, %{reason: :invalid_digest_length}} = Digest.parse("sha-256=:AA==:")
    legacy = %{message(@full, @sha256) | fields: [field("Digest", @sha256)]}
    assert {:error, %{reason: :missing_field}} = Digest.check(legacy, :content)
  end

  test "availability and invalid capture never substitute empty bytes" do
    msg = message(@full, @sha256)

    for state <- [:unavailable, :consumed, :streaming] do
      b = if state == :streaming, do: streaming(), else: elem(Body.new(%{state: state}), 1)
      assert {:error, %{reason: :body_unavailable}} = Digest.check(%{msg | body: b}, :content)
      assert {:error, %{reason: :body_unavailable}} = Digest.compute(b, ["sha-256"])
    end

    assert {:error, %{reason: :invalid_body}} =
             Digest.compute(%{body(@full) | bytes: nil}, ["sha-256"])

    assert {:error, %{reason: :invalid_message}} = Digest.check(%{msg | status: 0}, :content)
    assert {:error, %{reason: :invalid_kind}} = Digest.check(msg, :digest)
    assert {:error, %{reason: :invalid_options}} = Digest.check(msg, :content, unknown: true)

    assert {:error, %{reason: :invalid_options}} =
             Digest.check(msg, :content, section: :headers, section: :headers)
  end

  test "digest fields and preferences preserve RFC dictionary rules and parameters" do
    {:ok, parsed} = Digest.parse(@sha256 <> ";foo, " <> @sha256)
    assert {:ok, @sha256} = Digest.serialize(parsed)

    msg = %{
      message(@full, @sha256)
      | fields: [field("Content-Digest", @sha256), field("content-digest", @sha512)]
    }

    assert {:ok, %{checked: ["sha-256", "sha-512"]}} = Digest.check(msg, :content)
    {:ok, prefs} = Digest.parse_preferences("sha-512=3, sha-256=10, unixsum=0")
    assert {:ok, "sha-512=3, sha-256=10, unixsum=0"} = Digest.serialize_preferences(prefs)

    for name <- [
          "Want-Content-Digest",
          "Want-Repr-Digest",
          "want-content-digest",
          "wAnT-RePr-DiGeSt"
        ] do
      msg = %{msg | fields: [field(name, "sha-512=3, sha-256=10, unixsum=0")]}
      assert {:ok, ^prefs} = Digest.preferences(msg, name)
    end

    for {wire, reason} <- [
          {"sha-256=-1", :invalid_preference},
          {"sha-256=11", :invalid_preference},
          {"sha-256=1.0", :schema_type},
          {"sha-256", :schema_type},
          {"sha-256=(1)", :schema_type}
        ] do
      assert {:error, %{reason: ^reason}} = Digest.parse_preferences(wire)
    end

    assert {:error, %{reason: :invalid_field}} = Digest.preferences(msg, "Want-Digest")
    {:ok, invalid} = StructuredFields.parse("sha-256=11", integer_schema())
    assert {:error, %{reason: :invalid_preference}} = Digest.serialize_preferences(invalid)
    assert {:error, %{reason: :invalid_value}} = Digest.serialize(:bad)
  end

  test "digest dictionary member limit counts encounters below the wire byte bound" do
    allowed = Enum.map_join(1..1024, ", ", fn i -> "x#{i}=:AA==:" end)
    excess = allowed <> ", x1025=:AA==:"
    assert byte_size(excess) < 65_536
    assert {:ok, _} = Digest.parse(allowed)
    assert {:error, %{reason: :limit}} = Digest.parse(excess)
  end

  test "unknown-only streams cannot report checksum agreement" do
    {:ok, stream} = Digest.init(:content, ["sha-256"])
    {:ok, stream} = Digest.update(stream, @json)

    assert {:error, %{reason: :unsupported_algorithm}} =
             Digest.check_stream(stream, message(@json, "md5=:Sd/dVLAcvNLSq16eXua5uQ==:"))

    assert {:error, %{reason: :unsupported_algorithm}} =
             Digest.check_stream(stream, message(@json, ""))
  end

  test "invalid semantic kinds cannot select a representation and invalid messages reject before body access" do
    msg = message(@full, @sha256, [{"Repr-Digest", @sha256}])

    assert {:error, %{reason: :invalid_kind}} =
             Digest.check(msg, :digest, representation: body(@full))

    assert {:error, %{reason: :invalid_message}} =
             Digest.check(%{msg | status: 0, body: streaming()}, :content)

    assert {:error, %{reason: :invalid_message}} = Digest.check(%{}, :content)
  end

  test "inspection and errors exclude content and raw attacker values" do
    {:ok, stream} = Digest.init(:content, ["sha-256"])
    {:ok, stream} = Digest.update(stream, @full)
    assert inspect(stream) =~ "RequestSeal.Digest"
    refute inspect(stream) =~ "hello"
    assert {:ok, result} = Digest.check_stream(stream, message(@full, @sha256))
    refute inspect(result) =~ "RK/0"
    assert {:error, error} = Digest.check(message(@json, @sha256), :content)
    refute inspect(error) =~ "hello"
  end

  defp body(bytes), do: elem(Body.new(%{state: :retained, bytes: bytes}), 1)
  defp streaming, do: elem(Body.new(%{state: :streaming, source: self()}), 1)
  defp transport, do: elem(TransportFacts.new(%{}), 1)

  defp field(name, value, section \\ :headers),
    do: elem(FieldOccurrence.new(%{name: name, value: value, section: section}), 1)

  defp message(bytes, digest, extra \\ []) do
    fields = [field("Content-Digest", digest) | Enum.map(extra, fn {k, v} -> field(k, v) end)]

    {:ok, msg} =
      Message.new(%{
        kind: :response,
        status: 200,
        fields: fields,
        trailers: [],
        body: body(bytes),
        transport: transport()
      })

    msg
  end

  defp byte_schema,
    do:
      elem(
        StructuredFields.Schema.new(%{
          revision: :rfc8941,
          type: :dictionary,
          item_types: [:bytes]
        }),
        1
      )

  defp integer_schema,
    do:
      elem(
        StructuredFields.Schema.new(%{
          revision: :rfc8941,
          type: :dictionary,
          item_types: [:integer]
        }),
        1
      )
end
