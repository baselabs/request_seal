defmodule RequestSeal.SignatureBaseTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Body, FieldOccurrence, Message, SignatureBase, TransportFacts}
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}

  @root Path.join(__DIR__, "fixtures/signature_base")
  @vectors :json.decode(File.read!(Path.join(@root, "rfc9421.json")))

  test "all complete Sections 2, 4.3 and Appendix B bases match independently published bytes" do
    assert length(@vectors) == 12
    assert Enum.any?(@vectors, &(&1["section"] == "B.2.1"))

    for v <- @vectors do
      message = published_message(v["message"])
      assert {:ok, base} = SignatureBase.build(message, v["parameters"])
      assert base === v["base"], "RFC 9421 #{v["section"]}, source line #{v["source_line"]}"
      refute String.ends_with?(base, "\n")
      {:ok, %Value{value: [parameters]}} = SF.parse(v["parameters"], signature_schema())
      assert SignatureBase.build(message, parameters) == {:ok, v["base"]}
    end
  end

  test "Appendix B.4 all published transformations change only covered byte facts" do
    v = Enum.find(@vectors, &(&1["section"] == "B.4"))
    assert length(v["transformations"]) == 5

    for transformation <- v["transformations"] do
      assert {:ok, base} =
               SignatureBase.build(published_message(transformation["message"]), v["parameters"])

      assert base == v["base"] == transformation["same_base"],
             "RFC 9421 B.4, source line #{transformation["source_line"]}"
    end
  end

  test "Section 2.1 folding must be removed at capture before component construction" do
    assert {:error, _} =
             FieldOccurrence.new(%{
               name: "X-Obs-Fold-Header",
               value: "Obsolete\r\n    line folding.",
               section: :headers,
               provenance: :http1
             })

    message = request(%{fields: fields([{"X-Obs-Fold-Header", "Obsolete line folding."}])})

    assert_lines(message, ~s[("x-obs-fold-header")], [
      ~s["x-obs-fold-header": Obsolete line folding.]
    ])
  end

  test "the vendored expected bytes have a complete immutable hash inventory" do
    [hash, name] =
      File.read!(Path.join(@root, "SHA256SUMS")) |> String.trim() |> String.split("  ")

    assert name == "rfc9421.json"

    assert Base.encode16(:crypto.hash(:sha256, File.read!(Path.join(@root, name))), case: :lower) ==
             hash
  end

  test "Section 2.1 fields preserve OWS rules, internal whitespace and ordered repeats" do
    message =
      request(%{
        fields:
          fields([
            {"Host", "www.example.com"},
            {"Date", "Tue, 20 Apr 2021 02:07:56 GMT"},
            {"X-OWS-Header", "  Leading and trailing whitespace.  \t"},
            {"Cache-Control", "max-age=60"},
            {"Cache-Control", "   must-revalidate"},
            {"Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
            {"X-Empty-Header", " "}
          ])
      })

    assert_lines(
      message,
      ~s[("host" "date" "x-ows-header" "cache-control" "example-dict" "x-empty-header")],
      [
        ~s["host": www.example.com],
        ~s["date": Tue, 20 Apr 2021 02:07:56 GMT],
        ~s["x-ows-header": Leading and trailing whitespace.],
        ~s["cache-control": max-age=60, must-revalidate],
        ~s["example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)],
        ~s["x-empty-header": ]
      ]
    )
  end

  test "Section 2.1.1 and 2.1.2 strict fields and dictionary members use explicit schemas" do
    message =
      request(%{fields: fields([{"Example-Dict", " a=1,    b=2;x=1;y=2,   c=(a   b   c), d"}])})

    opts = [field_schemas: %{"example-dict" => dictionary_schema()}]

    assert_lines(
      message,
      ~s[("example-dict";sf "example-dict";key="a" "example-dict";key="d" "example-dict";key="b" "example-dict";key="c")],
      [
        ~s["example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c), d],
        ~s["example-dict";key="a": 1],
        ~s["example-dict";key="d": ?1],
        ~s["example-dict";key="b": 2;x=1;y=2],
        ~s["example-dict";key="c": (a b c)]
      ],
      opts
    )

    assert_lines(
      message,
      ~s[("example-dict";sf;key="b")],
      [~s["example-dict";sf;key="b": 2;x=1;y=2]],
      opts
    )

    assert_error(message, ~s[("example-dict";sf)], :unknown_field_schema)
    assert_error(message, ~s[("example-dict";key="missing")], :missing_dictionary_key, opts)

    assert_error(message, ~s[("example-dict";key="a")], :invalid_field_schema,
      field_schemas: %{"example-dict" => item_schema()}
    )

    malformed = %{message | fields: fields([{"Example-Dict", "a=("}])}
    assert_error(malformed, ~s[("example-dict";sf)], :invalid_structured_field, opts)
    newer = %{message | fields: fields([{"Example-Dict", "a=@42"}])}
    assert_error(newer, ~s[("example-dict";sf)], :invalid_structured_field, opts)
  end

  test "Section 2.1.3 binary wrapping separates ambiguous occurrence boundaries" do
    message =
      request(%{
        fields:
          fields([{"Example-Header", "value, with, lots"}, {"Example-Header", "of, commas"}])
      })

    assert_lines(message, ~s[("example-header";bs)], [
      ~s["example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:]
    ])

    single = %{message | fields: fields([{"Example-Header", "value, with, lots, of, commas"}])}

    assert_lines(single, ~s[("example-header";bs)], [
      ~s["example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:]
    ])

    assert SignatureBase.build(message, ~s[("example-header";bs)]) !=
             SignatureBase.build(single, ~s[("example-header";bs)])

    assert_error(message, ~s[("example-header";bs;sf)], :incompatible_parameters)
    assert_error(message, ~s[("example-header";bs;key="a")], :incompatible_parameters)
    # Hostile octet mutation of the public Section 2.1.3 field, not a peer fixture.
    octets = %{single | fields: fields([{"Example-Header", <<255>>}])}
    assert_error(octets, ~s[("example-header")], :non_ascii)
    assert_lines(octets, ~s[("example-header";bs)], [~s["example-header";bs: :/w==:]])
  end

  test "Section 2.1.4 trailers stay separate and unavailable or pending trailers reject" do
    message =
      response(%{
        fields: fields([{"Trailer", "Expires"}, {"Expires", "Tue, 20 Apr 2021 02:07:56 GMT"}]),
        trailers: fields([{"Expires", "Wed, 9 Nov 2022 07:28:00 GMT"}], :trailers)
      })

    assert_lines(message, ~s[("@status" "trailer" "expires";tr "expires")], [
      ~s["@status": 200],
      ~s["trailer": Expires],
      ~s["expires";tr: Wed, 9 Nov 2022 07:28:00 GMT],
      ~s["expires": Tue, 20 Apr 2021 02:07:56 GMT]
    ])

    assert_error(%{message | trailers: :unavailable}, ~s[("expires";tr)], :unavailable_trailers)

    {:ok, streaming} =
      Body.new(%{state: :streaming, source: self()})

    assert_error(
      %{message | trailers: :pending, body: streaming},
      ~s[("expires";tr)],
      :unavailable_trailers
    )

    assert_error(%{message | trailers: []}, ~s[("expires";tr)], :missing_field)
  end

  test "Sections 2.2.1 through 2.2.7 derived components retain exact request facts" do
    message = request(%{method: "POST", raw_target: "/path?param=value"})

    assert_lines(
      message,
      ~s[("@method" "@target-uri" "@authority" "@scheme" "@request-target" "@path" "@query")],
      [
        ~s["@method": POST],
        ~s["@target-uri": https://www.example.com/path?param=value],
        ~s["@authority": www.example.com],
        ~s["@scheme": https],
        ~s["@request-target": /path?param=value],
        ~s["@path": /path],
        ~s["@query": ?param=value]
      ]
    )

    assert_lines(%{message | scheme: "http"}, ~s[("@scheme")], [~s["@scheme": http]])

    assert_lines(
      %{message | raw_target: "/path?param=value&foo=bar&baz=bat%2Dman"},
      ~s[("@query")],
      [~s["@query": ?param=value&foo=bar&baz=bat%2Dman]]
    )

    assert_lines(%{message | raw_target: "/path?queryString"}, ~s[("@query")], [
      ~s["@query": ?queryString]
    ])

    for raw <- ["/path", "/path?"] do
      assert_lines(%{message | raw_target: raw}, ~s[("@query")], [~s["@query": ?]])
    end

    # Case mutation of the public method; RFC 9421 forbids case normalization.
    assert_lines(%{message | method: "post"}, ~s[("@method")], [~s["@method": post]])
  end

  test "Section 2.2.5 all four request-target forms and empty URI paths" do
    for {method, form, raw} <- [
          {"GET", :absolute, "https://www.example.com/path?param=value"},
          {"CONNECT", :authority, "www.example.com:80"},
          {"OPTIONS", :asterisk, "*"}
        ] do
      message =
        request(%{
          method: method,
          target_form: form,
          raw_target: raw,
          scheme: nil,
          authority: nil
        })

      assert_lines(message, ~s[("@request-target")], [~s["@request-target": #{raw}]])
    end

    absolute =
      request(%{
        method: "GET",
        target_form: :absolute,
        raw_target: "https://www.example.com",
        scheme: nil,
        authority: nil
      })

    assert_lines(absolute, ~s[("@path" "@query" "@target-uri" "@authority" "@scheme")], [
      ~s["@path": /],
      ~s["@query": ?],
      ~s["@target-uri": https://www.example.com],
      ~s["@authority": www.example.com],
      ~s["@scheme": https]
    ])

    # RFC 9110 Section 7.1/7.2: authority/asterisk target URI has an empty path.
    for {method, form, raw} <- [
          {"CONNECT", :authority, "www.example.com:80"},
          {"OPTIONS", :asterisk, "*"}
        ] do
      origin = if form == :authority, do: "www.example.com:80", else: "www.example.com"

      message =
        request(%{
          method: method,
          target_form: form,
          raw_target: raw,
          authority: origin,
          scheme: "http"
        })

      assert_lines(message, ~s[("@path" "@query" "@target-uri")], [
        ~s["@path": /],
        ~s["@query": ?],
        ~s["@target-uri": http://#{origin}]
      ])
    end
  end

  test "authority and scheme normalize while raw URI and percent encodings remain intact" do
    message =
      request(%{
        scheme: "HTTPS",
        authority: "WWW.EXAMPLE.COM:443",
        raw_target: "/path?param=value&foo=bar&baz=bat%2Dman"
      })

    assert_lines(message, ~s[("@authority" "@scheme" "@target-uri")], [
      ~s["@authority": www.example.com],
      ~s["@scheme": https],
      ~s["@target-uri": HTTPS://WWW.EXAMPLE.COM:443/path?param=value&foo=bar&baz=bat%2Dman]
    ])

    for {scheme, authority, expected} <- [
          {"http", "WWW.EXAMPLE.COM:80", "www.example.com"},
          {"https", "WWW.EXAMPLE.COM:80", "www.example.com:80"},
          {"https", "[::1]:443", "[::1]"}
        ] do
      assert_lines(%{message | scheme: scheme, authority: authority}, ~s[("@authority")], [
        ~s["@authority": #{expected}]
      ])
    end

    altered = %{message | raw_target: String.replace(message.raw_target, "%2D", "%2d")}

    refute SignatureBase.build(message, ~s[("@query")]) ==
             SignatureBase.build(altered, ~s[("@query")])

    assert_lines(%{message | raw_target: "/p%61th?param=value"}, ~s[("@path")], [
      ~s["@path": /p%61th]
    ])

    missing = %{message | scheme: nil, authority: nil}

    for component <- ["@authority", "@scheme", "@target-uri"] do
      assert_error(missing, ~s[("#{component}")], :unavailable_origin)
    end
  end

  test "Section 2.2.8 query parameters preserve empty values and canonical UTF-8 encoding" do
    message = request(%{raw_target: "/path?param=value&foo=bar&baz=batman&qux="})

    assert_lines(
      message,
      ~s[("@query-param";name="baz" "@query-param";name="qux" "@query-param";name="param")],
      [
        ~s["@query-param";name="baz": batman],
        ~s["@query-param";name="qux": ],
        ~s["@query-param";name="param": value]
      ]
    )

    unicode = %{
      message
      | raw_target:
          "/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"
    }

    assert_lines(
      unicode,
      ~s[("@query-param";name="var" "@query-param";name="bar" "@query-param";name="fa%C3%A7ade%22%3A%20")],
      [
        ~s["@query-param";name="var": this%20is%20a%20big%0Amultiline%20value],
        ~s["@query-param";name="bar": with%20plus%20whitespace],
        ~s["@query-param";name="fa%C3%A7ade%22%3A%20": something]
      ]
    )

    alternate = %{
      unicode
      | raw_target:
          String.replace(unicode.raw_target, "with+plus+whitespace", "with%20plus%20whitespace")
    }

    assert SignatureBase.build(unicode, ~s[("@query-param";name="bar")]) ==
             SignatureBase.build(alternate, ~s[("@query-param";name="bar")])

    for target <- ["/path?param=value&param=value", "/path?param=value&%70aram=value"] do
      assert_error(
        %{message | raw_target: target},
        ~s[("@query-param";name="param")],
        :ambiguous_query_parameter
      )
    end

    assert_error(message, ~s[("@query-param";name="missing")], :missing_query_parameter)
    assert_error(message, ~s[("@query-param")], :invalid_component_parameters)

    assert_error(
      unicode,
      ~s[("@query-param";name="fa%c3%a7ade%22%3a%20")],
      :noncanonical_query_name
    )

    assert_error(
      %{message | raw_target: "/path?param=%FF"},
      ~s[("@query-param";name="param")],
      :invalid_query_encoding
    )
  end

  test "Section 2.2.9 and 2.4 response context rejects wrong targets and lost requests" do
    message = published_message(hd(@vectors)["message"])
    assert_lines(message, ~s[("@status")], [~s["@status": 503]])
    assert_error(request(), ~s[("@status")], :wrong_message_kind)
    assert_error(message, ~s[("@method")], :wrong_message_kind)
    assert_error(request(), ~s[("@method";req)], :wrong_message_kind)
    assert_error(message, ~s[("@status";req)], :wrong_message_kind)
    assert_error(%{message | related_request: nil}, ~s[("@method";req)], :missing_request_context)
    # Combined req/tr/key selects only the linked request's trailer dictionary.
    related = %{
      message.related_request
      | trailers: fields([{"Example-Dict", "a=1, b=2;x=1;y=2"}], :trailers)
    }

    assert_lines(
      %{message | related_request: related},
      ~s[("example-dict";req;tr;key="b")],
      [~s["example-dict";req;tr;key="b": 2;x=1;y=2]],
      field_schemas: %{"example-dict" => dictionary_schema()}
    )
  end

  test "Sections 2 and 2.5 reject duplicate identifiers and unsupported parameter forms" do
    message = request(%{fields: fields([{"Example-Dict", "a=1"}])})
    assert_error(message, ~s[("@method" "@method")], :duplicate_component)
    response = response(%{related_request: message})

    assert_error(
      response,
      ~s[("example-dict";req;key="a" "example-dict";key="a";req)],
      :duplicate_component,
      field_schemas: %{"example-dict" => dictionary_schema()}
    )

    for input <- [~s[("@signature-params")], ~s[("@unknown")]] do
      assert_error(message, input, :unknown_component)
    end

    assert_error(message, ~s[("Host")], :invalid_component)
    assert_error(message, ~s[("date";unknown)], :invalid_component_parameters)

    for input <- [
          ~s[("@method";tr)],
          ~s[("date";name="foo")],
          ~s[("date";sf=?0)],
          ~s[("date";req=1)],
          ~s[("date";key=foo)],
          ~s[("@query-param";name=1)]
        ] do
      assert_error(message, input, :invalid_component_parameters)
    end

    assert_error(message, ~s[("missing")], :missing_field)

    for input <- [
          ~s[("@method");created="1618884473"],
          ~s[("@method");expires=1.5],
          ~s[("@method");keyid=42]
        ] do
      assert_error(message, input, :invalid_signature_parameters)
    end
  end

  test "Section 2.3 preserves component and parameter order with an exact final line" do
    message = request()
    first = ~s[("@method" "@path");keyid="test-key-rsa-pss";created=1618884473]
    second = ~s[("@path" "@method");created=1618884473;keyid="test-key-rsa-pss"]
    assert_lines(message, first, [~s["@method": POST], ~s["@path": /path]])
    refute SignatureBase.build(message, first) == SignatureBase.build(message, second)
    assert_lines(message, ~s[("@method");extension="test-key-rsa-pss"], [~s["@method": POST]])
  end

  test "malformed inputs and direct structures fail without leaking supplied bytes" do
    message = request()

    for input <- [
          nil,
          42,
          ~s["@method"],
          ~s[("@method") trailing],
          ~s[("@method"), ("@path")],
          ~s[(42)]
        ] do
      assert_error(message, input, :invalid_signature_parameters)
    end

    for invalid <- [nil, %{message | fields: %{}}, %{message | method: "POST\n"}] do
      assert_error(invalid, ~s[("@method")], :invalid_message)
    end

    {:ok, %Value{value: [parameters]}} = SF.parse(~s[("@method")], signature_schema())

    for invalid <- [
          Map.delete(parameters, :parameters),
          %{parameters | value: [hd(parameters.value) | :bad]},
          %{
            parameters
            | value: [
                %{
                  hd(parameters.value)
                  | parameters: [{"req", {:boolean, true}}, {"req", {:boolean, true}}]
                }
              ]
          }
        ] do
      assert_error(message, invalid, :invalid_signature_parameters)
    end

    assert {:error, error} =
             SignatureBase.build(
               message,
               ~s[("@method");keyid="test-key-rsa-pss";created="1618884473"]
             )

    assert inspect(error) ==
             "%RequestSeal.SignatureBase.Error{reason: :invalid_signature_parameters}"

    refute inspect(error) =~ "test-key-rsa-pss"
  end

  test "work limits can only lower ceilings and bound final output and component count" do
    message = request()
    assert {:ok, _} = SignatureBase.build(message, ~s[("@method")], max_components: 2)
    assert_error(message, ~s[("@method" "@path" "@query")], :limit, max_components: 2)
    assert_error(message, ~s[("@method")], :limit, max_bytes: 8)

    for opts <- [
          [max_bytes: 0],
          [max_bytes: 1_048_577],
          [max_components: 257],
          [unknown: true],
          [max_components: 2, max_components: 2],
          :bad,
          [field_schemas: %{"Example-Dict" => dictionary_schema()}]
        ] do
      assert_error(message, ~s[("@method")], :invalid_options, opts)
    end
  end

  test "field schemas combine ordered occurrences and reject repeated Item fields" do
    message =
      request(%{fields: fields([{"Example-Dict", "a=1"}, {"Example-Dict", "b=2;x=1;y=2"}])})

    opts = [field_schemas: %{"example-dict" => dictionary_schema()}]

    assert_lines(
      message,
      ~s[("example-dict";sf)],
      [~s["example-dict";sf: a=1, b=2;x=1;y=2]],
      opts
    )

    assert_lines(
      message,
      ~s[("example-dict";key="b")],
      [~s["example-dict";key="b": 2;x=1;y=2]],
      opts
    )

    # Item values from Section 2.1.2; joining two Items is malformed under an Item schema.
    items = %{message | fields: fields([{"Example-Dict", "1"}, {"Example-Dict", "2"}])}

    assert_error(items, ~s[("example-dict";sf)], :invalid_structured_field,
      field_schemas: %{"example-dict" => item_schema()}
    )
  end

  test "individual bounds cover component lines, final parameters, and malformed names" do
    message = request()
    assert_error(message, ~s[("@method")], :limit, max_bytes: 19)
    assert_error(message, ~s[("@method" "missing")], :limit, max_bytes: 8)
    assert {:ok, base} = SignatureBase.build(message, ~s[("@method")])

    assert {:ok, ^base} =
             SignatureBase.build(message, ~s[("@method")], max_bytes: byte_size(base) + 1)

    assert_error(message, ~s[("@method")], :limit, max_bytes: byte_size(base) - 1)
    assert_error(message, ~s[("@query-param";name="param%")], :invalid_query_encoding)
    assert_error(message, ~s[("@query-param";name="param+")], :noncanonical_query_name)
    assert_error(message, ~s[("not a field")], :invalid_component)

    assert_error(message, ~s[("@method")], :invalid_options,
      field_schemas: %{"example-dict" => :bad}
    )

    assert_error(message, ~s[("@method")], :invalid_options, field_schemas: :bad)
    assert_error(message, ~s[("@method")], :invalid_options, max_bytes: -1)
    assert_error(message, ~s[("@method")], :invalid_options, max_bytes: 1.5)
    assert_error(message, ~s[("@method")], :invalid_options, max_components: -1)
  end

  test "256 dictionary components reuse one parse of a near-limit field" do
    # Resource regression input, not an external conformance vector.
    member = String.duplicate("a", 60)
    dictionary = Enum.map_join(1..900, ", ", &~s[k#{&1}="#{member}"])
    assert byte_size(dictionary) == 61_990
    message = request(%{fields: fields([{"X-D", dictionary}])})
    components = Enum.map_join(1..256, " ", &~s["x-d";key="k#{&1}"])
    parameters = "(" <> components <> ")"
    opts = [field_schemas: %{"x-d" => dictionary_schema()}]

    {microseconds, result} = :timer.tc(fn -> SignatureBase.build(message, parameters, opts) end)
    milliseconds = microseconds / 1_000
    IO.puts("256_components_ms: #{milliseconds}")
    assert {:ok, base} = result
    expected = Enum.map_join(1..256, "\n", &~s["x-d";key="k#{&1}": "#{member}"])
    assert base == expected <> ~s[\n"@signature-params": #{parameters}]

    # OTP tracing observes real parser calls without a production hook or substitute.
    {^result, parses} =
      count_calls({SF, :parse, 2}, fn ->
        SignatureBase.build(message, parameters, opts)
      end)

    IO.puts("structured_field_parses: #{parses - 1}")
    assert parses == 2, "one signature-parameters parse and one dictionary parse"
  end

  test "structured field reuse separates sections and request context and ends with each build" do
    related =
      request(%{
        fields: fields([{"X-D", "a=1, b=2"}]),
        trailers: fields([{"X-D", "a=3, b=4"}], :trailers)
      })

    message =
      response(%{
        fields: fields([{"X-D", "a=5, b=6"}]),
        trailers: fields([{"X-D", "a=7, b=8"}], :trailers),
        related_request: related
      })

    components =
      for suffix <- ["", ";tr", ";req", ";req;tr"],
          selection <- [";sf", ~s[;key="a"], ~s[;key="b"]],
          do: ~s["x-d"#{suffix}#{selection}]

    parameters = "(" <> Enum.join(components, " ") <> ")"
    opts = [field_schemas: %{"x-d" => dictionary_schema()}]

    values = [
      "a=5, b=6",
      "5",
      "6",
      "a=7, b=8",
      "7",
      "8",
      "a=1, b=2",
      "1",
      "2",
      "a=3, b=4",
      "3",
      "4"
    ]

    lines =
      Enum.zip_with(components, values, fn component, value -> component <> ": " <> value end)

    {{{:ok, first_base}, {:ok, second_base}}, parses} =
      count_calls({SF, :parse, 2}, fn ->
        first = SignatureBase.build(message, parameters, opts)
        second = SignatureBase.build(message, parameters, opts)
        {first, second}
      end)

    assert first_base == second_base
    assert first_base == Enum.join(lines ++ [~s["@signature-params": #{parameters}]], "\n")
    assert parses == 10, "two parameters parses plus four distinct field parses per build"

    item = request(%{fields: fields([{"X-D", "1"}])})

    assert_error(item, ~s[("x-d";sf "x-d";key="a")], :invalid_field_schema,
      field_schemas: %{"x-d" => item_schema()}
    )
  end

  test "256 query components decode the query names once per message" do
    query = Enum.map_join(1..900, "&", &"k#{&1}=v#{&1}")
    message = request(%{raw_target: "/path?" <> query})
    components = Enum.map_join(1..256, " ", &~s["@query-param";name="k#{&1}"])
    parameters = "(" <> components <> ")"

    {{:ok, base}, decodes} =
      count_calls({SignatureBase, :decode_query, 1}, fn ->
        SignatureBase.build(message, parameters)
      end)

    expected = Enum.map_join(1..256, "\n", &~s["@query-param";name="k#{&1}": v#{&1}])
    assert base == expected <> ~s[\n"@signature-params": #{parameters}]
    assert decodes == 900 + 256 * 2, "each query name once, each selected name and value once"

    assert_lines(
      response(%{related_request: message}),
      ~s[("@query-param";req;name="k1" "@query-param";req;name="k2")],
      [~s["@query-param";req;name="k1": v1], ~s["@query-param";req;name="k2": v2]]
    )

    # Retain eager name validation and lazy value decoding across cached lookups.
    assert_lines(
      request(%{raw_target: "/p?a=1&b=2&unused=%FF"}),
      ~s[("@query-param";name="a" "@query-param";name="b")],
      [~s["@query-param";name="a": 1], ~s["@query-param";name="b": 2]]
    )

    assert_error(
      request(%{raw_target: "/p?a=1&%FF=2"}),
      ~s[("@query-param";name="a")],
      :invalid_query_encoding
    )

    assert_error(
      request(%{raw_target: "/p?a=1&b=2&%62=3"}),
      ~s[("@query-param";name="a" "@query-param";name="b")],
      :ambiguous_query_parameter
    )
  end

  defp count_calls(mfa, fun) do
    parent = self()

    worker =
      spawn(fn ->
        receive do
          :run ->
            send(parent, {:build_result, self(), fun.()})
            receive do: (:stop -> :ok)
        end
      end)

    session = :trace.session_create(:signature_base_parses, self(), [])

    try do
      Code.ensure_loaded!(elem(mfa, 0))
      Code.ensure_loaded!(RequestSeal.SignatureBase)
      assert :trace.function(session, mfa, true, [:local]) == 1
      assert :trace.process(session, worker, true, [:call, :arity]) == 1
      send(worker, :run)

      result =
        receive do
          {:build_result, ^worker, result} -> result
        after
          5_000 -> flunk("timed out waiting for the traced build result")
        end

      delivered = :trace.delivered(session, worker)
      assert_receive {:trace_delivered, ^worker, ^delivered}
      {result, drain_calls(worker, mfa, 0)}
    after
      :trace.session_destroy(session)
      Process.exit(worker, :kill)
    end
  end

  defp drain_calls(worker, mfa, count) do
    receive do
      {:trace, ^worker, :call, ^mfa} -> drain_calls(worker, mfa, count + 1)
    after
      0 -> count
    end
  end

  defp assert_lines(message, parameters, lines, opts \\ []) do
    assert SignatureBase.build(message, parameters, opts) ==
             {:ok, Enum.join(lines ++ [~s["@signature-params": #{parameters}]], "\n")}
  end

  defp assert_error(message, parameters, reason, opts \\ []) do
    assert {:error, %{__struct__: RequestSeal.SignatureBase.Error, reason: ^reason}} =
             SignatureBase.build(message, parameters, opts)
  end

  defp signature_schema do
    {:ok, s} =
      Schema.new(%{revision: :rfc8941, type: :list, item_types: [:string], inner_lists: true})

    s
  end

  defp dictionary_schema do
    {:ok, s} =
      Schema.new(%{
        revision: :rfc8941,
        type: :dictionary,
        item_types: Schema.types(:rfc8941),
        inner_lists: true
      })

    s
  end

  defp item_schema do
    {:ok, s} = Schema.new(%{revision: :rfc8941, type: :item, item_types: [:integer]})
    s
  end

  defp published_message(v) do
    attrs = %{fields: fields(v["fields"])}

    if v["kind"] == "request" do
      request(
        Map.merge(attrs, %{
          method: v["method"],
          raw_target: v["raw_target"],
          target_form: :origin,
          scheme: v["scheme"],
          authority: v["authority"]
        })
      )
    else
      related = if v["related_request"], do: published_message(v["related_request"]), else: nil
      response(Map.merge(attrs, %{status: v["status"], related_request: related}))
    end
  end

  defp fields(pairs, section \\ :headers) do
    Enum.map(pairs, fn pair ->
      {name, value} = if is_list(pair), do: List.to_tuple(pair), else: pair

      {:ok, f} =
        FieldOccurrence.new(%{name: name, value: value, section: section, provenance: :caller})

      f
    end)
  end

  defp request(attrs \\ %{}) do
    {:ok, body} = Body.new(%{state: :unavailable})
    {:ok, transport} = TransportFacts.new(%{})

    {:ok, m} =
      Message.new(
        Map.merge(
          %{
            kind: :request,
            method: "POST",
            raw_target: "/path?param=value",
            target_form: :origin,
            scheme: "https",
            authority: "www.example.com",
            fields: [],
            trailers: :unavailable,
            body: body,
            transport: transport
          },
          attrs
        )
      )

    m
  end

  defp response(attrs) do
    {:ok, body} = Body.new(%{state: :unavailable})
    {:ok, transport} = TransportFacts.new(%{})

    {:ok, m} =
      Message.new(
        Map.merge(
          %{
            kind: :response,
            status: 200,
            fields: [],
            trailers: :unavailable,
            body: body,
            transport: transport
          },
          attrs
        )
      )

    m
  end
end
