defmodule RequestSeal.MessageTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Body, FieldOccurrence, Message, TransportFacts}

  @capture Path.join(__DIR__, "fixtures/http")

  test "real captured HTTP bytes round-trip with ordered repeats and response linkage" do
    request_bytes = File.read!(Path.join(@capture, "request.http"))
    response_bytes = File.read!(Path.join(@capture, "response.http"))
    {request_line, fields} = captured_head(request_bytes)
    [method, target, "HTTP/1.1"] = String.split(request_line, " ")

    {:ok, request} =
      Message.new(request_attrs(%{method: method, raw_target: target, fields: fields}))

    assert Enum.count(request.fields, &(&1.name == "Accept")) == 2
    assert request.raw_target == "/httpwg/http-core/main/rfc9112.xml?capture=a%2Fb&capture=two"
    assert request_line <> "\r\n" <> field_bytes(request.fields) <> "\r\n" == request_bytes

    {status_line, response_fields} = captured_head(response_bytes)
    ["HTTP/1.1", status, _reason] = String.split(status_line, " ", parts: 3)

    {:ok, response} =
      Message.new(
        response_attrs(%{
          status: String.to_integer(status),
          fields: response_fields,
          related_request: request
        })
      )

    assert response.related_request === request
    assert response.fields !== request.fields
    assert status_line <> "\r\n" <> field_bytes(response.fields) <> "\r\n" == response_bytes
    assert response.body.bytes == ""
    assert Message.validate(response) == :ok
  end

  test "RFC 9421 request-target forms and encoded query octets stay exact" do
    # RFC 9421 Sections 2.2.5 and 2.2.7; no URI decoding or reconstruction.
    cases = [
      {"POST", :origin, "/path?param=value"},
      {"GET", :absolute, "https://www.example.com/path?param=value"},
      {"CONNECT", :authority, "www.example.com:80"},
      {"OPTIONS", :asterisk, "*"},
      {"GET", :origin, "/path?param=value&foo=bar&baz=bat%2Dman"},
      {"GET", :absolute, "https://www.example.com"},
      {"GET", :origin, "/?"},
      {"GET", :origin, "/a%2fb?q=%2F&q=+"},
      {"CONNECT", :authority, "[::1]:443"}
    ]

    for {method, form, raw} <- cases do
      {:ok, message} =
        Message.new(request_attrs(%{method: method, target_form: form, raw_target: raw}))

      assert message.raw_target === raw
      assert message.target_form == form
      assert Message.validate(message) == :ok
    end
  end

  test "raw field case, whitespace, obs-text, source section and provenance survive" do
    # RFC 9421 Section 2.1 repeated fields; raw OWS remains evidence.
    {:ok, first} =
      FieldOccurrence.new(%{
        name: "Cache-Control",
        value: " max-age=60",
        section: :headers,
        provenance: :http1
      })

    {:ok, second} =
      FieldOccurrence.new(%{
        name: "Cache-Control",
        value: "    must-revalidate",
        section: :headers,
        provenance: :http1
      })

    {:ok, trailer} =
      FieldOccurrence.new(%{
        name: "Example",
        value: <<32, 255, 9>>,
        section: :trailers,
        provenance: :http1
      })

    {:ok, message} = Message.new(request_attrs(%{fields: [first, second], trailers: [trailer]}))
    assert message.fields === [first, second]
    assert message.trailers === [trailer]
    assert trailer.value == <<32, 255, 9>>
    assert FieldOccurrence.validate(trailer) == :ok
  end

  test "body stream remains caller-owned and unread; availability and trailers are explicit" do
    {:ok, source} = File.open(Path.join(@capture, "response.http"), [:read, :binary])
    on_exit(fn -> File.close(source) end)
    {:ok, body} = Body.new(%{state: :streaming, source: source})
    {:ok, message} = Message.new(request_attrs(%{body: body, trailers: :pending}))
    assert message.body.source === source
    assert message.body.ownership == :caller
    assert message.body.bytes == nil
    assert message.trailers == :pending
    assert IO.binread(source, 8) == "HTTP/1.1"
    assert Body.validate(body) == :ok

    for state <- [:unavailable, :consumed] do
      {:ok, body} = Body.new(%{state: state})
      {:ok, message} = Message.new(request_attrs(%{body: body, trailers: :unavailable}))
      assert message.body.state == state
      assert message.body.bytes == nil
    end

    {:ok, bytes} = Body.new(%{state: :retained, bytes: <<0, 255, 1>>, max_bytes: 3})
    assert bytes.bytes == <<0, 255, 1>>

    assert {:error, %{reason: :invalid_body}} =
             Body.new(%{state: :retained, bytes: "four", max_bytes: 3})
  end

  test "declared origin and transport never become observed evidence or use forwarded fields" do
    {:ok, facts} = TransportFacts.new(%{http_version: :http1_1, tls: :tls})

    {:ok, field} =
      FieldOccurrence.new(%{
        name: "Forwarded",
        value: " proto=http;host=attacker.example",
        section: :headers
      })

    {:ok, message} =
      Message.new(
        request_attrs(%{
          scheme: "https",
          authority: "example.com:443",
          transport: facts,
          fields: [field]
        })
      )

    assert message.transport.evidence == :declared
    assert message.scheme == "https"
    assert message.authority == "example.com:443"
    assert TransportFacts.validate(facts) == :ok
    {:ok, unknown} = Message.new(request_attrs(%{fields: [field]}))
    assert unknown.scheme == nil and unknown.authority == nil

    for invalid <- [
          %{evidence: :observed},
          %{peer: "unbounded"},
          %{tls: true},
          %{http_version: :guess}
        ] do
      assert {:error, %{reason: :invalid_transport}} = TransportFacts.new(invalid)
    end
  end

  test "all constructor and validator boundaries reject malformed or ambiguous values safely" do
    for invalid <- [nil, [], %{"kind" => "request"}, %{kind: :request}, %{unexpected: true}] do
      assert {:error, _} = Message.new(invalid)
    end

    {:ok, valid} = Message.new(request_attrs())

    mutations = [
      %{method: "GET\r\n"},
      %{method: ""},
      %{method: String.duplicate("G", 257)},
      %{kind: :unknown},
      %{status: 200},
      %{related_request: valid},
      %{raw_target: nil},
      %{raw_target: "/a b"},
      %{raw_target: "/%GG"},
      %{raw_target: "/#fragment"},
      %{raw_target: ""},
      %{raw_target: "/" <> String.duplicate("a", 16_384)},
      %{target_form: :absolute},
      %{target_form: :asterisk},
      %{target_form: :authority, raw_target: "host:443"},
      %{target_form: :authority, method: "CONNECT", raw_target: "host"},
      %{target_form: :authority, method: "CONNECT", raw_target: "host:99999"},
      %{method: "CONNECT"},
      %{target_form: :absolute, raw_target: "https://user@host/"},
      %{fields: %{"host" => "example.com"}},
      %{fields: [nil]},
      %{fields: [1 | 2]},
      %{trailers: nil},
      %{trailers: :pending},
      %{body: nil},
      %{transport: nil},
      %{scheme: "https"},
      %{authority: "example.com"},
      %{scheme: "https", authority: "a/b"},
      %{scheme: "https", authority: "user@host"}
    ]

    for mutation <- mutations do
      assert {:error, _} = Message.new(Map.merge(request_attrs(), mutation)), inspect(mutation)
      assert {:error, _} = Message.validate(struct(valid, mutation)), inspect(mutation)
    end

    for status <- [99, 600, "200", nil] do
      assert {:error, _} = Message.new(response_attrs(%{status: status}))
    end

    {:ok, response} = Message.new(response_attrs())

    for mutation <- [
          %{method: "GET"},
          %{raw_target: "/"},
          %{target_form: :origin},
          %{related_request: response},
          %{related_request: struct(valid, method: "bad method")}
        ] do
      assert {:error, _} = Message.new(Map.merge(response_attrs(), mutation))
      assert {:error, _} = Message.validate(struct(response, mutation))
    end

    assert {:error, _} = Message.validate(%{})
  end

  test "malformed binary origins return errors and illegal URI delimiters reject" do
    for authority <- [<<91, 255, 93>>, "[]", "[not:ipv6]", "host:", "host:abc"] do
      attrs = request_attrs(%{scheme: "https", authority: authority})
      assert {:error, _} = Message.new(attrs)
    end

    for {form, target} <- [
          {:origin, "/a[b]"},
          {:origin, "/?a=[b]"},
          {:absolute, "https://host/a[b]"}
        ] do
      assert {:error, _} = Message.new(request_attrs(%{target_form: form, raw_target: target}))
    end
  end

  test "field guards cover constructed and modified structs, both sections and bounded lists" do
    attrs = %{name: "Example", value: " value", section: :headers}
    {:ok, field} = FieldOccurrence.new(attrs)

    for mutation <- [
          %{name: ""},
          %{name: "bad name"},
          %{name: ":method"},
          %{name: "x\r"},
          %{value: "a\n"},
          %{value: <<0>>},
          %{value: <<127>>},
          %{value: nil},
          %{section: :other},
          %{provenance: "unknown"},
          %{value: String.duplicate("x", 65_537)}
        ] do
      assert {:error, _} = FieldOccurrence.new(Map.merge(attrs, mutation))
      assert {:error, _} = FieldOccurrence.validate(struct(field, mutation))

      for {key, section} <- [fields: :headers, trailers: :trailers] do
        {:ok, section_field} = FieldOccurrence.new(%{attrs | section: section})
        invalid = struct(section_field, mutation)
        assert {:error, _} = FieldOccurrence.new(Map.merge(%{attrs | section: section}, mutation))
        assert {:error, _} = FieldOccurrence.validate(invalid)
        assert {:error, _} = Message.new(Map.put(request_attrs(), key, [invalid]))
      end
    end

    {:ok, trailer} = FieldOccurrence.new(%{attrs | section: :trailers})
    assert {:error, _} = Message.new(request_attrs(%{fields: [trailer]}))
    assert {:error, _} = Message.new(request_attrs(%{trailers: [field]}))
    assert {:error, _} = Message.new(request_attrs(%{fields: List.duplicate(field, 1025)}))
    {:ok, large} = FieldOccurrence.new(%{attrs | value: String.duplicate("x", 65_536)})
    assert {:error, _} = Message.new(request_attrs(%{fields: List.duplicate(large, 17)}))
  end

  test "body and transport structs cannot bypass their constructors" do
    {:ok, retained} = Body.new(%{state: :retained, bytes: ""})
    {:ok, facts} = TransportFacts.new(%{})

    for mutation <- [
          %{state: :unknown},
          %{ownership: :library},
          %{source: self()},
          %{bytes: nil},
          %{max_bytes: -1}
        ] do
      assert {:error, _} = Body.new(Map.merge(%{state: :retained, bytes: ""}, mutation))
      bad = struct(retained, mutation)
      assert {:error, _} = Body.validate(bad)
      assert {:error, _} = Message.new(request_attrs(%{body: bad}))
    end

    for mutation <- [%{evidence: :observed}, %{http_version: "HTTP/1.1"}, %{tls: :verified}] do
      bad = struct(facts, mutation)
      assert {:error, _} = TransportFacts.validate(bad)
      assert {:error, _} = Message.new(request_attrs(%{transport: bad}))
    end
  end

  test "default inspection and errors exclude message bytes and stream handles" do
    secret = "sensitive-canary"
    {:ok, field} = FieldOccurrence.new(%{name: "Authorization", value: secret, section: :headers})
    {:ok, body} = Body.new(%{state: :retained, bytes: secret})

    {:ok, message} =
      Message.new(
        request_attrs(%{
          raw_target: "/" <> secret,
          authority: secret,
          scheme: "https",
          fields: [field],
          body: body
        })
      )

    for value <- [field, body, message, Message.new(request_attrs(%{method: secret <> "\n"}))] do
      refute inspect(value) =~ secret
    end
  end

  defp request_attrs(overrides \\ %{}) do
    {:ok, body} = Body.new(%{state: :retained, bytes: ""})
    {:ok, transport} = TransportFacts.new(%{http_version: :http1_1})

    Map.merge(
      %{
        kind: :request,
        method: "GET",
        target_form: :origin,
        raw_target: "/",
        fields: [],
        trailers: [],
        body: body,
        transport: transport
      },
      overrides
    )
  end

  defp response_attrs(overrides \\ %{}) do
    request_attrs()
    |> Map.drop([:method, :target_form, :raw_target])
    |> Map.merge(%{kind: :response, status: 200})
    |> Map.merge(overrides)
  end

  # Reads a saved real capture. No adapter or HTTP peer is replaced by a test double.
  defp captured_head(bytes) do
    [head, ""] = :binary.split(bytes, "\r\n\r\n")
    [line | fields] = :binary.split(head, "\r\n", [:global])

    fields =
      Enum.map(fields, fn bytes ->
        [name, value] = :binary.split(bytes, ":")

        {:ok, occurrence} =
          FieldOccurrence.new(%{name: name, value: value, section: :headers, provenance: :http1})

        occurrence
      end)

    {line, fields}
  end

  defp field_bytes(fields), do: Enum.map_join(fields, "", &(&1.name <> ":" <> &1.value <> "\r\n"))
end
