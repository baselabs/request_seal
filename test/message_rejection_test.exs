defmodule RequestSeal.MessageRejectionTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Body, FieldOccurrence, Message, TransportFacts}

  test "unclosed IP literal returns a bounded error through every authority path" do
    for authority <- ["[", "[abc", "[::11", "[:443"] do
      for mutation <- [
            %{scheme: "https", authority: authority},
            %{method: "CONNECT", target_form: :authority, raw_target: authority},
            %{target_form: :absolute, raw_target: "https://" <> authority <> "/"}
          ] do
        attrs = Map.merge(request_attrs(), mutation)
        assert {:error, %{reason: :invalid_message}} = Message.new(attrs)
        assert {:error, %{reason: :invalid_message}} = Message.validate(struct(Message, attrs))
      end
    end
  end

  test "invalid occurrences report their field layer identically in headers and trailers" do
    for {key, section} <- [fields: :headers, trailers: :trailers] do
      {:ok, field} = FieldOccurrence.new(%{name: "Example", value: " valid", section: section})
      attrs = Map.put(request_attrs(), key, [%{field | value: "invalid\r\n"}])
      assert {:error, %{reason: :invalid_field}} = Message.new(attrs)
      assert {:error, %{reason: :invalid_field}} = Message.validate(struct(Message, attrs))
    end
  end

  test "declared origins cannot contradict authority-bearing request targets" do
    for {method, form, raw, scheme, authority} <- [
          {"GET", :absolute, "https://example.com/a%2Fb?", "https", "example.com"},
          {"CONNECT", :authority, "example.com:443", "https", "example.com:443"}
        ] do
      attrs =
        Map.merge(request_attrs(), %{
          method: method,
          target_form: form,
          raw_target: raw,
          scheme: scheme,
          authority: authority
        })

      {:ok, request} = Message.new(attrs)
      assert request.raw_target == raw
      assert request.authority == authority

      for change <-
            [%{authority: "different.example"}] ++
              if(form == :absolute, do: [%{scheme: "http"}], else: []) do
        assert {:error, %{reason: :invalid_message}} = Message.new(Map.merge(attrs, change))
        assert {:error, %{reason: :invalid_message}} = Message.validate(struct(request, change))
      end
    end
  end

  test "a completed capture can have known trailers while its caller-owned stream is unread" do
    path = Path.join(__DIR__, "fixtures/http/response.http")
    {:ok, source} = File.open(path, [:read, :binary])
    on_exit(fn -> File.close(source) end)
    {:ok, body} = Body.new(%{state: :streaming, source: source})
    {:ok, request} = Message.new(Map.merge(request_attrs(), %{body: body, trailers: []}))
    assert request.trailers == []
    assert request.body.state == :streaming
    assert IO.binread(source, 8) == "HTTP/1.1"
    assert Message.validate(request) == :ok
  end

  defp request_attrs do
    {:ok, body} = Body.new(%{state: :unavailable})
    {:ok, transport} = TransportFacts.new(%{})

    %{
      kind: :request,
      method: "GET",
      raw_target: "/",
      target_form: :origin,
      fields: [],
      trailers: :unavailable,
      body: body,
      transport: transport
    }
  end
end
