Code.require_file("support/plug_transport_helper.exs", __DIR__)
Code.require_file("support/plug_phoenix_helper.exs", __DIR__)

defmodule RequestSeal.PlugPhoenixTest do
  use ExUnit.Case, async: false
  alias RequestSeal.PlugTransport, as: T

  setup do
    start_supervised!({Finch, name: __MODULE__.Pool})

    start_supervised!(
      {Finch,
       name: __MODULE__.TLSPool,
       pools: %{default: [conn_opts: [transport_opts: [verify: :verify_none]]]}}
    )

    %{handle: T.handle()}
  end

  test "dual-stack socket peers match IPv4 and mapped IPv6 trusted ranges" do
    for network <- [{{127, 0, 0, 0}, 8}, {{0, 0, 0, 0, 0, 65535, 32512, 0}, 104}] do
      rule = {:forwarded, %{trusted_peers: [network], field: :forwarded}}

      {origin, _} =
        T.start([owner: self(), origin: rule],
          ip: {0, 0, 0, 0, 0, 0, 0, 0},
          thousand_island_options: [transport_options: [ipv6_v6only: false]]
        )

      assert T.raw(
               origin,
               "GET /foo HTTP/1.1\r\nHost: example.com\r\nForwarded: proto=https;host=example.com\r\nConnection: close\r\n\r\n"
             ) =~ "HTTP/1.1 200"

      assert_receive {:observed, _, {:ok, capture}, :error}, 5_000
      assert capture.ingress.remote_ip == {0, 0, 0, 0, 0, 65535, 32512, 1}
      assert capture.origin.source == :forwarded
    end

    rule =
      {:forwarded, %{trusted_peers: [{{0, 0, 0, 0, 0, 65535, 32512, 0}, 104}], field: :forwarded}}

    {origin, _} = T.start(owner: self(), origin: rule)

    assert T.raw(
             origin,
             "GET /foo HTTP/1.1\r\nHost: example.com\r\nForwarded: proto=https;host=example.com\r\nConnection: close\r\n\r\n"
           ) =~ "HTTP/1.1 200"

    assert_receive {:observed, _, {:ok, capture}, :error}, 5_000
    assert capture.ingress.remote_ip == {127, 0, 0, 1}
    assert capture.origin.source == :forwarded
  end

  test "Phoenix captures before parsers, verifies in router and signs controller JSON", %{
    handle: h
  } do
    port = start_phoenix(h)

    assert {:ok, req} =
             RequestSeal.Req.attach(
               Req.new(
                 url: "http://127.0.0.1:#{port}/foo",
                 method: :post,
                 json: %{"hello" => "world"},
                 headers: [{"accept", "*/*"}],
                 finch: [name: __MODULE__.Pool],
                 retry: false
               ),
               sign: T.spec(),
               signer: h,
               verify: %{
                 policy: T.policy(T.response_components()),
                 label: "res",
                 max_stream_bytes: 4096
               }
             )

    assert {:ok, response} = Req.request(req)
    assert response.body == %{"hello" => "world"}
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive {:phoenix, conn, {:ok, result}}, 5_000
    assert conn.body_params == %{"hello" => "world"}
    assert conn.assigns.verified == result
  end

  @tag :session_cookie_coverage
  test "Phoenix cookie sessions fail closed when response coverage includes set-cookie", %{
    handle: h
  } do
    port = start_phoenix(h)
    req = Finch.build(:post, "http://127.0.0.1:#{port}/session", [{"accept", "*/*"}])
    assert {:ok, req} = RequestSeal.Finch.sign(req, T.spec(), h)
    assert {:ok, response} = Finch.request(req, __MODULE__.Pool)
    assert response.status == 503
    assert response.body == ""
    refute List.keymember?(response.headers, "signature", 0)
    refute List.keymember?(response.headers, "signature-input", 0)
    assert_receive {:phoenix, conn, {:ok, _}}, 5_000
    assert Plug.Conn.get_session(conn, "visited") == true
    assert %{value: cookie} = conn.resp_cookies["_request_seal_session"]
    assert is_binary(cookie) and byte_size(cookie) > 0
    assert_receive {:phoenix_session_sent, sent}, 5_000

    assert %RequestSeal.Adapter.Error{reason: :unsupported_delivery, source: nil} =
             sent.private.request_seal.error
  end

  for content_type <- ["text/plain", "application/octet-stream", "application/xml", nil] do
    fields = [{"accept", "*/*"}]
    fields = if content_type, do: [{"content-type", content_type} | fields], else: fields
    body_params = if content_type, do: %Plug.Conn.Unfetched{aspect: :body_params}, else: %{}
    @tag :pass_through_parsing
    test "Phoenix pass-through #{inspect(content_type)} verifies and leaves raw body readable", %{
      handle: h
    } do
      port = start_phoenix(h)
      body = "<message>raw signed content</message>"
      fields = unquote(Macro.escape(fields))
      req = Finch.build(:post, "http://127.0.0.1:#{port}/raw", fields, body)
      assert {:ok, req} = RequestSeal.Finch.sign(req, T.spec(), h)
      assert {:ok, response} = Finch.request(req, __MODULE__.Pool)
      assert response.status == 200
      assert response.body == body

      assert {:ok, _} =
               RequestSeal.Finch.verify(response, req, T.policy(T.response_components()),
                 label: "res"
               )

      assert_receive {:phoenix, conn, {:ok, result}}, 5_000
      assert conn.assigns.verified == result
      assert conn.body_params == unquote(Macro.escape(body_params))
      assert {:ok, capture} = RequestSeal.Plug.capture(conn)
      assert capture.message.body.bytes == body
    end
  end

  @tag :proxy_range_matching
  test "native IPv4 and mapped peers agree for IPv6 prefixes containing mapped addresses" do
    native = {127, 0, 0, 1}
    mapped = {0, 0, 0, 0, 0, 65535, 32512, 1}

    for network <- [
          {{0, 0, 0, 0, 0, 0, 0, 0}, 0},
          {{0, 0, 0, 0, 0, 0, 0, 0}, 80},
          {{0, 0, 0, 0, 0, 65534, 0, 0}, 95},
          {{0, 0, 0, 0, 0, 65535, 0, 0}, 96},
          {{0, 0, 0, 0, 0, 65535, 32512, 0}, 104},
          {{0, 0, 0, 0, 0, 65535, 32512, 1}, 128}
        ] do
      assert RequestSeal.Plug.Origin.contains?(network, mapped)
      assert RequestSeal.Plug.Origin.contains?(network, native), inspect(network)
    end
  end

  @tag :proxy_range_matching
  test "cross-family matching excludes unrelated ranges and IPv6 transition forms" do
    native = {127, 0, 0, 1}
    mapped = {0, 0, 0, 0, 0, 65535, 32512, 1}

    for network <- [
          {{0, 0, 0, 0, 0, 0, 0, 0}, 96},
          {{0, 0, 0, 0, 0, 65535, 32768, 0}, 97},
          {{0, 0, 0, 0, 0, 65535, 32512, 2}, 128},
          {{0x2002, 32512, 1, 0, 0, 0, 0, 0}, 48},
          {{0x64, 0xFF9B, 0, 0, 0, 0, 0, 0}, 96}
        ] do
      refute RequestSeal.Plug.Origin.contains?(network, native), inspect(network)
      refute RequestSeal.Plug.Origin.contains?(network, mapped), inspect(network)
    end

    for peer <- [
          {0x2002, 32512, 1, 0, 0, 0, 0, 0},
          {0x64, 0xFF9B, 0, 0, 0, 0, 32512, 1},
          {0, 0, 0, 0, 0, 0, 32512, 1}
        ],
        network <- [{{0, 0, 0, 0}, 0}, {{127, 0, 0, 0}, 8}] do
      refute RequestSeal.Plug.Origin.contains?(network, peer)
    end
  end

  @tag :proxy_range_matching
  test "native and dual-stack Bandit listeners accept mapped-range IPv6 trust networks" do
    for network <- [{{0, 0, 0, 0, 0, 0, 0, 0}, 0}, {{0, 0, 0, 0, 0, 65535, 0, 0}, 96}],
        dual_stack <- [false, true] do
      server_opts =
        if dual_stack,
          do: [
            ip: {0, 0, 0, 0, 0, 0, 0, 0},
            thousand_island_options: [transport_options: [ipv6_v6only: false]]
          ],
          else: []

      rule = {:forwarded, %{trusted_peers: [network], field: :forwarded}}
      {origin, _} = T.start([owner: self(), origin: rule], server_opts)

      assert T.raw(
               origin,
               "GET /foo HTTP/1.1\r\nHost: example.com\r\nForwarded: proto=https;host=example.com\r\nConnection: close\r\n\r\n"
             ) =~ "HTTP/1.1 200"

      assert_receive {:observed, _, {:ok, capture}, :error}, 5_000
      expected = if dual_stack, do: {0, 0, 0, 0, 0, 65535, 32512, 1}, else: {127, 0, 0, 1}
      assert capture.ingress.remote_ip == expected
      assert capture.origin.source == :forwarded
    end
  end

  test "actual TLS reverse proxy reconstructs trusted external origin and retains ingress", %{
    handle: h
  } do
    trusted = {:forwarded, %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: :forwarded}}
    {backend, _} = T.start(owner: self(), origin: trusted, policy: T.policy())
    tls = T.tls()

    pid =
      start_supervised!(
        Supervisor.child_spec(
          {Bandit,
           plug: {RequestSeal.PlugForwarder, [backend: backend, pool: __MODULE__.Pool]},
           scheme: :https,
           ip: {127, 0, 0, 1},
           port: 0,
           startup_log: false,
           thousand_island_options: [transport_options: tls.server_config]},
          id: make_ref()
        )
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(pid)

    assert {:ok, req} =
             RequestSeal.Req.attach(
               Req.new(
                 url: "https://127.0.0.1:#{port}/foo%2Fbar?param=Value",
                 headers: [{"accept", "*/*"}],
                 finch: [name: __MODULE__.TLSPool],
                 retry: false
               ),
               sign: T.spec(),
               signer: h,
               verify: :none
             )

    assert {:ok, _} = Req.request(req)
    assert_receive {:observed, _, {:ok, captured}, {:ok, _}}, 5_000

    assert captured.origin == %{
             scheme: "https",
             authority: "127.0.0.1:#{port}",
             source: :forwarded
           }

    assert captured.ingress.scheme == :http
    assert captured.message.transport.tls == :plain
    assert captured.message.raw_target == "/foo%2Fbar?param=Value"
  end

  test "untrusted peer cannot forge forwarded origin; connection origin ignores it", %{handle: h} do
    for rule <- [
          {:forwarded, %{trusted_peers: [{{10, 0, 0, 0}, 8}], field: :forwarded}},
          :connection
        ] do
      {origin, _} = T.start(owner: self(), origin: rule, policy: T.policy())

      # The signature is locally constructed for a declared external origin, then sent to the actual backend.
      req =
        Finch.build(:get, "https://example.com/foo", [
          {"accept", "*/*"},
          {"forwarded", "for=192.0.2.43;proto=https;host=example.com"}
        ])

      assert {:ok, signed} = RequestSeal.Finch.sign(req, T.spec(), h)
      uri = URI.parse(origin)
      transport = %{signed | scheme: :http, host: "127.0.0.1", port: uri.port}
      assert {:ok, _} = Finch.request(transport, __MODULE__.Pool)
      assert_receive {:observed, conn, captured, :error}, 5_000

      if rule == :connection do
        assert {:ok, c} = captured
        assert c.origin.source == :connection

        assert {:error,
                %RequestSeal.Adapter.Error{source: %RequestSeal.Error{reason: :invalid_signature}}} =
                 conn.private[:request_seal].verification
      else
        assert :error = captured
        assert conn.private[:request_seal].error.reason == :untrusted_proxy
      end
    end
  end

  test "forwarded grammar rejects ambiguous or malformed last elements and x-forwarded selects paired last values" do
    for field <- [:forwarded, :x_forwarded] do
      rule = {:forwarded, %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: field}}
      {origin, _} = T.start(owner: self(), origin: rule)

      headers =
        if field == :forwarded,
          do:
            "Forwarded: for=192.0.2.43;proto=http;host=ignored.example, for=127.0.0.1;proto=https;host=example.com\r\n",
          else:
            "X-Forwarded-Proto: http, https\r\nX-Forwarded-Host: ignored.example, example.com\r\n"

      T.raw(
        origin,
        "GET /foo HTTP/1.1\r\nHost: example.com\r\n" <> headers <> "Connection: close\r\n\r\n"
      )

      assert_receive {:observed, _, {:ok, c}, _}, 5_000
      assert c.origin.scheme == "https"
      assert c.origin.authority == "example.com"
    end

    Code.ensure_loaded!(Bandit.Adapter)
    assert 1 == :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, true, [:local])
    on_exit(fn -> :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, false, [:local]) end)
    rule = {:forwarded, %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: :forwarded}}
    {origin, _} = T.start(owner: self(), origin: rule, trace_body: true)

    for header <- [
          "proto=https;host=example.com;host=other.example",
          "proto=https",
          "proto=https;host=\"unterminated",
          "proto=https;host=example.com,",
          "proto=https;host=example.com;for=",
          "proto=https;host=example.com/path",
          ~s[proto=https;host=example.com;for=""],
          "proto=https;host=example.com;for=invalid:value",
          ~s[proto=https;host=example.com;for="invalid"quote"]
        ] do
      assert T.raw(
               origin,
               "GET /foo HTTP/1.1\r\nHost: example.com\r\nForwarded: " <>
                 header <> "\r\nConnection: close\r\n\r\n"
             ) =~ "400"

      assert_receive {:observed, conn, :error, :error}, 5_000
      assert conn.private[:request_seal].error.reason == :invalid_request
      refute_received {:trace, _, :call, {Bandit.Adapter, :read_req_body, _}}
    end

    T.raw(
      origin,
      "GET /foo HTTP/1.1\r\nHost: example.com\r\nForwarded: proto=https;host=example.com\r\nConnection: close\r\n\r\n"
    )

    assert_receive {:trace, _, :call, {Bandit.Adapter, :read_req_body, _}}, 5_000
  end

  test "forwarded origin requires paired nonempty values and valid configured ranges" do
    rule = {:forwarded, %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: :x_forwarded}}
    {origin, _} = T.start(owner: self(), origin: rule)

    for fields <- [
          "X-Forwarded-Proto: http, https\r\nX-Forwarded-Host: example.com\r\n",
          "X-Forwarded-Proto: https\r\n",
          "X-Forwarded-Proto: https\r\nX-Forwarded-Host: \r\n"
        ] do
      assert T.raw(
               origin,
               "GET /foo HTTP/1.1\r\nHost: example.com\r\n" <>
                 fields <> "Connection: close\r\n\r\n"
             ) =~ "400"

      assert_receive {:observed, conn, :error, :error}, 5_000
      assert conn.private[:request_seal].error.reason == :invalid_request
    end

    for bad <- [
          %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: :implicit},
          %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: :forwarded, extra: true},
          %{trusted_peers: [{{127, 0, 0, 1}, -1}], field: :forwarded}
        ] do
      assert_raise RequestSeal.Adapter.Error, fn ->
        RequestSeal.Plug.Capture.init(
          origin: {:forwarded, bad},
          max_body_bytes: 4096,
          read_timeout: 1000
        )
      end
    end
  end

  defp start_phoenix(h) do
    original = Application.get_env(:request_seal, RequestSeal.PlugPhoenixEndpoint)
    original_options = Application.get_env(:request_seal, :plug_phoenix)

    on_exit(fn ->
      if original == nil,
        do: Application.delete_env(:request_seal, RequestSeal.PlugPhoenixEndpoint),
        else: Application.put_env(:request_seal, RequestSeal.PlugPhoenixEndpoint, original)

      if original_options == nil,
        do: Application.delete_env(:request_seal, :plug_phoenix),
        else: Application.put_env(:request_seal, :plug_phoenix, original_options)
    end)

    Application.put_env(:request_seal, RequestSeal.PlugPhoenixEndpoint,
      server: true,
      adapter: Bandit.PhoenixAdapter,
      http: [ip: {127, 0, 0, 1}, port: 0, http_options: [compress: false]],
      secret_key_base: String.duplicate("a", 64),
      debug_errors: false,
      render_errors: [formats: [json: RequestSeal.PlugPhoenixController]],
      pubsub_server: __MODULE__.PubSub
    )

    Application.put_env(:request_seal, :plug_phoenix,
      handle: h,
      policy: T.policy(),
      owner: self()
    )

    start_supervised!({Phoenix.PubSub, name: __MODULE__.PubSub})
    start_supervised!(RequestSeal.PlugPhoenixEndpoint)
    {:ok, {_, port}} = Bandit.PhoenixAdapter.server_info(RequestSeal.PlugPhoenixEndpoint, :http)

    port
  end
end
