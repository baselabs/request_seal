Code.require_file("support/plug_transport_helper.exs", __DIR__)
Code.require_file("support/plug_phoenix_helper.exs", __DIR__)

defmodule RequestSeal.PlugTargetFidelityTest do
  use ExUnit.Case, async: false
  alias RequestSeal.PlugTransport, as: T
  alias RequestSeal.Adapter.Error

  @sensitive ~w(@request-target @target-uri @query)

  test "exact target components reject before resolution on every Bandit transport" do
    tls = T.tls()

    for transport <- [:http1, :https1, :http1_0, :h2c, :https2] do
      server =
        if transport in [:https1, :https2],
          do: [scheme: :https, thousand_island_options: [transport_options: tls.server_config]],
          else: []

      for component <- @sensitive, required? <- [true, false] do
        covered = ~s[("#{component}")]

        policy =
          T.policy(if(required?, do: covered, else: "()"), content: :not_required, owner: self())

        {origin, _} = T.start([owner: self(), policy: policy, on_reject: {:halt, 401}], server)

        for signed_target <- ["/foo", "/foo?"], wire_target <- ["/foo?", "/foo", "/foo?x=1"] do
          headers = signed_headers(origin, signed_target, covered)
          status = send_exact(origin, transport, wire_target, headers)

          IO.puts(
            "TARGET verification transport=#{transport} signed=#{signed_target} sent=#{wire_target} component=#{component} required=#{required?} status=#{status}"
          )

          assert status == 401
          assert_receive {:observed, conn, {:ok, capture}, :error}

          assert capture.message.raw_target ==
                   if(wire_target == "/foo?x=1", do: wire_target, else: "/foo")

          assert {:error,
                  %Error{
                    reason: :unsupported_component,
                    adapter: :plug,
                    stage: :verify,
                    source: nil
                  }} = conn.private.request_seal.verification

          refute_received {:resolved, _}
        end
      end
    end
  end

  test "required target evidence rejects even when the selected signature omits it" do
    for component <- @sensitive do
      {origin, _} =
        T.start(
          owner: self(),
          policy: T.policy(~s[("#{component}")], content: :not_required, owner: self())
        )

      assert send_exact(origin, :http1, "/foo?", signed_headers(origin, "/foo", ~s[("@path")])) ==
               200

      assert_receive {:observed, conn, {:ok, _}, :error}

      assert {:error, %Error{reason: :unsupported_component}} =
               conn.private.request_seal.verification

      refute_received {:resolved, _}
    end
  end

  test "path method authority fields and actual content stay usable on every Bandit transport" do
    tls = T.tls()
    components = ~s[("@path" "@method" "@authority" "accept" "content-digest")]

    for transport <- [:http1, :https1, :http1_0, :h2c, :https2] do
      server =
        if transport in [:https1, :https2],
          do: [scheme: :https, thousand_island_options: [transport_options: tls.server_config]],
          else: []

      {origin, _} = T.start([owner: self(), policy: T.policy(components)], server)
      headers = signed_headers(origin, "/foo", components, "POST", T.body())

      for target <- ["/foo", "/foo?"] do
        assert send_exact(origin, transport, target, headers, "POST", T.body()) == 200
        assert_receive {:observed, _, {:ok, capture}, {:ok, result}}
        assert capture.message.body.bytes == T.body()
        assert result.signature.crypto == :valid
      end

      assert send_exact(
               origin,
               transport,
               "/foo?",
               headers,
               "POST",
               String.replace(T.body(), "world", "earth")
             ) == 200

      assert_receive {:observed, conn, {:ok, _}, :error}

      assert conn.private.request_seal.verification
             |> elem(1)
             |> Map.fetch!(:source)
             |> Map.fetch!(:reason) == :digest_mismatch
    end
  end

  test "live ingress proves target distinction is lost before capture on every Bandit transport" do
    tls = T.tls()

    for transport <- [:http1, :https1, :http1_0, :h2c, :https2] do
      server =
        if transport in [:https1, :https2],
          do: [scheme: :https, thousand_island_options: [transport_options: tls.server_config]],
          else: []

      {origin, _} = T.start([owner: self(), target_evidence: true], server)

      for target <-
            ["/foo", "/foo?", "/foo?x=1"] ++
              if(transport in [:http1, :https1, :http1_0], do: [origin <> "/foo?"], else: []) do
        assert send_exact(origin, transport, target, []) == 200
        assert_receive {:target_ingress, ingress}
        assert_receive {:observed, conn, {:ok, capture}, _}
        {Bandit.Adapter, adapter} = ingress.adapter
        assert ingress.request_path == conn.request_path
        assert ingress.query_string == conn.query_string
        assert Map.get(adapter.transport, :buffer) in [nil, ""]
        assert Map.get(adapter.transport, :pending_headers) == nil
        refute Enum.any?(ingress.req_headers, fn {name, _} -> name == ":path" end)
        assert conn.request_path == "/foo"
        assert conn.query_string == if(target == "/foo?x=1", do: "x=1", else: "")

        IO.puts(
          "TARGET transport=#{transport} sent=#{target} path=#{conn.request_path} query=#{inspect(conn.query_string)} captured=#{capture.message.raw_target} adapter_keys=#{inspect(Map.keys(adapter))} transport_keys=#{inspect(Map.keys(adapter.transport))} buffer=#{inspect(Map.get(adapter.transport, :buffer))} pending_headers=#{inspect(Map.get(adapter.transport, :pending_headers))}"
        )
      end
    end
  end

  test "Phoenix on Bandit rejects exact target coverage and preserves path coverage" do
    original = Application.get_env(:request_seal, RequestSeal.PlugPhoenixEndpoint)
    original_options = Application.get_env(:request_seal, :plug_phoenix)

    on_exit(fn ->
      restore(RequestSeal.PlugPhoenixEndpoint, original)
      restore(:plug_phoenix, original_options)
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
      handle: T.handle(),
      policy: T.policy(),
      owner: self()
    )

    start_supervised!({Phoenix.PubSub, name: __MODULE__.PubSub})
    start_supervised!(RequestSeal.PlugPhoenixEndpoint)
    {:ok, {_, port}} = Bandit.PhoenixAdapter.server_info(RequestSeal.PlugPhoenixEndpoint, :http)
    origin = "http://127.0.0.1:#{port}"

    for transport <- [:http1, :h2c], component <- @sensitive ++ ["@path"] do
      covered = ~s[("#{component}")]

      Application.put_env(:request_seal, :plug_phoenix,
        handle: T.handle(),
        policy: T.policy(covered, content: :not_required, owner: self()),
        owner: self()
      )

      for target <- ["/foo", "/foo?", "/foo?x=1"] do
        status = if component == "@path", do: 200, else: 401

        assert send_exact(
                 origin,
                 transport,
                 target,
                 signed_headers(origin, "/foo", covered, "POST"),
                 "POST"
               ) == status

        assert_receive {:phoenix, conn, result}
        assert conn.request_path == "/foo"
        assert conn.query_string == if(target == "/foo?x=1", do: "x=1", else: "")

        if component == "@path" do
          assert {:ok, _} = result
          assert Map.has_key?(conn.assigns, :verified)
          assert_receive {:resolved, _}
        else
          assert result == :error

          assert {:error, %Error{reason: :unsupported_component}} =
                   conn.private.request_seal.verification

          refute Map.has_key?(conn.assigns, :verified)
          refute_received {:resolved, _}
        end

        IO.puts(
          "TARGET phoenix transport=#{transport} sent=#{target} component=#{component} status=#{status}"
        )
      end
    end
  end

  test "selected label alone determines optional target coverage and malformed inputs stay bounded" do
    components = ~s[("@path")]
    {origin, _} = T.start(owner: self(), policy: T.policy(components, content: :not_required))
    path = signed_headers(origin, "/foo", components)
    target = signed_headers(origin, "/foo", ~s[("@request-target")])

    other =
      for {name, value} <- target,
          name in ["signature", "signature-input"],
          do: {name, String.replace_prefix(value, "sig=", "other=")}

    assert send_exact(origin, :http1, "/foo?", path ++ other) == 200
    assert_receive {:observed, _, {:ok, _}, {:ok, _}}

    for headers <- [
          [],
          [{"signature-input", "sig=("}],
          path ++ [{"signature-input", "sig=(\"@request-target\")"}]
        ] do
      assert send_exact(origin, :http1, "/foo?", headers) == 200
      assert_receive {:observed, conn, {:ok, _}, :error}

      assert {:error, %Error{reason: :request_rejected, source: %RequestSeal.Error{}}} =
               conn.private.request_seal.verification
    end
  end

  test "target evidence rejection precedes actual replay claims and every caller callback" do
    owner = self()

    store =
      start_supervised!({RequestSeal.Replay.ETS, max_entries: 20})
      |> RequestSeal.Replay.ETS.store()

    policy =
      T.policy("()",
        content: :not_required,
        owner: owner,
        freshness: %{
          clock: fn ->
            send(owner, :clock_called)
            1_618_884_473
          end,
          max_age: 60,
          skew: 0,
          require_expires: true
        },
        replay: %{
          identifier: :nonce,
          namespace: "target-fidelity",
          store: store,
          timeout: 1000,
          commitment: fn facts ->
            send(owner, :commitment_called)
            {:ok, facts.identifier}
          end
        }
      )

    {origin, _} = T.start(owner: self(), policy: policy)

    assert send_exact(
             origin,
             :http1,
             "/foo?",
             signed_headers(origin, "/foo", ~s[("@request-target")])
           ) == 200

    assert_receive {:observed, conn, {:ok, _}, :error}

    assert {:error, %Error{reason: :unsupported_component}} =
             conn.private.request_seal.verification

    refute_received {:resolved, _}
    refute_received :clock_called
    refute_received :commitment_called
  end

  test "related target response signing refuses reconstructed request evidence" do
    for component <- @sensitive do
      spec = %{T.spec(~s[("@status" "#{component}";req)]) | digest: nil}
      {origin, _} = T.start(owner: self(), sign: spec, signer: T.handle())

      response =
        T.raw(
          origin,
          "GET /foo? HTTP/1.1\r\nHost: #{URI.parse(origin).authority}\r\nConnection: close\r\n\r\n"
        )

      assert response =~ "HTTP/1.1 503"
      [headers, body] = :binary.split(response, "\r\n\r\n")
      assert body == ""
      refute headers =~ "signature"
      assert_receive {:sent, conn}
      assert conn.private.request_seal.error.reason == :unsupported_component

      refute Enum.any?(conn.resp_headers, fn {name, _} ->
               name in ["signature", "signature-input"]
             end)
    end
  end

  test "trusted TLS reverse proxy cannot restore target evidence but preserves usable path coverage" do
    start_supervised!({Finch, name: __MODULE__.ProxyPool})
    tls = T.tls()
    trusted = {:forwarded, %{trusted_peers: [{{127, 0, 0, 1}, 32}], field: :forwarded}}

    for component <- @sensitive ++ ["@path"] do
      covered = ~s[("#{component}")]

      {backend, _} =
        T.start(
          owner: self(),
          origin: trusted,
          policy: T.policy(covered, content: :not_required),
          on_reject: {:halt, 401}
        )

      pid =
        start_supervised!(
          Supervisor.child_spec(
            {Bandit,
             plug: {RequestSeal.PlugForwarder, [backend: backend, pool: __MODULE__.ProxyPool]},
             scheme: :https,
             ip: {127, 0, 0, 1},
             port: 0,
             startup_log: false,
             thousand_island_options: [transport_options: tls.server_config]},
            id: make_ref()
          )
        )

      {:ok, {_, port}} = ThousandIsland.listener_info(pid)
      origin = "https://127.0.0.1:#{port}"

      for target <- ["/foo", "/foo?", "/foo?x=1"] do
        status = if component == "@path", do: 200, else: 401

        assert send_exact(origin, :https1, target, signed_headers(origin, "/foo", covered)) ==
                 status

        assert_receive {:observed, conn, {:ok, capture}, verdict}
        assert capture.message.raw_target == if(target == "/foo?x=1", do: target, else: "/foo")
        assert capture.origin.source == :forwarded

        if component == "@path" do
          assert {:ok, _} = verdict
        else
          assert verdict == :error

          assert {:error, %Error{reason: :unsupported_component}} =
                   conn.private.request_seal.verification
        end

        IO.puts(
          "TARGET proxy transport=https1 sent=#{target} backend_target=#{capture.message.raw_target} component=#{component} status=#{status}"
        )
      end
    end
  end

  defp restore(key, nil), do: Application.delete_env(:request_seal, key)
  defp restore(key, value), do: Application.put_env(:request_seal, key, value)

  defp signed_headers(origin, target, components, method \\ "GET", body \\ "") do
    # Construct exact core input directly: Finch itself drops the empty query marker.
    {:ok, message} =
      RequestSeal.Message.new(%{
        kind: :request,
        method: method,
        raw_target: target,
        target_form: :origin,
        scheme: URI.parse(origin).scheme,
        authority: URI.parse(origin).authority,
        trailers: :unavailable,
        transport: %RequestSeal.TransportFacts{},
        fields: [
          %RequestSeal.FieldOccurrence{
            name: "accept",
            value: "*/*",
            section: :headers,
            provenance: :caller
          }
        ],
        body: %RequestSeal.Body{state: :retained, bytes: body, max_bytes: 4096}
      })

    spec = %{T.spec(components) | digest: if(body == "", do: nil, else: ["sha-256"])}

    signed =
      RequestSeal.Adapter.Signing.sign(message, spec, T.handle(), clock: fn -> 1_618_884_473 end)

    assert %RequestSeal.Message{} = signed
    Enum.map(signed.fields, &{String.downcase(&1.name), &1.value})
  end

  defp send_exact(origin, transport, target, headers, method \\ "GET", body \\ "") do
    if transport in [:h2c, :https2] do
      uri = URI.parse(origin)

      {:ok, conn} =
        Mint.HTTP.connect(String.to_existing_atom(uri.scheme), "127.0.0.1", uri.port,
          protocols: [:http2],
          mode: :passive,
          transport_opts: if(uri.scheme == "https", do: [verify: :verify_none], else: [])
        )

      {:ok, conn, ref} = Mint.HTTP.request(conn, method, target, headers, body)
      {conn, status} = receive_response(conn, ref, nil)
      {:ok, _} = Mint.HTTP.close(conn)
      status
    else
      version = if transport == :http1_0, do: "HTTP/1.0", else: "HTTP/1.1"

      response =
        T.raw(origin, [
          method,
          " ",
          target,
          " ",
          version,
          "\r\nHost: ",
          URI.parse(origin).authority,
          "\r\n",
          Enum.map(headers, fn {n, v} -> [n, ": ", v, "\r\n"] end),
          "Content-Length: ",
          Integer.to_string(byte_size(body)),
          "\r\nConnection: close\r\n\r\n",
          body
        ])

      [_, status | _] = String.split(response, " ", parts: 3)
      String.to_integer(status)
    end
  end

  defp receive_response(conn, ref, status) do
    {:ok, conn, responses} = Mint.HTTP.recv(conn, 0, 3000)

    status =
      Enum.reduce(responses, status, fn
        {:status, ^ref, value}, _ -> value
        _, value -> value
      end)

    if {:done, ref} in responses, do: {conn, status}, else: receive_response(conn, ref, status)
  end
end
