Code.require_file("support/plug_transport_helper.exs", __DIR__)

defmodule RequestSeal.PlugTransportTest do
  use ExUnit.Case, async: false
  alias RequestSeal.PlugTransport, as: T
  alias RequestSeal.Adapter.Error
  alias RequestSeal.Plug.{Capture, Verify, SignResponse}

  setup do
    start_supervised!({Finch, name: __MODULE__.Pool})

    start_supervised!(
      {Finch,
       name: __MODULE__.HTTP2Pool,
       pools: %{
         default: [protocols: [:http2], conn_opts: [transport_opts: [verify: :verify_none]]]
       }}
    )

    %{handle: T.handle()}
  end

  test "Capture, builder and Finch agree on mixed-case hosts and default ports" do
    tls = T.tls()

    for {scheme, default, server_opts} <- [
          {"http", 80, []},
          {"https", 443,
           [scheme: :https, thousand_island_options: [transport_options: tls.server_config]]}
        ] do
      {origin, _} = T.start([owner: self(), policy: T.policy()], server_opts)

      for host <- ["ExAmPlE.COM", "ExAmPlE.COM:#{default}", "ExAmPlE.COM:8443"] do
        T.raw(origin, "GET /path HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n")
        assert_receive {:observed, _conn, {:ok, captured}, _verdict}
        url = "#{scheme}://#{host}/path"
        {:ok, built} = RequestSeal.Message.request("GET", url, [], nil)
        {:ok, finch} = RequestSeal.Finch.request_message(Finch.build(:get, url))
        assert captured.message.authority == built.authority
        assert captured.message.scheme == built.scheme
        assert {finch.authority, finch.scheme} == {built.authority, built.scheme}

        for message <- [captured.message, finch] do
          assert RequestSeal.SignatureBase.build(message, ~s[("@authority" "@scheme")]) ==
                   RequestSeal.SignatureBase.build(built, ~s[("@authority" "@scheme")])
        end
      end
    end
  end

  test "published requests preserve bytes; exact query coverage refuses missing evidence" do
    for section <- ["B.2.3", "B.2.6", "B.3"] do
      {origin, _} =
        T.start(
          owner: self(),
          origin: {:declared, "https", T.base(section)["message"]["authority"]},
          policy: T.published_policy(section),
          label: T.vector(section)["label"],
          parse: true
        )

      assert T.raw(origin, T.wire(section)) =~ "HTTP/1.1 200"
      assert_receive {:observed, conn, {:ok, captured}, verdict}

      if section == "B.2.6" do
        assert {:ok, result} = verdict
        assert result.signature.crypto == :valid
      else
        assert :error = verdict

        assert {:error, %Error{reason: :unsupported_component}} =
                 conn.private[:request_seal].verification
      end

      assert captured.message.raw_target == T.base(section)["message"]["raw_target"]
      assert captured.message.body.bytes == T.body()
      assert conn.body_params == %{"hello" => "world"}
      assert captured.message.trailers == :unavailable
      assert captured.message.transport.http_version == :http1_1
      assert Enum.all?(captured.message.fields, &(&1.provenance == :http1))
      refute inspect(conn.private[:request_seal]) =~ "hello"
    end
  end

  test "all published B.4 transformations retain their independent verdict and duplicate order" do
    b = T.base("B.4")

    for {m, valid} <- [
          {b["message"], true} | Enum.map(b["transformations"], &{&1["message"], &1["same_base"]})
        ] do
      {origin, _} =
        T.start(
          owner: self(),
          origin: {:declared, "https", m["authority"]},
          policy: T.published_policy("B.4"),
          label: "transform"
        )

      T.raw(origin, T.wire("B.4", m))
      assert_receive {:observed, conn, {:ok, captured}, verdict}

      if valid do
        assert {:ok, _} = verdict
      else
        assert :error = verdict

        assert {:error,
                %Error{
                  reason: :request_rejected,
                  source: %RequestSeal.Error{reason: :invalid_signature}
                }} = conn.private[:request_seal].verification
      end

      assert Enum.map(captured.message.fields, &{&1.name, &1.value})
             |> Enum.filter(&(elem(&1, 0) == "accept")) ==
               Enum.filter(
                 Enum.map(m["fields"], fn [n, v] -> {String.downcase(n), v} end),
                 &(elem(&1, 0) == "accept")
               )
    end
  end

  test "published query coverage rejects before digest evaluation and halts delivery" do
    {origin, _} =
      T.start(
        owner: self(),
        origin: {:declared, "https", "example.com"},
        policy: T.published_policy("B.2.3"),
        label: "sig-b23",
        on_reject: {:halt, 401}
      )

    assert T.raw(origin, T.wire("B.2.3", nil, String.replace(T.body(), "world", "earth"))) =~
             "HTTP/1.1 401"

    assert_receive {:observed, conn, {:ok, _}, :error}
    assert conn.halted

    assert {:error,
            %Error{
              reason: :unsupported_component,
              source: nil
            }} = conn.private[:request_seal].verification
  end

  test "Req final JSON gzip and encoded target authenticate on HTTP/1.1, TLS HTTP/2 and h2c", %{
    handle: h
  } do
    tls = T.tls()

    for protocol <- [:http1, :https2, :h2c] do
      server =
        if protocol == :https2,
          do: [scheme: :https, thousand_island_options: [transport_options: tls.server_config]],
          else: []

      {origin, _} = T.start([owner: self(), policy: T.policy(), parse: true, gzip: true], server)

      opts = [
        url: origin <> "/foo%2Fbar?param=Value&Pet=dog",
        method: :post,
        json: %{"hello" => "world"},
        compress_body: true,
        headers: [{"accept", "text/plain"}, {"accept", "*/*"}],
        retry: false,
        decode_body: false,
        finch: [name: __MODULE__.Pool]
      ]

      opts =
        if protocol in [:https2, :h2c],
          do: Keyword.put(opts, :finch, name: __MODULE__.HTTP2Pool),
          else: opts

      assert {:ok, req} =
               RequestSeal.Req.attach(Req.new(opts), sign: T.spec(), signer: h, verify: :none)

      assert {:ok, _} = Req.request(req)
      assert_receive {:observed, conn, {:ok, captured}, {:ok, _}}
      assert conn.body_params == %{"hello" => "world"}
      assert :zlib.gunzip(captured.message.body.bytes) == Jason.encode!(%{"hello" => "world"})
      assert captured.message.raw_target == "/foo%2Fbar?param=Value&Pet=dog"

      assert Enum.filter(captured.message.fields, &(&1.name == "accept")) |> Enum.map(& &1.value) ==
               ["text/plain", "*/*"]

      assert captured.message.transport.http_version ==
               if(protocol == :http1, do: :http1_1, else: :http2)

      if protocol != :http1, do: refute(Enum.any?(captured.message.fields, &(&1.name == "host")))
    end
  end

  test "Req parsing receives retained uncompressed JSON over both HTTP versions", %{handle: h} do
    for protocol <- [:http1, :h2c] do
      {origin, _} = T.start(owner: self(), policy: T.policy(), parse: true, assign: :verified)
      opts = if protocol == :h2c, do: [finch: [name: __MODULE__.HTTP2Pool]], else: []

      assert {:ok, req} =
               RequestSeal.Req.attach(
                 Req.new(
                   [
                     url: origin <> "/foo?param=Value",
                     method: :post,
                     json: %{"hello" => "world"},
                     headers: [{"accept", "*/*"}],
                     finch: [name: __MODULE__.Pool],
                     retry: false
                   ] ++ opts
                 ),
                 sign: T.spec(),
                 signer: h,
                 verify: :none
               )

      assert {:ok, _} = Req.request(req)
      assert_receive {:observed, conn, {:ok, _}, {:ok, result}}
      assert conn.body_params == %{"hello" => "world"}
      assert conn.assigns.verified == result
    end
  end

  test "capture retention overflow halts after one read and closes unread input" do
    {origin, _} =
      T.start(
        owner: self(),
        max_body_bytes: 1,
        policy: T.published_policy("B.2.3"),
        label: "sig-b23"
      )

    # A complete published body exceeds the bound even if the adapter returns :ok past length.
    assert T.raw(origin, T.wire("B.2.3")) =~ "HTTP/1.1 413"
    assert_receive {:observed, conn, :error, :error}
    assert conn.private[:request_seal].error.reason == :limit
    refute_received {:first_verification, _}
  end

  test "parser before Capture rejects; default reader replays at the adapter" do
    p = T.published_policy("B.2.6", owner: self())

    {origin, _} =
      T.start(
        owner: self(),
        parser_first: true,
        origin: {:declared, "https", "example.com"},
        policy: p,
        label: "sig-b26"
      )

    assert T.raw(origin, T.wire("B.2.6")) =~ "HTTP/1.1 400"
    assert_receive {:observed, conn, :error, :error}
    assert conn.private[:request_seal].error.reason == :parser_order
    refute_received {:resolved, _}

    {origin, _} =
      T.start(
        owner: self(),
        origin: {:declared, "https", "example.com"},
        policy: p,
        label: "sig-b26",
        parse: true,
        reader: false
      )

    T.raw(origin, T.wire("B.2.6"))
    assert_receive {:observed, conn, {:ok, _}, {:ok, _}}
    assert conn.body_params == %{"hello" => "world"}
    assert_receive {:resolved, _}
  end

  test "verification contains malformed app policy without exposing it" do
    {origin, _} =
      T.start(
        owner: self(),
        invalid_verify_policy: true,
        policy: T.published_policy("B.2.6", owner: self()),
        label: "sig-b26",
        on_reject: {:halt, 400}
      )

    assert T.raw(origin, T.wire("B.2.6")) =~ "HTTP/1.1 400"
    assert_receive {:observed, conn, {:ok, _}, :error}

    assert {:error, %Error{reason: :response_rejected, stage: :verify, source: nil} = error} =
             conn.private[:request_seal].verification

    assert byte_size(Exception.message(error)) < 100
    refute inspect(error) =~ "policy-canary"
    refute_received {:resolved, _}
  end

  test "rejection statuses reject informational responses independently" do
    for status <- [100, 101, 199] do
      error =
        assert_raise Error, fn ->
          Verify.init(policy: T.policy(), label: "sig", on_reject: {:halt, status})
        end

      assert error.reason == :invalid_options
      assert error.source == nil
      assert byte_size(Exception.message(error)) < 100
    end
  end

  test "delivery propagates the real Bandit chunk error after stream completion" do
    {origin, _} = T.start(owner: self(), delivery: :closed_chunk)
    assert {:ok, response} = Finch.request(Finch.build(:get, origin <> "/foo"), __MODULE__.Pool)
    assert response.status == 200
    assert response.body == T.response()
    # Client completion can precede Bandit formatting its local transport exception.
    assert_receive {:closed_chunk, {:error, reason}}, 2000
    assert is_binary(reason)
    assert_receive {:sent, _}
  end

  test "failure and rejection accept only final statuses", %{handle: h} do
    signing = [
      sign: T.spec(),
      signer: h,
      signing_timeout: 1000,
      clock: fn -> 1_618_884_473 end,
      on_failure: {:respond, 503}
    ]

    verify = [policy: T.policy(), label: "sig", on_reject: :continue]

    for status <- [100, 101, 199, 600] do
      for {plug, opts} <- [
            {SignResponse, Keyword.put(signing, :on_failure, {:respond, status})},
            {Verify, Keyword.put(verify, :on_reject, {:halt, status})}
          ] do
        error = assert_raise Error, fn -> plug.init(opts) end
        assert error.reason == :invalid_options
        assert error.source == nil
        assert byte_size(Exception.message(error)) < 100
      end
    end

    for status <- [200, 599] do
      assert SignResponse.init(Keyword.put(signing, :on_failure, {:respond, status}))
      assert Verify.init(Keyword.put(verify, :on_reject, {:halt, status}))
    end
  end

  test "injected date and signature timestamps use one configured clock sample", %{handle: h} do
    now = 1_618_884_473

    for advancing? <- [false, true] do
      clock_calls = :atomics.new(1, signed: false)

      clock = fn ->
        calls = :atomics.add_get(clock_calls, 1, 1)
        if advancing?, do: now + calls - 1, else: now
      end

      s = T.spec(~s[("@status" "date" "content-digest")])
      {origin, _} = T.start(sign: s, signer: h, clock: clock)
      request = Finch.build(:get, origin <> "/foo")
      assert {:ok, response} = Finch.request(request, __MODULE__.Pool)
      assert {"date", "Tue, 20 Apr 2021 02:07:53 GMT"} in response.headers
      assert :atomics.get(clock_calls, 1) == 1

      assert {:ok, result} =
               RequestSeal.Finch.verify(response, request, T.policy(s.components), label: "sig")

      assert result.signature.parameters["created"] == now
      assert result.signature.parameters["expires"] == now + 60
    end
  end

  test "body reader replays once and delegates without capture" do
    {origin, _} = T.start(owner: self(), parse: true, no_capture: true)
    T.raw(origin, T.wire("B.2.3"))
    assert_receive {:observed, conn, :error, :error}
    assert conn.body_params == %{"hello" => "world"}
    {origin, _} = T.start(owner: self())
    T.raw(origin, T.wire("B.2.3"))
    assert_receive {:observed, conn, {:ok, _}, :error}
    assert {:ok, bytes, conn} = Capture.read_body(conn, [])
    assert bytes == T.body()
    assert {:ok, "", _} = Capture.read_body(conn, [])
  end

  test "missing capture rejects before key resolution" do
    p = T.published_policy("B.2.3", owner: self())
    {origin, _} = T.start(owner: self(), no_capture: true, policy: p, label: "sig-b23")
    T.raw(origin, T.wire("B.2.3"))
    assert_receive {:observed, conn, :error, :error}

    assert conn.private[:request_seal].verification |> elem(1) |> Map.fetch!(:reason) ==
             :not_captured

    refute_received {:resolved, _}
  end

  test "duplicate verification makes one resolver call and one atomic replay commitment; direct constructor shares identity",
       %{handle: h} do
    owner = self()

    store =
      start_supervised!({RequestSeal.Replay.ETS, max_entries: 20})
      |> RequestSeal.Replay.ETS.store()

    p =
      T.policy(T.components(),
        owner: owner,
        freshness: %{clock: fn -> 1_618_884_473 end, max_age: 60, skew: 0, require_expires: true},
        replay: %{
          identifier: :nonce,
          namespace: "rfc9421",
          store: store,
          timeout: 1000,
          commitment: fn facts ->
            send(owner, {:commitment, facts.identifier})
            {:ok, facts.identifier}
          end
        }
      )

    {origin, _} = T.start(owner: owner, policy: p, twice: true)

    assert {:ok, signed} =
             RequestSeal.Finch.sign(
               Finch.build(:post, origin <> "/foo", [{"accept", "*/*"}], T.body()),
               T.spec(),
               h,
               clock: fn -> 1_618_884_473 end
             )

    assert {:ok, _} = Finch.request(signed, __MODULE__.Pool)
    assert_receive {:observed, conn, {:ok, _}, :error}
    assert {:error, %Error{reason: :already_verified}} = conn.private[:request_seal].verification
    assert_receive {:first_verification, {:ok, _}}
    assert_receive {:resolved, _}
    assert_receive {:commitment, _}
    refute_received {:resolved, _}
    refute_received {:commitment, _}
    assert {:ok, _} = Finch.request(signed, __MODULE__.Pool)
    assert_receive {:observed, conn, {:ok, _}, :error}
    assert {:error, %Error{reason: :already_verified}} = conn.private[:request_seal].verification
    assert_receive {:first_verification, :error}

    assert_receive {:verification_attempt,
                    {:error, %Error{source: %RequestSeal.Error{reason: :replayed}}}}

    assert_receive {:sent, _}
    assert_receive {:sent, _}
    {origin, _} = T.start(owner: owner, policy: p, direct_claim: true)

    assert {:ok, signed} =
             RequestSeal.Finch.sign(
               Finch.build(:post, origin <> "/foo", [{"accept", "*/*"}], T.body()),
               T.spec(),
               h,
               clock: fn -> 1_618_884_473 end
             )

    assert {:ok, _} = Finch.request(signed, __MODULE__.Pool)
    assert_receive {:direct_claim, {:ok, _}}
    assert_receive {:observed, conn, {:ok, _}, :error}

    assert {:error, %Error{source: %RequestSeal.Error{reason: :replayed}}} =
             conn.private[:request_seal].verification
  end

  test "unknown key rejects; valid unattributed identity does not authorize and private inspection hides canaries",
       %{handle: h} do
    owner = self()

    store =
      start_supervised!({RequestSeal.Replay.ETS, max_entries: 20})
      |> RequestSeal.Replay.ETS.store()

    p =
      T.policy(T.components(),
        freshness: %{
          clock: fn -> System.system_time(:second) end,
          max_age: 60,
          skew: 0,
          require_expires: true
        },
        replay: %{
          identifier: :nonce,
          namespace: "rfc9421",
          store: store,
          timeout: 1000,
          commitment: fn facts ->
            send(owner, {:identity_commitment, facts.identifier})
            {:ok, facts.identifier}
          end
        }
      )

    {origin, _} = T.start(owner: self(), policy: p, delivery: :deny)

    for keyid <- ["unknown", "test-key-ed25519"] do
      s = %{T.spec() | parameters: %{T.spec().parameters | keyid: keyid}}

      assert {:ok, req} =
               RequestSeal.Finch.sign(
                 Finch.build(
                   :post,
                   origin <> "/foo",
                   [{"accept", "*/*"}, {"authorization", "Bearer header-canary"}],
                   T.body()
                 ),
                 s,
                 h
               )

      assert {:ok, %{status: 403}} = Finch.request(req, __MODULE__.Pool)
      assert_receive {:observed, conn, {:ok, _}, result}

      if keyid == "unknown" do
        assert :error = result

        assert {:error, %Error{source: %RequestSeal.Error{reason: :unknown_key}} = e} =
                 conn.private[:request_seal].verification

        refute inspect(e) =~ "header-canary"
        refute_received {:identity_commitment, _}
      else
        assert {:ok, result} = result
        assert result.principal == :unattributed
        assert result.authorization == :not_evaluated
        assert_receive {:identity_commitment, _}
      end

      refute inspect(conn.private[:request_seal]) =~ "header-canary"
      refute inspect(conn.private[:request_seal]) =~ "hello"
    end
  end

  test "request trailers unavailable reject a trailer policy", %{handle: h} do
    p =
      T.policy(~s[("content-digest";tr)],
        content: %{kind: :content, algorithms: ["sha-256"], section: :trailers}
      )

    {origin, _} = T.start(owner: self(), policy: p)

    {:ok, request} =
      RequestSeal.Finch.request_message(Finch.build(:post, origin <> "/foo", [], T.body()))

    {:ok, digest} = RequestSeal.Digest.compute(request.body, ["sha-256"])
    {:ok, digest} = RequestSeal.Digest.serialize(digest)

    message = %{
      request
      | trailers: [
          %RequestSeal.FieldOccurrence{name: "content-digest", value: digest, section: :trailers}
        ]
    }

    {:ok, signed} =
      RequestSeal.sign(
        message,
        %{
          label: "sig",
          algorithm: "ed25519",
          signature_input: ~s[("content-digest";tr);keyid="test-key-ed25519"]
        },
        fn _, base -> RequestSeal.Custody.sign(h, base) end
      )

    # Locally constructed trailer signature over real retained bytes; not an external conformance claim.
    assert {:ok, _} = RequestSeal.verify(signed, p, label: "sig")
    headers = Enum.map(signed.fields, &[&1.name, ": ", &1.value, "\r\n"])

    bytes = [
      "POST /foo HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: content-digest\r\nConnection: close\r\n",
      headers,
      "\r\n12\r\n",
      T.body(),
      "\r\n0\r\ncontent-digest: ",
      digest,
      "\r\n\r\n"
    ]

    T.raw(origin, bytes)
    assert_receive {:observed, conn, {:ok, captured}, :error}
    assert captured.message.trailers == :unavailable
    assert {:error, %Error{reason: :request_rejected}} = conn.private[:request_seal].verification
  end

  test "HTTP/1.0 without Host and CONNECT fail capture rather than inventing an origin" do
    Code.ensure_loaded!(Bandit.Adapter)
    assert 1 == :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, true, [:local])
    on_exit(fn -> :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, false, [:local]) end)
    {origin, _} = T.start(owner: self(), trace_body: true)
    assert T.raw(origin, "GET /foo HTTP/1.0\r\n\r\n") =~ "400"
    assert_receive {:observed, conn, :error, :error}
    assert conn.private[:request_seal].error.reason == :invalid_request
    refute_received {:trace, _, :call, {Bandit.Adapter, :read_req_body, _}}

    assert T.raw(
             origin,
             "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
           ) =~ "400"

    # Known-positive probe on the same listener and tracing setup.
    assert T.raw(origin, T.wire("B.2.3")) =~ "200"
    assert_receive {:trace, _, :call, {Bandit.Adapter, :read_req_body, _}}
  end

  test "response signature binds final bytes to captured request on HTTP/1.1 and HTTP/2", %{
    handle: h
  } do
    for protocol <- [:http1, :h2c] do
      {origin, _} =
        T.start(owner: self(), sign: %{T.spec(T.response_components()) | label: "res"}, signer: h)

      opts = if protocol == :h2c, do: [finch: [name: __MODULE__.HTTP2Pool]], else: []

      assert {:ok, req} =
               RequestSeal.Req.attach(
                 Req.new(
                   [
                     url: origin <> "/foo%2Fbar?param=Value",
                     headers: [{"accept", "*/*"}],
                     finch: [name: __MODULE__.Pool],
                     retry: false,
                     decode_body: false
                   ] ++ opts
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
      assert response.body == T.response()
      assert {:ok, _} = RequestSeal.Req.verification(response)
      assert_receive {:observed, _, {:ok, captured}, _}
      assert captured.message.raw_target == "/foo%2Fbar?param=Value"

      assert {:ok, request} =
               RequestSeal.Finch.sign(
                 Finch.build(:get, origin <> "/different", [{"accept", "*/*"}]),
                 T.spec(),
                 h
               )

      assert {:ok, response} = Finch.request(request, __MODULE__.Pool)

      assert {:ok, _} =
               RequestSeal.Finch.verify(response, request, T.policy(T.response_components()),
                 label: "res"
               )

      assert_receive {:observed, _, {:ok, second_capture}, _}
      assert second_capture.message.raw_target == "/different"

      assert {:error, %Error{reason: :response_rejected}} =
               RequestSeal.Finch.verify(
                 response,
                 %{request | path: "/wrong"},
                 T.policy(T.response_components()),
                 label: "res"
               )
    end
  end

  test "published B.2.4 response served through real send_resp verifies with Finch" do
    {origin, _} = T.start(published_response: true)
    req = Finch.build(:get, origin <> "/foo")
    assert {:ok, response} = Finch.request(req, __MODULE__.Pool)

    assert {:ok, _} =
             RequestSeal.Finch.verify(response, req, T.published_policy("B.2.4"),
               label: "sig-b24"
             )
  end

  test "Bandit compression invalidates covered bytes; disabling compression preserves them", %{
    handle: h
  } do
    for compress <- [true, false] do
      {origin, _} =
        T.start([sign: %{T.spec(T.response_components()) | label: "res"}, signer: h],
          http_options: [compress: compress]
        )

      assert {:ok, req} =
               RequestSeal.Req.attach(
                 Req.new(
                   url: origin <> "/foo",
                   headers: [{"accept", "*/*"}],
                   compressed: true,
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

      if compress do
        assert {:error,
                %Error{
                  reason: :response_rejected,
                  source: %RequestSeal.Error{reason: :digest_mismatch}
                }} = Req.request(req)
      else
        assert {:ok, _} = Req.request(req)
      end
    end
  end

  test "chunked and file body signing fail with empty unsigned failure while status-only streams sign",
       %{handle: h} do
    for delivery <- [:chunked, :file] do
      {origin, _} =
        T.start(
          owner: self(),
          delivery: delivery,
          sign: T.spec(T.response_components()),
          signer: h
        )

      assert {:ok, response} = Finch.request(Finch.build(:get, origin <> "/foo"), __MODULE__.Pool)
      assert response.status == 503
      assert response.body == ""

      refute Enum.any?(response.headers, fn {name, _} ->
               name in ["signature", "signature-input"]
             end)

      assert_receive {:sent, conn}
      assert conn.private[:request_seal].error.reason == :unsupported_delivery

      if delivery == :chunked do
        assert_receive {:chunk_write, {:error, :closed}}
        assert {:error, :closed} = Plug.Conn.chunk(conn, "later bytes")
      end
    end

    s = %{T.spec(~s[("@status")]) | digest: nil}
    {origin, _} = T.start(delivery: :chunked, sign: s, signer: h)
    req = Finch.build(:get, origin <> "/foo")
    assert {:ok, response} = Finch.request(req, __MODULE__.Pool)
    assert response.body == T.response()

    assert {:ok, _} =
             RequestSeal.Finch.verify(
               response,
               req,
               T.policy(~s[("@status")], content: :not_required),
               label: "sig"
             )
  end

  @tag :unwrapped_failure
  test "buffered signing failure stays bounded when the application unwraps the adapter", %{
    handle: h
  } do
    unwrap = fn conn ->
      {RequestSeal.Plug.Delivery, delivery} = conn.adapter
      %{conn | adapter: {delivery.adapter, delivery.payload}}
    end

    for protocol <- [:http1, :h2c, :https2] do
      {origin, _} =
        transport_start(protocol,
          owner: self(),
          no_capture: true,
          sign: T.spec(T.response_components()),
          signer: h,
          existing_signature: true,
          after_sign: unwrap
        )

      assert {:ok, response} =
               Finch.request(Finch.build(:get, origin <> "/foo"), transport_pool(protocol))

      assert response.status == 503
      assert response.body == ""

      refute Enum.any?(response.headers, fn {name, _} ->
               name in ["signature", "signature-input", "content-digest", "repr-digest"]
             end)

      assert_receive {:sent, conn}
      assert {Bandit.Adapter, _} = conn.adapter
      assert %Error{reason: :not_captured, source: nil} = conn.private.request_seal.error
    end
  end

  test "response date and content length are supplied before signing and signer failure strips signatures",
       %{handle: h} do
    s = %{T.spec(~s[("@status" "date" "content-length" "content-digest")]) | label: "res"}
    {origin, _} = T.start(sign: s, signer: h)
    req = Finch.build(:get, origin <> "/foo")
    assert {:ok, response} = Finch.request(req, __MODULE__.Pool)

    assert {:ok, _} =
             RequestSeal.Finch.verify(response, req, T.policy(s.components), label: "res")

    :ok = RequestSeal.Custody.Local.release(h)
    {origin, _} = T.start(owner: self(), sign: s, signer: h)
    assert {:ok, response} = Finch.request(Finch.build(:get, origin <> "/foo"), __MODULE__.Pool)
    assert response.status == 503
    assert response.body == ""
    refute Enum.any?(response.headers, fn {n, _} -> n in ["signature", "signature-input"] end)
  end

  test "all required option choices, timeout bounds and unsupported response components reject safely",
       %{handle: h} do
    for opts <- [
          [],
          [origin: :connection],
          [origin: :connection, max_body_bytes: -1, read_timeout: 1000],
          [origin: :connection, max_body_bytes: 1, read_timeout: 300_001],
          [origin: :connection, max_body_bytes: 1, read_timeout: 0],
          [origin: :implicit, max_body_bytes: 1, read_timeout: 1],
          [origin: :connection, max_body_bytes: 1, read_timeout: 1, unknown: true]
        ] do
      assert_raise Error, fn -> Capture.init(opts) end
    end

    p = T.policy()

    for opts <- [
          [policy: p, label: "sig"],
          [policy: p, label: "sig", on_reject: :unknown],
          [policy: p, label: "sig", on_reject: {:halt, 600}],
          [policy: p, label: "sig", on_reject: :continue, assign: "wrong"]
        ] do
      assert_raise Error, fn -> Verify.init(opts) end
    end

    for opts <- [
          [sign: T.spec(), signer: h],
          [
            sign: T.spec(),
            signer: h,
            signing_timeout: 0,
            clock: fn -> 1 end,
            on_failure: {:respond, 503}
          ],
          [
            sign: T.spec(~s[("content-digest";tr)]),
            signer: h,
            signing_timeout: 1000,
            clock: fn -> 1 end,
            on_failure: {:respond, 503}
          ]
        ] do
      assert_raise Error, fn -> SignResponse.init(opts) end
    end
  end

  test "related request body components permit status-only streaming without claiming response integrity",
       %{handle: h} do
    s = %{T.spec(~s[("@status" "content-digest";req)]) | digest: nil}
    {origin, _} = T.start(delivery: :chunked, sign: s, signer: h)

    {:ok, req} =
      RequestSeal.Finch.sign(
        Finch.build(:get, origin <> "/foo", [{"accept", "*/*"}]),
        T.spec(),
        h
      )

    assert {:ok, response} = Finch.request(req, __MODULE__.Pool)
    assert response.status == 200

    assert {:ok, result} =
             RequestSeal.Finch.verify(
               response,
               req,
               T.policy(s.components, content: :not_required),
               label: "sig"
             )

    assert result.content == :not_required
  end

  test "capture uses one read and closes overflow before a pipelined request can be interpreted" do
    Code.ensure_loaded!(Bandit.Adapter)
    assert 1 == :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, true, [:local])
    on_exit(fn -> :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, false, [:local]) end)
    {origin, _} = T.start(owner: self(), trace_body: true, max_body_bytes: 1)

    wire =
      T.wire("B.2.3")
      |> IO.iodata_to_binary()
      |> String.replace("Connection: close", "Connection: keep-alive")

    response =
      T.raw(origin, wire <> "GET /foo HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

    assert response =~ "HTTP/1.1 413"
    assert length(:binary.matches(response, "HTTP/1.1")) == 1
    assert_receive {:trace, _, :call, {Bandit.Adapter, :read_req_body, [_, opts]}}
    assert opts[:length] == 1
    refute_received {:trace, _, :call, {Bandit.Adapter, :read_req_body, _}}
    assert_receive {:observed, conn, :error, :error}
    assert conn.private[:request_seal].error.reason == :limit
  end

  test "zero-byte bound retains empty bodies, OPTIONS asterisk and normalized IPv6 authority" do
    {origin, _} = T.start(owner: self(), max_body_bytes: 0)

    for {method, target, host, authority} <- [
          {"OPTIONS", "*", "ExAmPlE.CoM:80", "example.com"},
          {"GET", "/foo", "[2001:db8:cafe::17]:4711", "[2001:db8:cafe::17]:4711"}
        ] do
      assert T.raw(origin, [
               method,
               " ",
               target,
               " HTTP/1.1\r\nHost: ",
               host,
               "\r\nConnection: close\r\n\r\n"
             ]) =~ "200"

      assert_receive {:observed, _, {:ok, capture}, :error}
      assert capture.message.raw_target == target
      assert capture.message.authority == authority
      assert capture.message.body.bytes == ""
      assert capture.message.target_form == if(target == "*", do: :asterisk, else: :origin)
    end
  end

  test "HTTP/2 cookie joining is visible and makes lost occurrence bytes reject", %{handle: h} do
    {origin, _} =
      T.start(
        owner: self(),
        policy: T.policy(~s[("@method" "@path" "cookie")], content: :not_required)
      )

    {:ok, req} =
      RequestSeal.Finch.sign(
        Finch.build(:get, origin <> "/foo", [
          {"cookie", "a=b"},
          {"cookie", "c=d"},
          {"cookie", "e=f"}
        ]),
        %{T.spec(~s[("@method" "@path" "cookie")]) | digest: nil},
        h
      )

    assert {:ok, _} = Finch.request(req, __MODULE__.HTTP2Pool)
    assert_receive {:observed, conn, {:ok, capture}, :error}

    assert Enum.filter(capture.message.fields, &(&1.name == "cookie")) |> Enum.map(& &1.value) ==
             ["a=b; c=d; e=f"]

    assert {:error, %Error{source: %RequestSeal.Error{reason: :invalid_signature}}} =
             conn.private[:request_seal].verification
  end

  test "wrong response request context rejects at Req; later registered body transformations run before signing",
       %{handle: h} do
    for mode <- [:wrong_related, :transform_response] do
      {origin, _} =
        T.start([
          {mode, true},
          {:sign, %{T.spec(T.response_components()) | label: "res"}},
          {:signer, h}
        ])

      {:ok, req} =
        RequestSeal.Req.attach(
          Req.new(
            url: origin <> "/foo",
            headers: [{"accept", "*/*"}],
            finch: [name: __MODULE__.Pool],
            decode_body: false,
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

      if mode == :wrong_related do
        assert {:error,
                %Error{
                  reason: :response_rejected,
                  source: %RequestSeal.Error{reason: :invalid_signature}
                }} = Req.request(req)
      else
        assert {:ok, response} = Req.request(req)
        assert response.body == T.body()
        assert {:ok, _} = RequestSeal.Req.verification(response)
      end
    end
  end

  test "CONNECT framework values and repeated capture reject before another read" do
    Code.ensure_loaded!(Bandit.Adapter)
    assert 1 == :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, true, [:local])
    on_exit(fn -> :erlang.trace_pattern({Bandit.Adapter, :read_req_body, 2}, false, [:local]) end)

    for opts <- [[connect_method: true], [capture_twice: true]] do
      {origin, _} = T.start([owner: self(), trace_body: true] ++ opts)
      assert T.raw(origin, T.wire("B.2.3")) =~ "400"
      assert_receive {:observed, conn, _, :error}
      assert conn.private[:request_seal].error.reason == :invalid_request

      if opts[:capture_twice],
        do: assert_receive({:trace, _, :call, {Bandit.Adapter, :read_req_body, _}})

      refute_received {:trace, _, :call, {Bandit.Adapter, :read_req_body, _}}
    end
  end

  test "public accessors hide failures and capture inspection hides ingress authority" do
    {origin, _} = T.start(owner: self())
    T.raw(origin, "GET /foo HTTP/1.1\r\nHost: header-canary.example\r\nConnection: close\r\n\r\n")
    assert_receive {:observed, conn, {:ok, capture}, :error}
    assert {:ok, _} = RequestSeal.Plug.capture(conn)
    assert :error == RequestSeal.Plug.verification(conn)
    refute inspect(capture) =~ "header-canary"
    refute inspect(conn.private[:request_seal]) =~ "header-canary"
    refute inspect(capture.message) =~ "header-canary"
  end

  test "signing without capture produces empty unsigned failure", %{handle: h} do
    {origin, _} = T.start(owner: self(), no_capture: true, sign: T.spec(), signer: h)
    assert {:ok, response} = Finch.request(Finch.build(:get, origin <> "/foo"), __MODULE__.Pool)
    assert response.status == 503
    assert response.body == ""
    refute Enum.any?(response.headers, fn {n, _} -> n in ["signature", "signature-input"] end)
    assert_receive {:sent, conn}
    assert conn.private[:request_seal].error.reason == :not_captured
  end

  test "each omitted response signing choice rejects instead of silently using a default", %{
    handle: h
  } do
    opts = [
      sign: T.spec(),
      signer: h,
      signing_timeout: 1000,
      clock: fn -> System.system_time(:second) end,
      on_failure: {:respond, 503}
    ]

    for key <- Keyword.keys(opts) do
      assert_raise Error, fn -> SignResponse.init(Keyword.delete(opts, key)) end
    end

    for bad <- [
          [signing_timeout: 300_001],
          [clock: :invalid],
          [on_failure: {:respond, 600}],
          [on_failure: :continue],
          [signer: :invalid],
          [extra: true]
        ] do
      assert_raise Error, fn -> SignResponse.init(Keyword.merge(opts, bad)) end
    end

    for component <- [~s[("content-digest";tr)], ~s[("host")]] do
      assert_raise Error, fn -> SignResponse.init(Keyword.put(opts, :sign, T.spec(component))) end
    end

    for bad <- [
          [],
          [
            {:origin, :connection},
            {:origin, :connection},
            {:max_body_bytes, 1},
            {:read_timeout, 1}
          ],
          [origin: {:declared, "https", "example.com/path"}, max_body_bytes: 1, read_timeout: 1],
          [
            origin: {:forwarded, %{trusted_peers: [{{127, 0, 0, 1}, 33}], field: :forwarded}},
            max_body_bytes: 1,
            read_timeout: 1
          ],
          [
            origin: {:forwarded, %{trusted_peers: [{{127, 0, 0, 999}, 32}], field: :forwarded}},
            max_body_bytes: 1,
            read_timeout: 1
          ],
          [
            origin: {:forwarded, %{trusted_peers: [], field: :forwarded}},
            max_body_bytes: 1,
            read_timeout: 1
          ]
        ] do
      assert_raise Error, fn -> Capture.init(bad) end
    end

    p = T.policy()

    for bad <- [[policy: :invalid], [label: "INVALID"], [extra: true]] do
      assert_raise Error, fn ->
        Verify.init(Keyword.merge([policy: p, label: "sig", on_reject: :continue], bad))
      end
    end
  end

  test "published query coverage rejects over raw TLS with ingress security retained" do
    tls = T.tls()

    {origin, _} =
      T.start(
        [
          owner: self(),
          origin: {:declared, "https", "example.com"},
          policy: T.published_policy("B.2.3"),
          label: "sig-b23",
          parse: true
        ],
        scheme: :https,
        thousand_island_options: [transport_options: tls.server_config]
      )

    assert T.raw(origin, T.wire("B.2.3")) =~ "200"
    assert_receive {:observed, conn, {:ok, capture}, :error}

    assert {:error, %Error{reason: :unsupported_component}} =
             conn.private[:request_seal].verification

    assert capture.ingress.scheme == :https
    assert capture.message.transport.tls == :tls
    assert capture.message.transport.evidence == :declared
    assert conn.body_params == %{"hello" => "world"}
  end

  test "existing response date is retained once and failures erase preexisting or late signature fields",
       %{handle: h} do
    s = T.spec(~s[("@status" "date" "content-digest")])
    {origin, _} = T.start(response_date: true, sign: s, signer: h)
    req = Finch.build(:get, origin <> "/foo")
    assert {:ok, response} = Finch.request(req, __MODULE__.Pool)

    assert Enum.filter(response.headers, fn {n, _} -> n == "date" end) == [
             {"date", "Tue, 20 Apr 2021 02:07:56 GMT"}
           ]

    assert {:ok, _} =
             RequestSeal.Finch.verify(response, req, T.policy(s.components), label: "sig")

    :ok = RequestSeal.Custody.Local.release(h)

    for mode <- [:existing_signature, :late_signature] do
      {origin, _} = T.start([{mode, true}, {:owner, self()}, {:sign, s}, {:signer, h}])
      assert {:ok, response} = Finch.request(Finch.build(:get, origin <> "/foo"), __MODULE__.Pool)
      assert response.status == 503
      assert response.body == ""
      refute Enum.any?(response.headers, fn {n, _} -> n in ["signature", "signature-input"] end)
      assert_receive {:sent, conn}

      if mode == :existing_signature,
        do:
          refute(
            Enum.any?(conn.resp_headers, fn {n, _} -> n in ["signature", "signature-input"] end)
          )
    end
  end

  test "related signing mode accepts only explicit Boolean options" do
    for value <- [:implicit, nil, 1] do
      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.Adapter.Signing.protect(:plug, :attach, 0, fn ->
                 RequestSeal.Adapter.Signing.spec!(T.spec(), related: value)
               end)
    end
  end

  test "unbracketed framework IPv6 host is bracketed in the declared connection authority" do
    {origin, _} = T.start(owner: self(), bare_host: true)

    T.raw(
      origin,
      "GET /foo HTTP/1.1\r\nHost: [2001:db8:cafe::17]:4711\r\nConnection: close\r\n\r\n"
    )

    assert_receive {:observed, _, {:ok, capture}, :error}
    assert capture.ingress.host == "2001:db8:cafe::17"
    assert capture.origin.authority == "[2001:db8:cafe::17]:4711"
  end

  for protocol <- [:h2c, :https2],
      {kind, status, reason} <- [{:oversize, 413, :limit}, {:invalid, 400, :invalid_request}] do
    @tag :http2_capture_rejection
    test "#{protocol} #{kind} Capture rejection is a valid HTTP/2 response" do
      protocol = unquote(protocol)
      opts = if unquote(kind) == :oversize, do: [max_body_bytes: 1], else: [capture_twice: true]
      {origin, _} = transport_start(protocol, [owner: self()] ++ opts)
      request = Finch.build(:post, origin <> "/foo", [], "ab")
      result = Finch.request(request, __MODULE__.HTTP2Pool)
      assert_receive {:observed, conn, _, :error}
      assert conn.private[:request_seal].error.reason == unquote(reason)
      assert {:ok, response} = result
      assert response.status == unquote(status)
      refute List.keymember?(response.headers, "connection", 0)
    end
  end

  @tag :multipart_replay
  test "multipart replay matches the no-Capture control on every transport", %{handle: h} do
    # RFC 7578 form-data; local transport behavior, not an external conformance vector.
    body =
      "--boundary\r\nContent-Disposition: form-data; name=\"hello\"\r\n\r\nworld\r\n--boundary--\r\n"

    spec = T.spec(~s[("@method" "@path" "content-digest")])

    for protocol <- [:http1, :h2c, :https2], no_capture <- [true, false] do
      opts = [
        owner: self(),
        no_capture: no_capture,
        parse: true,
        parser_opts: [parsers: [:multipart]]
      ]

      opts = if no_capture, do: opts, else: Keyword.put(opts, :policy, T.policy(spec.components))
      {origin, _} = transport_start(protocol, opts)

      req =
        Finch.build(
          :post,
          origin <> "/foo",
          [{"content-type", "multipart/form-data; boundary=boundary"}],
          body
        )

      assert {:ok, req} = RequestSeal.Finch.sign(req, spec, h)
      assert {:ok, %{status: 200}} = Finch.request(req, transport_pool(protocol))
      assert_receive {:observed, conn, captured, verdict}
      assert conn.body_params == %{"hello" => "world"}

      if no_capture do
        assert captured == :error
      else
        assert {:ok, capture} = captured
        assert capture.message.body.bytes == body
        assert {:ok, _} = verdict
      end
    end
  end

  @tag :response_cookie_coverage
  test "cookie-covered responses verify or fail closed, including late cookies", %{handle: h} do
    spec = T.spec(~s[("@status" "set-cookie" "content-digest")])

    for protocol <- [:http1, :h2c, :https2], cookie <- [nil, :pending, :late] do
      {origin, _} =
        transport_start(protocol,
          owner: self(),
          sign: spec,
          signer: h,
          cookie_header: true,
          cookie: cookie
        )

      req = Finch.build(:get, origin <> "/foo")
      assert {:ok, response} = Finch.request(req, transport_pool(protocol))
      assert_receive {:sent, conn}

      if response.status == 200 do
        assert {:ok, _} =
                 RequestSeal.Finch.verify(response, req, T.policy(spec.components), label: "sig")
      else
        assert cookie != nil
        assert response.status == 503
        assert response.body == ""
        refute List.keymember?(response.headers, "signature", 0)
        refute List.keymember?(response.headers, "signature-input", 0)
        assert conn.private[:request_seal].error.reason == :unsupported_delivery
      end
    end
  end

  @tag :reader_observation_boundary
  test "wrapper transformation is outside the replay observation boundary", %{handle: h} do
    for transform <- [false, true] do
      {origin, _} =
        T.start(owner: self(), parse: true, wrapper_transform: transform, policy: T.policy())

      req =
        Finch.build(
          :post,
          origin <> "/foo",
          [{"content-type", "application/json"}, {"accept", "*/*"}],
          T.body()
        )

      assert {:ok, req} = RequestSeal.Finch.sign(req, T.spec(), h)
      assert {:ok, %{status: 200}} = Finch.request(req, __MODULE__.Pool)
      assert_receive {:observed, conn, {:ok, capture}, {:ok, _}}
      assert capture.message.body.bytes == T.body()
      assert conn.body_params == %{"hello" => if(transform, do: "earth", else: "world")}
    end
  end

  @tag :replay_digest_validation
  test "handed-out replay digest rejects replaced capture before key resolution", %{handle: h} do
    {origin, _} =
      T.start(
        owner: self(),
        parse: true,
        replay_tamper: true,
        policy: T.policy(T.components(), owner: self())
      )

    req =
      Finch.build(
        :post,
        origin <> "/foo",
        [{"content-type", "application/json"}, {"accept", "*/*"}],
        T.body()
      )

    assert {:ok, req} = RequestSeal.Finch.sign(req, T.spec(), h)
    assert {:ok, _} = Finch.request(req, __MODULE__.Pool)
    assert_receive {:observed, conn, {:ok, _}, :error}
    assert conn.body_params == %{"hello" => "world"}

    assert {:error, %Error{reason: :parser_order, source: nil}} =
             conn.private[:request_seal].verification

    refute_received {:resolved, _}
  end

  @tag :parser_read_limits
  test "parser length below Capture's bound rejects retained JSON" do
    for protocol <- [:http1, :h2c, :https2] do
      {origin, _} =
        transport_start(protocol,
          owner: self(),
          parse: true,
          max_body_bytes: 4096,
          parser_opts: [length: 5]
        )

      req = Finch.build(:post, origin <> "/foo", [{"content-type", "application/json"}], T.body())
      assert {:ok, %{status: 413}} = Finch.request(req, transport_pool(protocol))
      assert_receive {:parser_rejection, Plug.Parsers.RequestTooLargeError}
      assert_receive {:observed, _, {:ok, capture}, :error}
      assert capture.message.body.bytes == T.body()
    end
  end

  @tag :parser_read_limits
  test "replay reads length-sized slices until drained" do
    {origin, _} = T.start(owner: self())

    assert {:ok, _} =
             Finch.request(Finch.build(:post, origin <> "/foo", [], "abcdefgh"), __MODULE__.Pool)

    assert_receive {:observed, conn, {:ok, _}, :error}
    assert {:more, "abc", conn} = Capture.read_body(conn, length: 3)
    assert {:more, "def", conn} = Capture.read_body(conn, length: 3)
    assert {:ok, "gh", conn} = Capture.read_body(conn, length: 3)
    assert {:ok, "", _} = Capture.read_body(conn, length: 3)
  end

  for protocol <- [:http1, :h2c, :https2] do
    @tag :replay_coverage
    @tag :partial_replay_rejection
    test "#{protocol} partial reads and unread suffix tamper reject before resolution", %{
      handle: h
    } do
      for tamper <- [false, true] do
        read = fn conn ->
          {:more, prefix, conn} = Plug.Conn.read_body(conn, length: 5)
          assert prefix == binary_part(T.body(), 0, 5)

          if tamper do
            {adapter, payload} = conn.adapter

            replay = %{
              payload.replay
              | bytes: String.replace(payload.replay.bytes, "world", "earth")
            }

            %{conn | adapter: {adapter, %{payload | replay: replay}}}
          else
            conn
          end
        end

        {origin, _} =
          transport_start(unquote(protocol),
            owner: self(),
            before_verify: read,
            policy: T.policy(T.components(), owner: self())
          )

        signed_body_request(origin, unquote(protocol), h)
        assert_receive {:observed, conn, {:ok, _}, verdict}
        assert verdict == :error

        assert {:error, %Error{reason: :parser_order, source: nil}} =
                 conn.private.request_seal.verification

        refute_received {:resolved, _}
      end
    end

    @tag :replay_coverage
    @tag :unread_suffix_tamper
    test "#{protocol} suffix-only tamper after a prefix read rejects", %{handle: h} do
      read = fn conn ->
        {:more, _, conn} = Plug.Conn.read_body(conn, length: 5)
        {adapter, payload} = conn.adapter
        replay = %{payload.replay | bytes: String.replace(payload.replay.bytes, "world", "earth")}
        %{conn | adapter: {adapter, %{payload | replay: replay}}}
      end

      {origin, _} =
        transport_start(unquote(protocol),
          owner: self(),
          before_verify: read,
          policy: T.policy(T.components(), owner: self())
        )

      signed_body_request(origin, unquote(protocol), h)
      assert_receive {:observed, conn, {:ok, _}, verdict}
      assert verdict == :error

      assert {:error, %Error{reason: :parser_order, source: nil}} =
               conn.private.request_seal.verification

      refute_received {:resolved, _}
    end

    @tag :replay_coverage
    @tag :full_replay_digest
    test "#{protocol} fully drained replay still checks the full handed-out digest", %{
      handle: h
    } do
      for tamper <- [false, true] do
        read = fn conn ->
          {:more, _, conn} = Plug.Conn.read_body(conn, length: 5)
          {adapter, payload} = conn.adapter

          bytes =
            if tamper,
              do: String.replace(payload.replay.bytes, "world", "earth"),
              else: payload.replay.bytes

          conn = %{
            conn
            | adapter: {adapter, %{payload | replay: %{payload.replay | bytes: bytes}}}
          }

          {:ok, _, conn} = Plug.Conn.read_body(conn, [])
          conn
        end

        {origin, _} =
          transport_start(unquote(protocol),
            owner: self(),
            before_verify: read,
            policy: T.policy(T.components(), owner: self())
          )

        signed_body_request(origin, unquote(protocol), h)
        assert_receive {:observed, conn, {:ok, _}, verdict}

        if tamper do
          assert verdict == :error

          assert {:error, %Error{reason: :parser_order, source: nil}} =
                   conn.private.request_seal.verification

          refute_received {:resolved, _}
        else
          assert {:ok, _} = verdict
          assert_receive {:resolved, _}
        end
      end
    end

    @tag :replay_coverage
    @tag :replay_adapter_identity
    test "#{protocol} replacing or rewrapping the captured adapter rejects", %{handle: h} do
      for mode <- [:unwrap, :rewrap, :new_replay] do
        replace = fn conn ->
          {_, delivery} = conn.adapter
          original = {delivery.adapter, delivery.payload}

          adapter =
            case mode do
              :unwrap -> original
              :rewrap -> RequestSeal.Plug.Delivery.wrap(original)
              :new_replay -> RequestSeal.Plug.Delivery.retain(original, T.body())
            end

          %{conn | adapter: adapter}
        end

        {origin, _} =
          transport_start(unquote(protocol),
            owner: self(),
            before_verify: replace,
            policy: T.policy(T.components(), owner: self())
          )

        signed_body_request(origin, unquote(protocol), h)
        assert_receive {:observed, conn, {:ok, _}, verdict}
        assert verdict == :error

        assert {:error, %Error{reason: :parser_order, source: nil} = error} =
                 conn.private.request_seal.verification

        assert byte_size(Exception.message(error)) < 100
        refute_received {:resolved, _}
      end
    end

    @tag :replay_coverage
    @tag :reader_instrumentation
    test "#{protocol} reader instrumentation distinguishes Capture from adapter reads", %{
      handle: h
    } do
      for reader <- [true, false] do
        {origin, _} =
          transport_start(unquote(protocol),
            owner: self(),
            parse: true,
            reader: reader,
            policy: T.policy()
          )

        signed_body_request(origin, unquote(protocol), h)
        assert_receive {:observed, conn, {:ok, _}, {:ok, _}}
        assert Map.get(conn.private.request_seal, :reader_called?, false) == reader
        assert RequestSeal.Plug.Delivery.replayed?(conn.adapter)
      end
    end

    @tag :replay_coverage
    @tag :reader_consumption_guard
    test "#{protocol} reader invocation without replay consumption rejects", %{handle: h} do
      read = fn conn ->
        retained = conn.adapter
        {_, delivery} = retained
        conn = %{conn | adapter: {delivery.adapter, delivery.payload}}
        {:ok, "", conn} = Capture.read_body(conn, [])
        %{conn | adapter: retained}
      end

      {origin, _} =
        transport_start(unquote(protocol),
          owner: self(),
          before_verify: read,
          policy: T.policy(T.components(), owner: self())
        )

      signed_body_request(origin, unquote(protocol), h)
      assert_receive {:observed, conn, {:ok, _}, :error}
      assert conn.private.request_seal.reader_called?
      refute RequestSeal.Plug.Delivery.replayed?(conn.adapter)

      assert {:error, %Error{reason: :parser_order, source: nil}} =
               conn.private.request_seal.verification

      refute_received {:resolved, _}
    end

    @tag :replay_coverage
    @tag :bypass_reader_boundary
    test "#{protocol} bypass reader is indistinguishable from unread pass-through", %{
      handle: h
    } do
      {origin, _} =
        transport_start(unquote(protocol),
          owner: self(),
          parse: true,
          parser_opts: [body_reader: {T, :bypass_reader, []}],
          policy: T.policy()
        )

      signed_body_request(origin, unquote(protocol), h)
      assert_receive {:observed, conn, {:ok, capture}, {:ok, _}}
      assert conn.body_params == %{"hello" => "earth"}
      assert capture.message.body.bytes == T.body()
      refute Map.get(conn.private.request_seal, :reader_called?, false)
      refute RequestSeal.Plug.Delivery.replayed?(conn.adapter)

      for type <- ["text/plain", "application/octet-stream", "application/xml", nil] do
        {origin, _} =
          transport_start(unquote(protocol), owner: self(), parse: true, policy: T.policy())

        signed_body_request(origin, unquote(protocol), h, type)
        assert_receive {:observed, conn, {:ok, _}, {:ok, _}}
        refute Map.get(conn.private.request_seal, :reader_called?, false)
        refute RequestSeal.Plug.Delivery.replayed?(conn.adapter)
      end
    end

    @tag :replay_coverage
    @tag :invalid_replay_lengths
    test "#{protocol} invalid replay lengths return bounded errors without moving offset",
         %{handle: h} do
      owner = self()

      read = fn conn ->
        for offset <- [0, 5, byte_size(T.body())],
            bad <- [-1, -5, 1.5, nil, :invalid, "length-canary"] do
          conn =
            if offset > 0 do
              {_, _, conn} = Plug.Conn.read_body(conn, length: offset)
              conn
            else
              conn
            end

          result =
            try do
              Plug.Conn.read_body(conn, length: bad)
            rescue
              e -> {:raised, e.__struct__}
            end

          send(owner, {:invalid_replay_length, offset, bad, result})
        end

        {:more, "", zero_conn} = Plug.Conn.read_body(conn, length: 0)
        assert elem(zero_conn.adapter, 1).replay.offset == 0
        {:ok, bytes, drained} = Plug.Conn.read_body(zero_conn, [])
        assert bytes == T.body()
        send(owner, {:replay_drained, drained})
        drained
      end

      {origin, _} =
        transport_start(unquote(protocol), owner: self(), before_verify: read, policy: T.policy())

      signed_body_request(origin, unquote(protocol), h)

      for offset <- [0, 5, byte_size(T.body())],
          bad <- [-1, -5, 1.5, nil, :invalid, "length-canary"] do
        assert_receive {:invalid_replay_length, ^offset, ^bad, result}
        assert {:error, %Error{reason: :invalid_options, source: nil} = error} = result
        assert byte_size(Exception.message(error)) < 100
        refute inspect(error) =~ "length-canary"
      end

      assert_receive {:observed, _, {:ok, _}, {:ok, _}}
    end

    @tag :replay_coverage
    @tag :parameterized_cookie_coverage
    test "#{protocol} parameterized set-cookie coverage rejects pending cookies", %{
      handle: h
    } do
      for component <- [~s["set-cookie";sf], ~s["set-cookie";key="session"], ~s["set-cookie";bs]] do
        spec = T.spec("(\"@status\" " <> component <> " \"content-digest\")")
        input = RequestSeal.Adapter.Signing.spec!(spec, related: true)
        assert RequestSeal.Adapter.Signing.covered?(input, "set-cookie")

        for cookie <- [:pending, :late] do
          {origin, _} =
            transport_start(unquote(protocol),
              owner: self(),
              sign: spec,
              signer: h,
              cookie_header: true,
              cookie: cookie
            )

          assert {:ok, response} =
                   Finch.request(
                     Finch.build(:get, origin <> "/foo"),
                     transport_pool(unquote(protocol))
                   )

          assert response.status == 503
          assert response.body == ""
          refute List.keymember?(response.headers, "signature", 0)
          refute List.keymember?(response.headers, "signature-input", 0)
          assert_receive {:sent, conn}
          assert conn.private.request_seal.error.reason == :unsupported_delivery
        end
      end
    end

    @tag :replay_coverage
    @tag :response_callback_order
    test "#{protocol} earlier registered callbacks mutate bytes before signing", %{
      handle: h
    } do
      prepare = fn conn ->
        Plug.Conn.register_before_send(conn, fn c -> %{c | resp_body: T.body()} end)
      end

      {origin, _} =
        transport_start(unquote(protocol),
          owner: self(),
          before_sign: prepare,
          sign: T.spec(T.response_components()),
          signer: h
        )

      req = Finch.build(:get, origin <> "/foo")
      assert {:ok, response} = Finch.request(req, transport_pool(unquote(protocol)))
      assert response.status == 200
      assert response.body == T.body()

      assert {:ok, _} =
               RequestSeal.Finch.verify(response, req, T.policy(T.response_components()),
                 label: "sig"
               )
    end

    @tag :replay_coverage
    @tag :response_callback_validation
    test "#{protocol} callback absence is valid and malformed callback state fails closed",
         %{handle: h} do
      for callbacks <- [:absent, nil, :invalid, %{}, [nil], [fn c -> c end | :invalid]] do
        prepare = fn conn ->
          if callbacks == :absent,
            do: %{conn | private: Map.delete(conn.private, :before_send)},
            else: Plug.Conn.put_private(conn, :before_send, callbacks)
        end

        {origin, _} =
          transport_start(unquote(protocol),
            owner: self(),
            before_sign: prepare,
            sign: T.spec(T.response_components()),
            signer: h
          )

        req = Finch.build(:get, origin <> "/foo")
        assert {:ok, response} = Finch.request(req, transport_pool(unquote(protocol)))
        assert_receive {:sent, conn}

        if callbacks in [:absent, nil] do
          assert response.status == 200

          assert {:ok, _} =
                   RequestSeal.Finch.verify(response, req, T.policy(T.response_components()),
                     label: "sig"
                   )
        else
          assert response.status == 503
          assert response.body == ""
          refute List.keymember?(response.headers, "signature", 0)
          refute List.keymember?(response.headers, "signature-input", 0)

          assert %Error{reason: :unsupported_delivery, source: nil} =
                   error = conn.private.request_seal.error

          assert byte_size(Exception.message(error)) < 100
        end
      end
    end
  end

  defp signed_body_request(origin, protocol, h, type \\ "application/json") do
    headers = [{"accept", "*/*"}]
    headers = if type, do: [{"content-type", type} | headers], else: headers
    req = Finch.build(:post, origin <> "/foo", headers, T.body())
    assert {:ok, req} = RequestSeal.Finch.sign(req, T.spec(), h)
    assert {:ok, %{status: 200}} = Finch.request(req, transport_pool(protocol))
  end

  defp transport_pool(:http1), do: __MODULE__.Pool
  defp transport_pool(_), do: __MODULE__.HTTP2Pool

  defp transport_start(:https2, opts) do
    tls = T.tls()
    T.start(opts, scheme: :https, thousand_island_options: [transport_options: tls.server_config])
  end

  defp transport_start(_, opts), do: T.start(opts)
end
