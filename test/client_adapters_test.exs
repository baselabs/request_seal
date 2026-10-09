Code.require_file("support/http_signature_peer_helper.exs", __DIR__)

defmodule RequestSeal.ClientAdaptersTest do
  use ExUnit.Case, async: false
  alias RequestSeal.HTTPSignaturePeer, as: Peer
  alias RequestSeal.Adapter.Error
  alias RequestSeal.{Digest, SignatureFields}

  setup do
    h = Peer.handle()
    start_supervised!({Finch, name: __MODULE__.Pool})
    %{handle: h}
  end

  defp request(origin, handle, options \\ [], adapter_options \\ []) do
    req =
      Req.new(
        [
          url: origin <> "/foo%2Fbar?param=Value&Pet=dog",
          headers: [{"accept", "text/plain"}, {"accept", "*/*"}],
          finch: [name: __MODULE__.Pool],
          retry: false,
          decode_body: false
        ]
        |> Keyword.merge(options)
      )

    RequestSeal.Req.attach(
      req,
      [
        sign: Peer.spec(),
        signer: handle,
        verify: %{
          policy: Peer.policy(Peer.response_components(), handle),
          label: "res",
          max_stream_bytes: 4096
        }
      ]
      |> Keyword.merge(adapter_options)
    )
  end

  test "short signing specs default metadata on every Req retry", %{handle: h} do
    {origin, task} = Peer.start([%{status: 503}, %{}], h)

    spec = %{
      label: "sig",
      algorithm: "hmac-sha256",
      components: Peer.components(),
      expires_in: 60,
      digest: ["sha-256"]
    }

    assert {:ok, req} =
             request(
               origin,
               h,
               [retry: :transient, retry_delay: 0, max_retries: 1, retry_log_level: false],
               sign: spec
             )

    assert {:ok, response} = Req.request(req)
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive {:wire_request, first, {:ok, _}}
    assert_receive {:wire_request, second, {:ok, _}}
    assert params(first)["nonce"] != params(second)["nonce"]
    assert params(second)["expires"] - params(second)["created"] == 60
    assert params(second)["alg"] == "hmac-sha256"
    refute Map.has_key?(params(second), "keyid")
    refute Map.has_key?(params(second), "tag")
    Peer.finish(task)
  end

  test "short and full specs produce identical bytes with explicit metadata", %{handle: h} do
    {origin, task} = Peer.start([%{}, %{}], h)
    full = put_in(Peer.spec().parameters.nonce, nil)
    short = full |> Map.delete(:parameters) |> Map.merge(full.parameters)
    clock = fn -> 123 end

    sent =
      for spec <- [full, short] do
        assert {:ok, req} = request(origin, h, [], sign: spec, clock: clock)
        assert {:ok, _} = Req.request(req)
        assert_receive {:wire_request, message, {:ok, _}}
        message
      end

    assert Enum.at(sent, 0) == Enum.at(sent, 1)
    Peer.finish(task)

    request = Finch.build(:get, origin <> "/foo?param=Value", [{"accept", "text/plain"}])
    assert {:ok, full_request} = RequestSeal.Finch.sign(request, full, h, clock: clock)
    assert {:ok, short_request} = RequestSeal.Finch.sign(request, short, h, clock: clock)
    assert full_request == short_request
    {:ok, message} = RequestSeal.Finch.request_message(short_request)
    assert {:ok, _} = RequestSeal.verify(message, Peer.policy(Peer.components(), h), label: "sig")
  end

  test "minimal Finch specs generate fresh metadata and reject invalid defaults", %{handle: h} do
    request = Finch.build(:get, "https://example.com/")
    spec = %{label: "sig", algorithm: "hmac-sha256", components: ~s[("@method")], expires_in: 60}
    assert {:ok, first} = RequestSeal.Finch.sign(request, spec, h)
    assert {:ok, second} = RequestSeal.Finch.sign(request, spec, h)
    {:ok, first} = RequestSeal.Finch.request_message(first)
    {:ok, second} = RequestSeal.Finch.request_message(second)
    assert params(first)["nonce"] != params(second)["nonce"]
    assert params(second)["expires"] - params(second)["created"] == 60
    assert params(second)["alg"] == "hmac-sha256"
    refute Map.has_key?(params(second), "keyid")
    refute Map.has_key?(params(second), "tag")

    {:ok, policy} =
      RequestSeal.Policy.new(%{
        algorithms: ["hmac-sha256"],
        components: spec.components,
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: "hmac-sha256",
             key: fn _, base, sig ->
               RequestSeal.Custody.verify(h, base, sig)
             end
           }}
        end,
        freshness: :not_evaluated,
        content: :not_required,
        replay: :not_required
      })

    assert {:ok, _} = RequestSeal.verify(second, policy, label: "sig")

    for bad <- [
          Map.delete(spec, :expires_in),
          %{spec | expires_in: nil},
          Map.put(spec, :created, false),
          Map.put(spec, :nonce, "fixed"),
          Map.put(spec, :unknown, true)
        ] do
      assert {:error, %Error{reason: :invalid_options}} = RequestSeal.Finch.sign(request, bad, h)

      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.Req.attach(
                 Req.new(url: "https://example.com/"),
                 sign: bad,
                 signer: h,
                 verify: :none
               )
    end
  end

  test "final JSON and compressed bytes verify at the actual listener", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)

    assert {:ok, req} =
             request(origin, h, method: :post, json: %{"hello" => "world"}, compress_body: true)

    assert {:ok, response} = Req.request(req)
    assert response.body == Peer.body()
    assert {:ok, result} = RequestSeal.Req.verification(response)
    assert result.signature.crypto == :valid
    assert_receive {:wire_request, sent, {:ok, _}}
    assert :zlib.gunzip(sent.body.bytes) == Jason.encode!(%{"hello" => "world"})
    assert sent.raw_target == "/foo%2Fbar?param=Value&Pet=dog"
    assert for(f <- sent.fields, f.name == "accept", do: f.value) == ["text/plain", "*/*"]
    Peer.finish(task)
  end

  test "signing must remain the last request transformation", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h)
    req = Req.Request.append_request_steps(req, change_body: fn r -> %{r | body: Peer.body()} end)
    assert {:error, %Error{reason: :not_final_step}} = Req.request(req)
    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "retry signs each attempt with fresh nonce and no accumulated signature fields", %{
    handle: h
  } do
    {origin, task} = Peer.start([%{status: 503}, %{}], h)

    assert {:ok, req} =
             request(origin, h,
               retry: :transient,
               retry_delay: 0,
               max_retries: 1,
               retry_log_level: false
             )

    assert {:ok, response} = Req.request(req)
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive {:wire_request, first, {:ok, _}}
    assert_receive {:wire_request, second, {:ok, _}}
    assert params(first)["nonce"] != params(second)["nonce"]
    assert is_integer(params(first)["created"])
    assert is_integer(params(second)["created"])
    assert params(first)["created"] <= params(second)["created"]
    assert params(second)["expires"] - params(second)["created"] == 60
    assert byte_size(Base.url_decode64!(params(first)["nonce"], padding: false)) == 32
    input_field = Enum.find(second.fields, &(&1.name == "signature-input")).value
    [_, inner] = String.split(input_field, "=", parts: 2)
    {:ok, input} = SignatureFields.inner(inner)

    assert Enum.map(input.parameters, &elem(&1, 0)) == [
             "created",
             "expires",
             "nonce",
             "alg",
             "keyid"
           ]

    assert Enum.count(second.fields, &(&1.name == "signature-input")) == 1
    Peer.finish(task)
  end

  test "receive timeout retry signs again", %{handle: h} do
    {origin, task} = Peer.start([:timeout, %{}], h)

    assert {:ok, req} =
             request(origin, h,
               receive_timeout: 80,
               retry: :transient,
               retry_delay: 80,
               max_retries: 1,
               retry_log_level: false
             )

    assert {:ok, _} = Req.request(req)
    assert_receive {:wire_request, first, {:ok, _}}
    assert_receive {:wire_request, second, {:ok, _}}
    assert params(first)["nonce"] != params(second)["nonce"]
    assert Enum.count(second.fields, &(&1.name == "signature-input")) == 1
    Peer.finish(task)
  end

  test "same-origin redirect re-signs and associates only the final response", %{handle: h} do
    {origin, task} =
      Peer.start([%{status: 307, headers: [{"location", "/redirect?param=Value"}]}, %{}], h)

    assert {:ok, req} = request(origin, h, redirect_log_level: false)
    assert {:ok, response} = Req.request(req)
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive {:wire_request, first, {:ok, _}}
    assert_receive {:wire_request, second, {:ok, _}}
    assert first.raw_target != second.raw_target
    assert params(first)["nonce"] != params(second)["nonce"]
    Peer.finish(task)
  end

  test "cross-origin policy denies before connection and allowed redirects strip authorization",
       %{handle: h} do
    for allow <- [false, true] do
      {b, tb} = Peer.start([%{}], h)
      {a, ta} = Peer.start([%{status: 302, headers: [{"location", b <> "/foo?param=Value"}]}], h)
      opts = if allow, do: [redirect: {:allow, [b]}], else: []

      assert {:ok, req} =
               request(
                 a,
                 h,
                 [
                   headers: [
                     {"accept", "text/plain"},
                     {"authorization", "Bearer confidential-canary"}
                   ],
                   redirect_log_level: false,
                   redirect_trusted: true
                 ],
                 opts
               )

      if allow do
        assert {:ok, _} = Req.request(req)
        assert_receive {:wire_request, original, {:ok, _}}
        assert Enum.any?(original.fields, &(&1.name == "authorization"))
        assert_receive {:wire_request, sent, {:ok, _}}
        refute Enum.any?(sent.fields, &(&1.name == "authorization"))
      else
        assert {:error, %Error{reason: :cross_origin_redirect}} = Req.request(req)
        assert_receive {:wire_request, _, {:ok, _}}
        assert_receive :no_connection, 1_500
      end

      Peer.finish(ta)
      Peer.finish(tb)
    end
  end

  test "303 changes POST to GET with empty content digest", %{handle: h} do
    {origin, task} =
      Peer.start([%{status: 303, headers: [{"location", "/foo?param=Value"}]}, %{}], h)

    assert {:ok, req} =
             request(origin, h,
               method: :post,
               json: %{"hello" => "world"},
               redirect_log_level: false
             )

    assert {:ok, _} = Req.request(req)
    assert_receive {:wire_request, _, {:ok, _}}
    assert_receive {:wire_request, sent, {:ok, _}}
    assert sent.method == "GET"
    assert sent.body.bytes == ""
    Peer.finish(task)
  end

  test "retained request streams have a bound and are replayable on retry", %{handle: h} do
    {origin, task} = Peer.start([%{status: 503}, %{}], h)
    stream = Stream.map([Peer.body()], & &1)

    assert {:ok, req} =
             request(
               origin,
               h,
               [
                 method: :post,
                 body: stream,
                 retry: :transient,
                 retry_delay: 0,
                 retry_log_level: false
               ],
               request_body: {:retain, 100}
             )

    assert {:ok, _} = Req.request(req)
    assert_receive {:wire_request, first, {:ok, _}}
    assert_receive {:wire_request, second, {:ok, _}}
    assert first.body.bytes == second.body.bytes
    Peer.finish(task)
    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h, [body: stream], request_body: {:retain, 1})
    assert {:error, %Error{reason: :limit}} = Req.request(req)
    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "unsigned and tampered responses never release streamed chunks", %{handle: h} do
    owner = self()

    into = fn {:data, chunk}, {r, s} ->
      send(owner, {:delivered, chunk})
      {:cont, {r, %{s | body: s.body <> chunk}}}
    end

    for action <- [%{tamper: true}, %{unsigned: true}, %{}] do
      {origin, task} = Peer.start([action], h)
      assert {:ok, req} = request(origin, h, into: into)

      if action == %{} do
        assert {:ok, response} = Req.request(req)
        assert response.body == Peer.body()
        assert_receive {:delivered, bytes}
        assert bytes == Peer.body()
      else
        assert {:error, %Error{reason: :response_rejected}} = Req.request(req)
        refute_receive {:delivered, _}
      end

      assert_receive {:wire_request, _, {:ok, _}}
      Peer.finish(task)
    end
  end

  test "Finch actual request and stream preserve association and digest state", %{handle: h} do
    {origin, task} = Peer.start([%{}, %{trailers: true}], h)

    base =
      Finch.build(:post, origin <> "/foo?param=Value", [{"accept", "text/plain"}], [Peer.body()])

    assert {:ok, signed} = RequestSeal.Finch.sign(base, Peer.spec(), h)
    assert is_binary(signed.body)
    assert {:ok, response} = Finch.request(signed, __MODULE__.Pool)
    p = Peer.policy(Peer.response_components(), h)
    assert {:ok, _} = RequestSeal.Finch.verify(response, signed, p, label: "res")
    wrong = %{signed | path: "/wrong"}

    assert {:error, %Error{reason: :response_rejected}} =
             RequestSeal.Finch.verify(response, wrong, p, label: "res")

    assert {:ok, state} = Digest.init(:content, ["sha-256"])
    acc = {%Finch.Response{}, state}

    fun = fn
      {:status, v}, {r, d} ->
        {%{r | status: v}, d}

      {:headers, v}, {r, d} ->
        {%{r | headers: r.headers ++ v}, d}

      {:data, v}, {r, d} ->
        {:ok, d} = Digest.update(d, v)
        {r, d}

      {:trailers, v}, {r, d} ->
        {%{r | trailers: r.trailers ++ v}, d}
    end

    assert {:ok, signed} = RequestSeal.Finch.sign(base, Peer.spec(), h)
    assert {:ok, {r, d}} = Finch.stream(signed, __MODULE__.Pool, acc, fun, [])

    trailer_components =
      String.replace(Peer.response_components(), "\"content-digest\"", "\"content-digest\";tr")

    assert {:ok, _} =
             RequestSeal.Finch.verify(r, signed, Peer.policy(trailer_components, h, :trailers),
               label: "res",
               digest_state: d
             )

    assert_receive {:wire_request, _, {:ok, _}}
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "unsupported components and delivery fail with redacted errors", %{handle: h} do
    assert {:error, %Error{reason: :unsupported_delivery}} =
             RequestSeal.Req.attach(Req.new(into: :self),
               sign: Peer.spec(),
               signer: h,
               verify: :none
             )

    r =
      Finch.build(:get, "http://example.com/confidential-path?param=Value", [
        {"authorization", "Bearer confidential-canary"},
        {"host", "example.com"}
      ])

    for component <- [~s[("host")], ~s[("@method";req)], ~s[("content-digest";tr)]] do
      assert {:error, %Error{reason: :unsupported_component} = error} =
               RequestSeal.Finch.sign(r, Peer.spec(component), h)

      refute inspect(error) =~ "confidential"
      refute Exception.message(error) =~ "confidential"
    end

    assert {:error, %Error{reason: :unsupported_delivery}} =
             request("http://example.com", h, into: :self)

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(), sign: Peer.spec(), signer: h)
  end

  test "published Appendix B component sets reproduce independent bases", %{handle: h} do
    bases = :json.decode(File.read!(Path.join(__DIR__, "fixtures/signature_base/rfc9421.json")))
    vectors = :json.decode(File.read!(Path.join(__DIR__, "fixtures/verification/rfc9421.json")))

    for section <- ["B.2.1", "B.2.5"] do
      b = Enum.find(bases, &(&1["section"] == section))
      v = Enum.find(vectors, &(&1["section"] == section))

      key =
        if section == "B.2.1" do
          {:ok, key} =
            RequestSeal.Custody.Local.import(
              "rsa-pss-sha512",
              File.read!(Path.join(__DIR__, "fixtures/crypto/rsa_pss_private.pem")),
              :pem
            )

          key
        else
          h
        end

      {:ok, input} = SignatureFields.inner(b["parameters"])

      {:ok, components} =
        RequestSeal.StructuredFields.serialize(
          %RequestSeal.StructuredFields.Value{type: :list, value: [%{input | parameters: []}]},
          SignatureFields.schema(:list)
        )

      spec = %{
        Peer.spec(components)
        | algorithm: v["algorithm"],
          digest: nil,
          parameters: %{
            created: true,
            expires_in: nil,
            nonce: nil,
            alg: false,
            keyid: SignatureFields.parameters(input)["keyid"],
            tag: nil
          }
      }

      req =
        Finch.build(
          :post,
          "https://example.com" <> b["message"]["raw_target"],
          Enum.map(b["message"]["fields"], fn [k, v] -> {k, v} end),
          Peer.body()
        )

      assert {:ok, signed} =
               RequestSeal.Finch.sign(req, spec, key, clock: fn -> 1_618_884_473 end)

      assert {:ok, message} = RequestSeal.Finch.request_message(signed)

      field =
        Enum.find(signed.headers, fn {name, _} -> String.downcase(name) == "signature-input" end)
        |> elem(1)

      [_, inner] = String.split(field, "=", parts: 2)
      assert {:ok, base} = RequestSeal.SignatureBase.build(message, inner)
      expected = Regex.replace(~r/;nonce="[^"]+"/, b["base"], "")
      assert base == expected

      if section == "B.2.5" do
        assert List.keyfind(signed.headers, "Signature", 0) |> elem(1) ==
                 String.replace(v["signature"], v["label"] <> "=", "sig=")
      end
    end
  end

  test "a tampered outbound body reaches real verification as digest mismatch", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)

    req =
      Finch.build(:post, origin <> "/foo?param=Value", [{"accept", "text/plain"}], Peer.body())

    assert {:ok, signed} = RequestSeal.Finch.sign(req, Peer.spec(), h)
    tampered = %{signed | body: String.replace(Peer.body(), "world", "earth")}
    assert {:ok, _} = Finch.request(tampered, __MODULE__.Pool)
    assert_receive {:wire_request, _, {:error, %RequestSeal.Error{reason: :digest_mismatch}}}
    Peer.finish(task)
  end

  test "verification runs once even if a later step invokes it again", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    p = Peer.policy(Peer.response_components(), h, :headers, self())

    assert {:ok, req} =
             request(origin, h, [], verify: %{policy: p, label: "res", max_stream_bytes: 100})

    req =
      Req.Request.append_response_steps(req,
        repeated_verification: &RequestSeal.Req.verify_response/1
      )

    assert {:ok, response} = Req.request(req)
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive :resolved
    refute_receive :resolved
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "Req verifies actual chunked trailers before collection", %{handle: h} do
    {origin, task} = Peer.start([%{trailers: true}], h)

    components =
      String.replace(Peer.response_components(), "\"content-digest\"", "\"content-digest\";tr")

    p = Peer.policy(components, h, :trailers)

    assert {:ok, req} =
             request(origin, h, [into: ""],
               verify: %{policy: p, label: "res", max_stream_bytes: 100}
             )

    assert {:ok, response} = Req.request(req)
    assert response.body == Peer.body()
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "stream retention overflow rejects without opening the collectable", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)

    file =
      Path.join(
        System.tmp_dir!(),
        "req-collect-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    on_exit(fn -> File.rm(file) end)
    p = Peer.policy(Peer.response_components(), h)

    assert {:ok, req} =
             request(origin, h, [into: File.stream!(file)],
               verify: %{policy: p, label: "res", max_stream_bytes: 1}
             )

    assert {:error, %Error{reason: :limit}} = Req.request(req)
    refute File.exists?(file)
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "invalid final unsigned non-success responses fail closed", %{handle: h} do
    {origin, task} = Peer.start([%{status: 503, unsigned: true}], h)
    assert {:ok, req} = request(origin, h)

    assert {:error,
            %Error{
              reason: :response_rejected,
              source: %RequestSeal.Error{reason: :missing_signature_input}
            }} = Req.request(req)

    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "changed verification order and changed adapter refuse before transport", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h)
    steps = Enum.reject(req.response_steps, fn {name, _} -> name == :request_seal_verify end)

    assert {:error, %Error{reason: :unsupported_delivery}} =
             Req.request(%{req | response_steps: steps})

    assert {:error, %Error{reason: :unsupported_delivery}} =
             Req.request(%{req | adapter: Req.Steps})

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(req, sign: Peer.spec(), signer: h, verify: :none)

    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "final values, option sets, timestamps, lengths and digest conflicts reject safely", %{
    handle: h
  } do
    r =
      Finch.build(
        :post,
        "http://example.com/confidential-path?param=Value",
        [{"accept", "text/plain"}],
        Peer.body()
      )

    for opts <- [
          [unknown: true],
          [clock: false],
          [signing_timeout: 0],
          [signing_timeout: 300_001],
          [body: {:retain, -1}],
          [body: :bad],
          [clock: fn -> :invalid end],
          [clock: fn -> 999_999_999_999_999 end],
          [clock: fn -> -1_000_000_000_000_000 end],
          [body: :as_is, body: :as_is]
        ] do
      assert {:error, %Error{reason: :invalid_options} = e} =
               RequestSeal.Finch.sign(r, Peer.spec(), h, opts)

      refute inspect(e) =~ "confidential"
      refute Exception.message(e) =~ "confidential"
    end

    for spec <- [
          Map.delete(Peer.spec(), :label),
          %{Peer.spec() | label: "BAD"},
          %{Peer.spec() | algorithm: "bad"},
          %{Peer.spec() | components: "bad"},
          %{Peer.spec() | components: "();created=1"},
          %{Peer.spec() | digest: ["sha-256", "sha-256"]},
          %{Peer.spec() | field_schemas: %{not_valid: true}},
          %{Peer.spec() | parameters: %{Peer.spec().parameters | created: false}},
          %{
            Peer.spec()
            | parameters: %{Peer.spec().parameters | keyid: String.duplicate("x", 1025)}
          },
          %{Peer.spec() | parameters: Map.put(Peer.spec().parameters, :unknown, true)}
        ] do
      assert {:error, %Error{reason: :invalid_options}} = RequestSeal.Finch.sign(r, spec, h)
    end

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Finch.sign(r, Peer.spec(), :not_a_signer)

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.request_message(:invalid)

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.request_message(%{r | port: 0})

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.request_message(%{r | path: "/confidential\npath"})

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.request_message(%{r | body: :invalid})

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.sign(
               %{r | headers: r.headers ++ [{"content-length", "1"}]},
               Peer.spec(),
               h
             )

    assert {:error, %Error{reason: :digest_conflict}} =
             RequestSeal.Finch.sign(
               %{r | headers: r.headers ++ [{"content-digest", Peer.digest("")}]},
               Peer.spec(),
               h
             )

    stream = %{r | body: {:stream, Stream.map([Peer.body()], & &1)}}

    assert {:error, %Error{reason: :body_unavailable}} =
             RequestSeal.Finch.sign(stream, Peer.spec(), h)

    assert {:ok, signed} = RequestSeal.Finch.sign(r, Peer.spec(), h)

    assert {:error,
            %Error{reason: :signing_failed, source: %RequestSeal.Error{reason: :label_in_use}}} =
             RequestSeal.Finch.sign(signed, Peer.spec(), h)

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Finch.response_message(%Finch.Response{}, r, body: :invalid)

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Finch.verify(
               %Finch.Response{},
               r,
               Peer.policy(Peer.response_components(), h),
               unexpected: true
             )

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.response_message(:invalid, r)

    assert {:ok, message} =
             RequestSeal.Finch.response_message(%Finch.Response{status: 200}, r, body: :consumed)

    assert message.body.state == :consumed

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(),
               sign: Peer.spec(),
               signer: h,
               verify: :none,
               unknown: true
             )

    for redirect <- [
          :bad,
          {:allow, ["http://example.com/path"]},
          {:allow, ["file:///foo"]},
          {:allow, ["http://secret@example.com"]},
          {:allow, [123]}
        ] do
      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.Req.attach(Req.new(),
                 sign: Peer.spec(),
                 signer: h,
                 verify: :none,
                 redirect: redirect
               )
    end

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(),
               sign: Peer.spec(),
               signer: h,
               verify: %{policy: :bad, label: "res", max_stream_bytes: 1}
             )

    assert {:error, %Error{reason: :unsupported_delivery}} =
             request("http://example.com", h, into: "", checksum: "sha256:0")

    assert {:error, %Error{reason: :unsupported_delivery}} =
             request("http://example.com", h, [into: ""],
               verify: %{
                 policy: Peer.policy(Peer.response_components(), h),
                 label: "res",
                 max_stream_bytes: nil
               }
             )

    assert {:ok, req} = request("relative/confidential-path", h)
    assert {:error, %Error{reason: :invalid_request} = e} = Req.request(req)
    refute inspect(e) =~ "confidential"
    refute Exception.message(e) =~ "confidential"
  end

  test "stopped real OpenSSH agent deadline prevents any HTTP connection", %{handle: h} do
    dir =
      Path.join(
        System.tmp_dir!(),
        "req-agent-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir!(dir)
    File.chmod!(dir, 0o700)
    socket = Path.join(dir, "agent")
    {output, 0} = System.cmd("ssh-agent", ["-a", socket, "-s"], stderr_to_stdout: true)
    [_, pid] = Regex.run(~r/SSH_AGENT_PID=(\d+);/, output)

    on_exit(fn ->
      System.cmd("kill", ["-CONT", pid], stderr_to_stdout: true)
      System.cmd("kill", ["-TERM", pid], stderr_to_stdout: true)
      File.rm_rf!(dir)
    end)

    env = [{"SSH_AUTH_SOCK", socket}, {"SSH_AGENT_PID", pid}]
    file = write_agent_key(dir)
    assert {_, 0} = System.cmd("ssh-add", [file], env: env, stderr_to_stdout: true)

    assert {:ok, public} =
             RequestSeal.PublicKey.import(
               File.read!(Path.join(__DIR__, "fixtures/crypto/ed25519_public.pem")),
               :pem
             )

    assert {:ok, handle} = RequestSeal.Custody.SSHAgent.new("ed25519", socket, public)
    assert {_, 0} = System.cmd("kill", ["-STOP", pid])
    {origin, task} = Peer.start([%{}], h)

    req =
      Req.new(url: origin <> "/confidential-path", finch: [name: __MODULE__.Pool], retry: false)

    assert {:ok, req} =
             RequestSeal.Req.attach(req,
               sign: %{Peer.spec("()") | algorithm: "ed25519", digest: nil},
               signer: handle,
               signing_timeout: 60,
               verify: :none
             )

    started = System.monotonic_time(:millisecond)

    assert {:error,
            %Error{
              reason: :signing_failed,
              source: %RequestSeal.Custody.Error{reason: :deadline_exceeded}
            }} = Req.request(req)

    assert System.monotonic_time(:millisecond) - started < 1_000

    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  defp write_agent_key(dir) do
    [entry] =
      :public_key.pem_decode(
        File.read!(Path.join(__DIR__, "fixtures/crypto/ed25519_private.pem"))
      )

    {:ECPrivateKey, _, seed, _, _, _} = :public_key.pem_entry_decode(entry)
    {public, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    str = fn bytes -> <<byte_size(bytes)::32, bytes::binary>> end
    blob = str.("ssh-ed25519") <> str.(public)
    <<check::32>> = :crypto.strong_rand_bytes(4)

    private =
      <<check::32, check::32>> <>
        str.("ssh-ed25519") <>
        str.(public) <> str.(seed <> public) <> str.("RFC 9421 published test key")

    padding = 8 - rem(byte_size(private), 8)
    private = private <> :binary.list_to_bin(Enum.to_list(1..padding))

    encoded =
      "openssh-key-v1\0" <>
        str.("none") <> str.("none") <> str.("") <> <<1::32>> <> str.(blob) <> str.(private)

    file = Path.join(dir, "rfc-ed25519")

    File.write!(
      file,
      "-----BEGIN OPENSSH " <>
        "PRIVATE KEY-----\n" <> Base.encode64(encoded) <> "\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    File.chmod!(file, 0o600)
    file
  end

  test "Req body functions retain finalized bytes before signing", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)

    body = fn r ->
      if Req.Request.get_private(r, :body_emitted, false) do
        {:done, r}
      else
        {:data, Peer.body(), Req.Request.put_private(r, :body_emitted, true)}
      end
    end

    assert {:ok, req} =
             request(origin, h, [method: :post, body: body], request_body: {:retain, 100})

    assert {:ok, _} = Req.request(req)
    assert_receive {:wire_request, sent, {:ok, _}}
    assert sent.body.bytes == Peer.body()
    Peer.finish(task)
    assert {:ok, req} = request(origin, h, [body: body], request_body: {:retain, 1})
    assert {:error, %Error{reason: :limit}} = Req.request(req)
  end

  test "body retention bounds apply even when digest checking is not required", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    p = %{Peer.policy(Peer.response_components(), h) | content: :not_required}

    assert {:ok, req} =
             request(origin, h, [into: ""],
               verify: %{policy: p, label: "res", max_stream_bytes: 1}
             )

    assert {:error, %Error{reason: :limit}} = Req.request(req)
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "the base application does not own or start optional HTTP clients" do
    assert :crypto in Application.spec(:request_seal, :applications)
    refute :req in Application.spec(:request_seal, :applications)
    refute :finch in Application.spec(:request_seal, :applications)
    refute Enum.any?(Application.started_applications(), fn {a, _, _} -> a in [:req, :finch] end)
  end

  test "verified delivery rejects framework paths that expose bodies before verification", %{
    handle: h
  } do
    assert {:error, %Error{reason: :unsupported_delivery}} =
             request("http://example.com", h, http_errors: :raise)

    assert {:error, %Error{reason: :unsupported_delivery}} =
             request("http://example.com", h, cache: true)

    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h)

    req =
      Req.Request.prepend_response_steps(req,
        consume_body: fn {r, s} -> {r, %{s | body: :consumed}} end
      )

    assert {:error, %Error{reason: :unsupported_delivery}} = Req.request(req)
    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "retaining a body function cannot replace the signed transport", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    fun = fn r -> {:done, %{r | adapter: Req.Steps}} end

    assert {:ok, req} =
             request(origin, h, [body: fun], request_body: {:retain, 100})

    assert {:error, %Error{reason: :unsupported_delivery}} = Req.request(req)
    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "runtime stream destination is wrapped and released after verification", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    owner = self()

    into = fn {:data, chunk}, {r, response} ->
      assert {:ok, _} = RequestSeal.Req.verification(response)
      send(owner, {:runtime_destination, chunk})
      {:cont, {r, response}}
    end

    assert {:ok, req} = request(origin, h)
    assert {:ok, _} = Req.request(req, into: into)
    assert_receive {:runtime_destination, bytes}
    assert bytes == Peer.body()
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "a mismatched real key handle rejects before signing", %{handle: h} do
    {:ok, other} =
      RequestSeal.Custody.Local.import(
        "ed25519",
        File.read!(Path.join(__DIR__, "fixtures/crypto/ed25519_private.pem")),
        :pem
      )

    r = Finch.build(:get, "http://example.com/foo?param=Value", [{"accept", "text/plain"}])

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Finch.sign(r, Peer.spec(), other)

    assert {:ok, _} =
             RequestSeal.Finch.sign(r, Peer.spec(), fn alg, base ->
               assert alg == h.algorithm
               RequestSeal.Custody.sign(h, base)
             end)
  end

  test "caller-owned digest fields are preserved and all adapter errors redact sensitive input",
       %{handle: h} do
    r =
      Finch.build(:get, "http://example.com/confidential-path?param=Value", [
        {"accept", "text/plain"},
        {"authorization", "Bearer confidential-canary"},
        {"content-digest", Peer.digest("")}
      ])

    assert {:ok, signed} = RequestSeal.Finch.sign(r, Peer.spec(), h)

    assert Enum.count(signed.headers, fn {k, _} -> String.downcase(k) == "content-digest" end) ==
             1

    reasons = [
      :invalid_options,
      :invalid_request,
      :not_final_step,
      :cross_origin_redirect,
      :unsupported_delivery,
      :unsupported_component,
      :body_unavailable,
      :digest_conflict,
      :limit,
      :signing_failed,
      :response_rejected
    ]

    for reason <- reasons do
      e = Error.new(reason, :req, :sign, 1)
      assert Regex.match?(~r/^[a-f0-9]{16}$/, e.correlation)
      assert Exception.message(e) == "#{reason} (#{e.correlation})"
      refute inspect(e) =~ "confidential"
      refute Exception.message(e) =~ "confidential"
    end

    assert :error = RequestSeal.Req.verification(Req.Response.new())
    {origin, task} = Peer.start([%{}], h)

    secret_id = %{
      Peer.spec()
      | parameters: %{Peer.spec().parameters | keyid: "confidential-keyid"}
    }

    assert {:ok, req} = request(origin <> "/confidential-path", h, [], sign: secret_id)
    {sent_request, %Req.Response{}} = Req.Request.run_request(req)
    refute inspect(sent_request.private) =~ "confidential"
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "encoded responses are verified before decompression and JSON parsing", %{handle: h} do
    {origin, task} = Peer.start([%{gzip: true}], h)
    assert {:ok, req} = request(origin, h, compressed: true, decode_body: true)
    assert {:ok, response} = Req.request(req)
    assert response.body == %{"hello" => "world"}
    assert {:ok, result} = RequestSeal.Req.verification(response)
    assert result.content.bytes == byte_size(:zlib.gzip(Peer.body()))
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  test "retention halts a body producer at the first oversized chunk", %{handle: h} do
    owner = self()

    producer = fn r ->
      send(owner, :body_read)

      if r.private[:content_read],
        do: {:done, r},
        else: {:data, Peer.body(), Req.Request.put_private(r, :content_read, true)}
    end

    assert {:ok, req} =
             request("http://example.com", h, [body: producer], request_body: {:retain, 1})

    assert {:error, %Error{reason: :limit}} = Req.request(req)
    assert_receive :body_read
    refute_receive :body_read
    r = Finch.build(:get, "http://example.com", [], [Peer.body()])

    assert {:error, %Error{reason: :limit}} =
             RequestSeal.Finch.sign(r, Peer.spec("()"), h, body: {:retain, 1})

    assert {:error, %Error{reason: :body_unavailable}} =
             RequestSeal.Finch.response_message(%Finch.Response{status: 200, body: nil}, %{
               r
               | body: nil
             })

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Finch.request_message(%{r | headers: %{}})
  end

  test "Finch emits the same target the adapter signs for an empty query", %{handle: h} do
    components = ~s[("@method" "@target-uri" "content-digest" "content-length")]
    {origin, task} = Peer.start([%{}], h, components)
    r = Finch.build(:get, origin <> "/foo?")
    assert {:ok, signed} = RequestSeal.Finch.sign(r, Peer.spec(components), h)
    assert {:ok, _} = Finch.request(signed, __MODULE__.Pool)
    assert_receive {:wire_request, sent, {:ok, _}}
    assert sent.raw_target == "/foo"
    Peer.finish(task)
  end

  test "malformed option containers, verification choices and clocks have bounded rejection", %{
    handle: h
  } do
    r = Finch.build(:get, "http://example.com/foo?param=Value", [{"accept", "text/plain"}])
    spec = %{Peer.spec() | parameters: %{Peer.spec().parameters | expires_in: nil}}

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Finch.sign(r, spec, h, clock: fn -> nil end)

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Finch.sign(r, Peer.spec(), h, :invalid)

    assert {:error, %Error{reason: :invalid_request}} =
             RequestSeal.Req.attach(:invalid, sign: Peer.spec(), signer: h, verify: :none)

    p = Peer.policy(Peer.response_components(), h)

    for verify <- [
          %{policy: p, label: "BAD", max_stream_bytes: 1},
          %{policy: p, label: "res", max_stream_bytes: -1},
          %{policy: p, label: "res", max_stream_bytes: 1, unknown: true},
          :bad
        ] do
      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.Req.attach(Req.new(), sign: Peer.spec(), signer: h, verify: verify)
    end

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(), sign: Peer.spec(), signer: :invalid, verify: :none)

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(),
               sign: Peer.spec(),
               signer: h,
               verify: :none,
               redirect: {:allow, List.duplicate("https://example.com", 65)}
             )

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(),
               sign: Peer.spec(),
               signer: h,
               verify: :none,
               redirect: {:allow, ["https://" <> String.duplicate("x", 2050) <> ".com"]}
             )

    req = Req.new()

    assert {:error, %Error{reason: :unsupported_delivery}} =
             RequestSeal.Req.attach(%{req | response_steps: []},
               sign: Peer.spec(),
               signer: h,
               verify: :none
             )

    assert {:error, %Error{reason: :unsupported_delivery}} =
             RequestSeal.Req.attach(%{req | into: :invalid},
               sign: Peer.spec(),
               signer: h,
               verify: %{policy: p, label: "res", max_stream_bytes: 100}
             )

    assert {:error, %Error{reason: :invalid_options}} =
             RequestSeal.Req.attach(
               Req.new(finch_request: fn req -> %{req | body: Peer.body()} end),
               sign: Peer.spec(),
               signer: h,
               verify: :none
             )
  end

  test "unavailable stream content cannot acquire body coverage from a caller digest", %{
    handle: h
  } do
    r =
      Finch.build(
        :post,
        "http://example.com",
        [{"content-digest", Peer.digest(Peer.body())}],
        {:stream, Stream.map([Peer.body()], & &1)}
      )

    spec = %{Peer.spec(~s[("content-digest")]) | digest: nil}
    assert {:error, %Error{reason: :body_unavailable}} = RequestSeal.Finch.sign(r, spec, h)
    function_stream = %{r | body: {:stream, fn acc -> {:done, acc} end}}

    assert {:error, %Error{reason: :body_unavailable}} =
             RequestSeal.Finch.sign(function_stream, spec, h, body: {:retain, 100})
  end

  test "caller callback exceptions and throws after real cryptography stay redacted", %{handle: h} do
    r = Finch.build(:get, "http://example.com/confidential-path")

    for mode <- [:raise, :throw] do
      signer = fn _, base ->
        {:ok, _} = RequestSeal.Custody.sign(h, base)
        if mode == :raise, do: raise("confidential-canary"), else: throw("confidential-canary")
      end

      assert {:error, %Error{reason: :signing_failed} = error} =
               RequestSeal.Finch.sign(r, %{Peer.spec("()") | digest: nil}, signer)

      refute inspect(error) =~ "confidential"
      refute Exception.message(error) =~ "confidential"
    end
  end

  test "a matching caller digest with legal whitespace keeps its wire value", %{handle: h} do
    wire = " " <> Peer.digest(Peer.body()) <> " "
    r = Finch.build(:post, "http://example.com", [{"content-digest", wire}], Peer.body())
    assert {:ok, signed} = RequestSeal.Finch.sign(r, Peer.spec(~s[("content-digest")]), h)
    assert List.keyfind(signed.headers, "content-digest", 0) == {"content-digest", wire}
  end

  test "caller digests cannot change the selected computation algorithms", %{handle: h} do
    {:ok, value} = Digest.compute(Peer.retained(Peer.body()), ["sha-512"])
    {:ok, wire} = Digest.serialize(value)
    r = Finch.build(:post, "http://example.com", [{"content-digest", wire}], Peer.body())

    assert {:error, %Error{reason: :digest_conflict}} =
             RequestSeal.Finch.sign(r, Peer.spec(~s[("content-digest")]), h)
  end

  test "automatic streaming cannot substitute content for caller-selected representation", %{
    handle: h
  } do
    {origin, task} = Peer.start([%{}], h)

    p = %{
      Peer.policy(~s[("repr-digest")], h)
      | content: %{kind: :representation, algorithms: ["sha-256"], section: :headers}
    }

    assert {:error, %Error{reason: :unsupported_component}} =
             request(origin, h, [into: ""],
               verify: %{policy: p, label: "res", max_stream_bytes: 100}
             )

    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "parser and signature base resource ceilings keep the adapter limit reason", %{handle: h} do
    r = Finch.build(:get, "http://example.com")
    spec = Peer.spec("(" <> String.duplicate(" ", 70_000) <> ")")
    assert {:error, %Error{reason: :limit}} = RequestSeal.Finch.sign(r, spec, h)
    headers = Enum.map(1..16, fn n -> {"x" <> to_string(n), String.duplicate("a", 65_530)} end)
    r = %{r | headers: headers}
    assert {:ok, message} = RequestSeal.Finch.request_message(r)

    components =
      "(" <> Enum.map_join(headers, " ", fn {name, _} -> "\"" <> name <> "\"" end) <> ")"

    assert {:error, %{reason: :limit}} = RequestSeal.SignatureBase.build(message, components)

    assert {:error, %Error{reason: :limit}} =
             RequestSeal.Finch.sign(r, %{Peer.spec(components) | digest: nil}, h)
  end

  for {key, value} <- [
        connect_options: [hostname: "other.example"],
        connect_options: [proxy: {:http, "127.0.0.1", 1, []}],
        connect_options: [transport_opts: [verify: :verify_none]],
        proxy: "http://127.0.0.1:1",
        unix_socket: "/invalid/socket",
        finch: [conn_opts: [hostname: "other.example"]],
        finch: [name: __MODULE__.Pool, unix_socket: "/invalid/socket"],
        finch_private: %{canary: true},
        aws_sigv4: [access_key_id: "canary", secret_access_key: "canary"],
        auth: {:digest, "user:password"},
        inet6: true,
        pool_max_idle_time: 10,
        protocols: [:http2],
        plug: :invalid,
        finch_request: :invalid
      ] do
    @tag :finding
    test "F1 rejects #{key} #{inspect(value)}", %{handle: h} do
      {origin, task} = Peer.start([%{}], h)
      assert {:ok, req} = request(origin, h)
      req = %{req | options: Map.put(req.options, unquote(key), unquote(Macro.escape(value)))}
      assert {:error, %Error{reason: :invalid_options}} = Req.request(req)
      assert_receive :no_connection, 1_500
      Peer.finish(task)
    end
  end

  for status <- [307, 503] do
    @tag :finding
    test "F2 unsigned #{status} cannot redirect or retry", %{handle: h} do
      status = unquote(status)

      {origin, task} =
        Peer.start(
          [
            %{status: status, unsigned: true, headers: [{"location", "/attacker?param=Value"}]},
            %{}
          ],
          h
        )

      assert {:ok, req} =
               request(origin, h,
                 method: :post,
                 body: Peer.body(),
                 retry: :transient,
                 retry_delay: 0,
                 max_retries: 1,
                 retry_log_level: false,
                 redirect_log_level: false
               )

      result = Req.request(req)
      assert_receive {:wire_request, _, {:ok, _}}
      assert {:error, %Error{reason: :response_rejected}} = result
      assert_receive :no_connection, 1_500
      refute_receive {:wire_request, _, _}
      Peer.finish(task)
    end
  end

  @tag :finding
  test "F3 allowed cross-origin redirects strip all declared credentials", %{handle: h} do
    {b, tb} = Peer.start([%{}], h)
    {a, ta} = Peer.start([%{status: 307, headers: [{"location", b <> "/foo?param=Value"}]}], h)
    credentials = ["authorization", "cookie", "proxy-authorization", "x-api-key"]

    assert {:ok, req} =
             request(
               a,
               h,
               [
                 headers: [{"accept", "text/plain"} | Enum.map(credentials, &{&1, "canary"})],
                 redirect_trusted: true,
                 redirect_log_level: false
               ],
               redirect: {:allow, [b]},
               credential_headers: ["X-API-Key"]
             )

    assert {:ok, _} = Req.request(req)
    assert_receive {:wire_request, first, {:ok, _}}
    assert Enum.all?(credentials, fn name -> Enum.any?(first.fields, &(&1.name == name)) end)
    assert_receive {:wire_request, second, {:ok, _}}
    refute Enum.any?(second.fields, &(&1.name in credentials))
    Peer.finish(ta)
    Peer.finish(tb)
  end

  @tag :finding
  test "F4 synchronous verified responses stop at the bound before EOF", %{handle: h} do
    {origin, task} = Peer.start([%{body: String.duplicate("x", 100), missing_tail: 100}], h)

    assert {:ok, req} =
             request(origin, h, [receive_timeout: 500],
               verify: %{
                 policy: Peer.policy(Peer.response_components(), h),
                 label: "res",
                 max_stream_bytes: 10
               }
             )

    assert {:error, %Error{reason: :limit}} = Req.request(req)
    assert_receive {:wire_request, _, {:ok, _}}
    assert_receive {:peer_closed, {:error, :closed}}, 1_000
    Peer.finish(task)
  end

  @tag :finding
  test "F5 function signer deadline terminates its worker", %{handle: h} do
    owner = self()

    signer = fn _, base ->
      {:links, links} = Process.info(self(), :links)
      send(owner, {:signer, self(), links})
      Process.sleep(200)
      RequestSeal.Custody.sign(h, base)
    end

    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h, [], signer: signer, signing_timeout: 30)
    result = Req.request(req)
    assert_receive {:signer, worker, guardians}

    assert {:error,
            %Error{
              reason: :signing_failed,
              source: %RequestSeal.Custody.Error{reason: :deadline_exceeded}
            }} = result

    refute Process.alive?(worker)

    for guardian <- guardians do
      ref = Process.monitor(guardian)
      assert_receive {:DOWN, ^ref, :process, ^guardian, _}, 1_000
    end

    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  @tag :finding
  test "F6 caller death closes held sockets and leaves no late signed request or worker", %{
    handle: h
  } do
    {origin, task} = Peer.start([%{}, :hold, %{}], h)
    assert {:ok, req} = request(origin, h)
    assert {:ok, _} = Req.request(req)
    assert_receive {:wire_request, _, {:ok, _}}
    baseline = MapSet.new(Process.list())
    port = URI.parse(origin).port
    assert client_socket_count(port) == 0
    {caller, ref} = spawn_monitor(fn -> Req.request(req) end)
    assert_receive {:wire_request, _, {:ok, _}}
    assert_receive {:holding, _}
    assert client_socket_count(port) == 1
    assert MapSet.member?(MapSet.difference(MapSet.new(Process.list()), baseline), caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^ref, :process, ^caller, :killed}
    assert_receive {:peer_closed, {:error, :closed}}, 1_000
    assert_receive :no_connection, 1_500
    refute_receive {:wire_request, _, _}
    assert client_socket_count(port) == 0
    assert MapSet.difference(MapSet.new(Process.list()), baseline) == MapSet.new()
    Peer.finish(task)
  end

  @tag :finding
  test "F7 halted adapter errors bypass every retry choice", %{handle: h} do
    owner = self()

    for retry <- [
          false,
          :transient,
          :safe_transient,
          fn
            _, %Error{} ->
              send(owner, :retry_called)
              true

            _, _ ->
              false
          end
        ] do
      {b, tb} = Peer.start([%{}], h)
      {a, ta} = Peer.start([%{status: 307, headers: [{"location", b <> "/foo?param=Value"}]}], h)

      assert {:ok, req} =
               request(a, h,
                 retry: retry,
                 retry_delay: 0,
                 max_retries: 1,
                 retry_log_level: false,
                 redirect_log_level: false
               )

      assert {:error, %Error{reason: :cross_origin_redirect, attempt: 2}} = Req.request(req)
      assert_receive {:wire_request, _, {:ok, _}}
      # Only policy errors trigger this retry callback; ordinary responses do not.
      refute_receive :retry_called
      assert_receive :no_connection, 1_500
      Peer.finish(ta)
      Peer.finish(tb)
    end
  end

  @tag :finding
  test "F5 caller death cancels an in-flight function signer before transport", %{handle: h} do
    owner = self()

    signer = fn _, base ->
      {:links, links} = Process.info(self(), :links)
      send(owner, {:signer_started, self(), links})

      receive do
        :release -> RequestSeal.Custody.sign(h, base)
      end
    end

    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h, [], signer: signer)
    {caller, caller_ref} = spawn_monitor(fn -> Req.request(req) end)
    assert_receive {:signer_started, worker, guardians}
    worker_ref = Process.monitor(worker)
    guardian_refs = Enum.map(guardians, &{&1, Process.monitor(&1)})
    assert Process.alive?(worker)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^caller_ref, :process, ^caller, :killed}
    assert_receive {:DOWN, ^worker_ref, :process, ^worker, :killed}, 1_000

    for {guardian, ref} <- guardian_refs do
      assert_receive {:DOWN, ^ref, :process, ^guardian, _}, 1_000
    end

    send(worker, :release)
    assert_receive :no_connection, 1_500
    refute_receive {:wire_request, _, _}
    assert client_socket_count(URI.parse(origin).port) == 0
    Peer.finish(task)
  end

  @tag :finding
  test "F7 response rejection and collection overflow never invoke custom retries", %{handle: h} do
    owner = self()

    retry = fn _, _ ->
      send(owner, :retry_called)
      true
    end

    for {action, max, reason} <- [{%{unsigned: true}, 100, :response_rejected}, {%{}, 1, :limit}] do
      {origin, task} = Peer.start([action, %{}], h)

      assert {:ok, req} =
               request(origin, h, [retry: retry, retry_delay: 0, max_retries: 1],
                 verify: %{
                   policy: Peer.policy(Peer.response_components(), h),
                   label: "res",
                   max_stream_bytes: max
                 }
               )

      assert {:error, %Error{reason: ^reason, attempt: 1}} = Req.request(req)
      assert_receive {:wire_request, _, {:ok, _}}
      assert_receive :no_connection, 1_500
      refute_receive :retry_called
      refute_receive {:wire_request, _, _}
      Peer.finish(task)
    end
  end

  @tag :collector_retry
  test "bounded synchronous collection preserves checksum across a transport retry", %{handle: h} do
    {origin, task} = Peer.start([:timeout, %{}], h)
    checksum = "sha256:" <> Base.encode16(:crypto.hash(:sha256, Peer.body()), case: :lower)

    assert {:ok, req} =
             request(origin, h,
               checksum: checksum,
               receive_timeout: 80,
               retry: :transient,
               retry_delay: 80,
               max_retries: 1,
               retry_log_level: false
             )

    assert {:ok, response} = Req.request(req)
    assert response.body == Peer.body()
    assert {:ok, _} = RequestSeal.Req.verification(response)
    assert_receive {:wire_request, _, {:ok, _}}
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  @tag :unverified_order
  test "explicit verify none preserves Req response hooks before decompression", %{handle: h} do
    {origin, task} = Peer.start([%{}], h)
    assert {:ok, req} = request(origin, h, [], verify: :none)
    owner = self()

    req =
      Req.Request.prepend_response_steps(req,
        observe: fn {r, response} ->
          send(owner, :observed_response)
          {r, response}
        end
      )

    assert {:ok, response} = Req.request(req)
    assert response.body == Peer.body()
    assert_receive :observed_response
    assert_receive {:wire_request, _, {:ok, _}}
    Peer.finish(task)
  end

  defp client_socket_count(port) do
    Enum.count(:erlang.ports(), fn socket ->
      case :inet.peername(socket) do
        {:ok, {{127, 0, 0, 1}, ^port}} -> true
        _ -> false
      end
    end)
  end

  defp params(message) do
    value = Enum.find(message.fields, &(String.downcase(&1.name) == "signature-input")).value
    [_, inner] = String.split(value, "=", parts: 2)
    {:ok, input} = SignatureFields.inner(inner)
    SignatureFields.parameters(input)
  end
end
