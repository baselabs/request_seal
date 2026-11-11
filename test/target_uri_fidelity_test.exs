defmodule RequestSeal.TargetURIFidelityTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Crypto, FieldOccurrence, Message, Policy, PublicKey, SignatureBase}

  @components ~s[("@target-uri" "@authority")]

  defmodule WireVerifier do
    @moduledoc false
    def init(options), do: options

    def call(conn, {owner, key, components}) do
      [authority] = Plug.Conn.get_req_header(conn, "host")
      target = conn.request_path <> "?" <> conn.query_string

      {:ok, message} =
        Message.new(%{
          kind: :request,
          method: conn.method,
          scheme: "http",
          authority: authority,
          raw_target: target,
          target_form: :origin,
          fields:
            Enum.map(conn.req_headers, fn {name, value} ->
              %FieldOccurrence{name: name, value: value, section: :headers}
            end),
          trailers: :unavailable,
          body: %RequestSeal.Body{state: :retained, bytes: ""},
          transport: %RequestSeal.TransportFacts{}
        })

      {:ok, policy} =
        Policy.new(%{
          algorithms: ["ed25519"],
          components: components,
          key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
          freshness: :not_evaluated,
          content: :not_required,
          replay: :not_required
        })

      result = RequestSeal.verify(message, policy, label: "sig")
      send(owner, {:wire_verified, message, result})
      Plug.Conn.send_resp(conn, if(match?({:ok, _}, result), do: 204, else: 401), "")
    end
  end

  setup do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, key} = PublicKey.import({:ed25519, public}, :raw)
    signer = fn algorithm, base -> Crypto.sign(algorithm, base, {:ed25519, private}) end
    %{public: public, private: private, key: key, signer: signer}
  end

  # RFC 9421 Sections 2.2.2 and 2.2.3 distinguish preserved target URI bytes
  # from normalized authority. Client expectations instead use Mint's wire
  # authority (default ports omitted), not the original URL's spelling.
  for adapter <- [:message, :finch, :req],
      {url, wire_uri, authority} <- [
        {"https://EXAMPLE.COM:443/", "https://EXAMPLE.COM/", "example.com"},
        {"http://Example.Org:80/x?y=1", "http://Example.Org/x?y=1", "example.org"},
        {"https://example.com:8443/", "https://example.com:8443/", "example.com:8443"},
        {"https://Example.COM:08443/a%2Fb?y=%2f", "https://Example.COM:8443/a%2Fb?y=%2f",
         "example.com:8443"},
        {"https://[2001:DB8::A]:443/", "https://[2001:DB8::A]/", "[2001:db8::a]"}
      ] do
    target_uri = if adapter == :message, do: url, else: wire_uri

    authority =
      if adapter == :message and String.contains?(url, ":08443/"),
        do: "example.com:08443",
        else: authority

    test "#{adapter} preserves target URI and reciprocally verifies #{url}", context do
      adapter = unquote(adapter)
      url = unquote(url)
      target_uri = unquote(target_uri)
      authority = unquote(authority)

      signed = sign_request(adapter, "GET", url, [], nil, spec(@components), context.signer)

      expected =
        Enum.join(
          [
            ~s["@target-uri": #{target_uri}],
            ~s["@authority": #{authority}],
            ~s["@signature-params": #{@components}]
          ],
          "\n"
        )

      assert {:ok, ^expected} = SignatureBase.build(signed, @components)

      assert {:ok, %{signature: %{crypto: :valid}}} =
               RequestSeal.verify(signed, policy(context.key, @components), label: "sig")

      # Check both directions against literal expected bytes using OTP directly;
      # this is a local RFC regression, not a claimed external peer vector.
      ["sig=:" <> encoded] = field_values(signed, "signature")
      signature = encoded |> String.trim_trailing(":") |> Base.decode64!()
      assert :crypto.verify(:eddsa, :none, expected, signature, [context.public, :ed25519])

      reciprocal = :crypto.sign(:eddsa, :none, expected, [context.private, :ed25519])

      fields =
        Enum.map(signed.fields, fn field ->
          if String.downcase(field.name) == "signature",
            do: %{field | value: "sig=:#{Base.encode64(reciprocal)}:"},
            else: field
        end)

      assert {:ok, _} =
               RequestSeal.verify(%{signed | fields: fields}, policy(context.key, @components),
                 label: "sig"
               )

      changed_authority =
        if signed.authority == String.downcase(signed.authority),
          do: String.upcase(signed.authority),
          else: String.downcase(signed.authority)

      tampered = %{signed | authority: changed_authority}

      assert SignatureBase.build(tampered, ~s[("@authority")]) ==
               SignatureBase.build(signed, ~s[("@authority")])

      assert {:error, %{reason: :invalid_signature, layer: :crypto}} =
               RequestSeal.verify(
                 tampered,
                 policy(context.key, @components),
                 label: "sig"
               )

      # Related-request derivation must retain exactly the same origin facts.
      assert {:ok, response} = Message.response(200, [], nil, request: signed)

      assert {:ok, related_base} =
               SignatureBase.build(response, ~s[("@target-uri";req "@authority";req)])

      assert String.split(related_base, "\n") == [
               ~s["@target-uri";req: #{target_uri}],
               ~s["@authority";req: #{authority}],
               ~s["@signature-params": ("@target-uri";req "@authority";req)]
             ]
    end
  end

  test "request builder validates the preserved authority before derivation" do
    for url <- [
          "https://EXAMPLE.COM:000443/",
          "http://Example.Org:000080/",
          "https://EXAMPLE.COM:65536/",
          "https://user@EXAMPLE.COM:443/"
        ] do
      assert {:error, %Message.Error{reason: :invalid_message}} =
               Message.request("GET", url, [], nil)
    end
  end

  test "request builder preserves scheme spelling while @scheme normalizes", context do
    url = "HTTPS://EXAMPLE.COM:443/a%2Fb?x=%2f"
    components = ~s[("@target-uri" "@authority" "@scheme")]
    signed = sign_request(:message, "GET", url, [], nil, spec(components), context.signer)

    assert {:ok, base} = SignatureBase.build(signed, components)

    assert String.split(base, "\n") == [
             ~s["@target-uri": #{url}],
             ~s["@authority": example.com],
             ~s["@scheme": https],
             ~s["@signature-params": #{components}]
           ]

    assert {:ok, _} = RequestSeal.verify(signed, policy(context.key, components), label: "sig")
  end

  for adapter <- [:finch, :req] do
    test "#{adapter} signatures match the mixed-case authority actually sent by Mint", context do
      server =
        start_supervised!(
          {Bandit,
           plug: {WireVerifier, {self(), context.key, @components}},
           ip: {127, 0, 0, 1},
           port: 0,
           startup_log: false}
        )

      {:ok, {_, port}} = ThousandIsland.listener_info(server)
      start_supervised!({Finch, name: __MODULE__.Pool})
      url = "http://LOCALHOST:#{port}/a%2Fb?y=%2f"

      if unquote(adapter) == :finch do
        assert {:ok, signed} =
                 RequestSeal.Finch.sign(Finch.build(:get, url), spec(@components), context.signer)

        assert {:ok, %{status: 204}} = Finch.request(signed, __MODULE__.Pool)
      else
        request =
          Req.new(url: url, finch: [name: __MODULE__.Pool], retry: false, decode_body: false)

        assert {:ok, attached} =
                 RequestSeal.Req.attach(request,
                   sign: spec(@components),
                   signer: context.signer,
                   verify: :none
                 )

        assert {:ok, %{status: 204}} = Req.request(attached)
      end

      assert_receive {:wire_verified, message, {:ok, %{signature: %{crypto: :valid}}}}, 5_000
      assert message.authority == "LOCALHOST:#{port}"
      assert {:ok, base} = SignatureBase.build(message, @components)

      assert String.split(base, "\n") == [
               ~s["@target-uri": #{url}],
               ~s["@authority": localhost:#{port}],
               ~s["@signature-params": #{@components}]
             ]
    end
  end

  for adapter <- [:message, :finch, :req], existing? <- [false, true] do
    test "#{adapter} adding a label preserves covered Content-Digest (existing=#{existing?})",
         context do
      body = "exact POST content\n"
      components = ~s[("@method" "@target-uri" "@authority" "content-digest")]
      digest = ["sha-256", "sha-512"]

      headers =
        if unquote(existing?) do
          # A valid dictionary need not follow the signing spec's algorithm
          # order or its serializer's whitespace. It is already covered bytes.
          value =
            " sha-512=:#{Base.encode64(:crypto.hash(:sha512, body))}:,  " <>
              "sha-256=:#{Base.encode64(:crypto.hash(:sha256, body))}: "

          [{"Content-Digest", value}]
        else
          []
        end

      signing = %{spec(components) | digest: digest}
      adapter = unquote(adapter)
      url = "https://EXAMPLE.COM:443/submit"
      first = sign_request(adapter, "POST", url, headers, body, signing, context.signer)
      p = policy(context.key, components, digest)
      assert {:ok, _} = RequestSeal.verify(first, p, label: "sig")
      before = Enum.filter(first.fields, &(String.downcase(&1.name) == "content-digest"))
      assert [%FieldOccurrence{}] = before

      second =
        sign_request(
          adapter,
          "POST",
          url,
          Enum.map(first.fields, &{&1.name, &1.value}),
          body,
          %{signing | label: "sig2"},
          context.signer
        )

      assert Enum.filter(second.fields, &(String.downcase(&1.name) == "content-digest")) ==
               before

      for label <- ["sig", "sig2"] do
        assert {:ok, %{label: ^label, signature: %{crypto: :valid}}} =
                 RequestSeal.verify(second, p, label: label)
      end

      assert {:error, %{reason: :digest_mismatch}} =
               RequestSeal.verify(%{second | body: %{second.body | bytes: "tampered"}}, p,
                 label: "sig2"
               )
    end
  end

  defp sign_request(:message, method, url, headers, body, spec, signer) do
    assert {:ok, message} = Message.request(method, url, headers, body)
    assert {:ok, signed} = RequestSeal.sign(message, spec, signer)
    signed
  end

  defp sign_request(:finch, method, url, headers, body, spec, signer) do
    request = Finch.build(method, url, headers, body)
    assert {:ok, signed} = RequestSeal.Finch.sign(request, spec, signer)
    assert {:ok, message} = RequestSeal.Finch.request_message(signed)
    message
  end

  defp sign_request(:req, method, url, headers, body, spec, signer) do
    request = Req.new(method: method, url: url, headers: headers, body: body)

    assert {:ok, attached} =
             RequestSeal.Req.attach(request, sign: spec, signer: signer, verify: :none)

    signed = RequestSeal.Req.sign_attempt(attached)
    refute signed.halted
    signed.private.request_seal.sent
  end

  defp spec(components) do
    %{
      label: "sig",
      algorithm: "ed25519",
      components: components,
      parameters: %{
        created: false,
        expires_in: nil,
        nonce: nil,
        alg: false,
        keyid: nil,
        tag: nil
      },
      digest: nil,
      field_schemas: %{}
    }
  end

  defp policy(key, components, digest \\ nil) do
    assert {:ok, policy} =
             Policy.new(%{
               algorithms: ["ed25519"],
               components: components,
               key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
               freshness: :not_evaluated,
               content:
                 if(digest,
                   do: %{kind: :content, algorithms: digest, section: :headers},
                   else: :not_required
                 ),
               replay: :not_required
             })

    policy
  end

  defp field_values(message, name),
    do: for(field <- message.fields, String.downcase(field.name) == name, do: field.value)
end
