defmodule RequestSeal.DXBuilderTest do
  use ExUnit.Case, async: true
  doctest RequestSeal
  alias RequestSeal.{Body, Crypto, Digest, FieldOccurrence, Message, PublicKey, TransportFacts}

  test "request builder normalizes origins while preserving target and field bytes" do
    headers = [{"X-Repeat", " first "}, {"x-repeat", <<255>>}, {"X-Repeat", "third"}]

    for method <- ["GET", "post", "M-SEARCH", "OPTIONS"],
        {url, scheme, authority, target} <- [
          {"https://Example.COM/a%2Fb?x=1&x=2", "https", "example.com", "/a%2Fb?x=1&x=2"},
          {"http://example.com:080?", "http", "example.com", "/?"},
          {"https://[2001:db8::1]:8443/", "https", "[2001:db8::1]:8443", "/"},
          {"http://example.com:0", "http", "example.com:0", "/"},
          {"HTTPS://Example.COM:443?x=%2f", "https", "example.com", "/?x=%2f"}
        ],
        bytes <- [nil, "", <<0, 255, 1>>],
        algorithms <- [nil, ["sha-256"], ["sha-512", "sha-256"]] do
      {:ok, body} = Body.new(%{state: :retained, bytes: bytes || ""})
      {:ok, transport} = TransportFacts.new(%{})

      fields =
        Enum.map(headers, fn {name, value} ->
          {:ok, field} = FieldOccurrence.new(%{name: name, value: value, section: :headers})
          field
        end)

      fields =
        if algorithms do
          {:ok, digest} = Digest.compute(body, algorithms)
          {:ok, wire} = Digest.serialize(digest)
          fields ++ [%FieldOccurrence{name: "content-digest", value: wire, section: :headers}]
        else
          fields
        end

      {:ok, expected} =
        Message.new(%{
          kind: :request,
          method: method,
          scheme: scheme,
          authority: authority,
          raw_target: target,
          target_form: :origin,
          fields: fields,
          trailers: :unavailable,
          body: body,
          transport: transport
        })

      assert {:ok, ^expected} = Message.request(method, url, headers, bytes, digest: algorithms)
      assert :ok = Message.validate(expected)
    end
  end

  test "response builder preserves related request and validates through Message.new" do
    {:ok, request} = Message.request("GET", "https://example.com/", [], nil)
    {:ok, body} = Body.new(%{state: :retained, bytes: ""})

    {:ok, expected} =
      Message.new(%{
        kind: :response,
        status: 204,
        fields: [],
        trailers: :unavailable,
        body: body,
        transport: %TransportFacts{},
        related_request: request
      })

    assert {:ok, ^expected} = Message.response(204, [], nil, request: request)
    assert {:ok, response} = Message.response(200, [], "body", digest: ["sha-256"])
    assert {:ok, _} = Digest.check(response, :content)

    for status <- [99, 600, "200", nil] do
      assert {:error, %Message.Error{}} = Message.response(status, [], "")
    end

    assert {:error, %Message.Error{}} = Message.response(200, [], "", request: response)
  end

  test "builders return existing bounded errors for invalid input and options" do
    for url <- [
          "/path",
          "ftp://example.com/",
          "https:///a",
          "https://u@example.com/",
          "https://example.com/#fragment",
          "https://example.com/%zz",
          "https://example.com:65536/",
          "https://[bad]/",
          "https://example.com/a b",
          "https://example.com/[x]",
          <<255>>,
          nil,
          %URI{}
        ] do
      assert {:error, %Message.Error{}} = Message.request("GET", url, [], "")
    end

    for method <- ["", "bad method", :get, "CONNECT", String.duplicate("x", 257)] do
      assert {:error, %Message.Error{}} = Message.request(method, "https://example.com/", [], "")
    end

    for headers <- [
          %{},
          ["bad"],
          [{"bad name", "x"}],
          [{"x", "a\r\nb"}],
          [{"x", 1}],
          [{"x", "a", "b"}],
          List.duplicate({"x", ""}, 1025)
        ] do
      assert {:error, %Message.Error{}} =
               Message.request("GET", "https://example.com/", headers, "")

      assert {:error, %Message.Error{}} = Message.response(200, headers, "")
    end

    for body <- [[], :unavailable, 1, String.duplicate("x", 1_048_577)] do
      assert {:error, %Message.Error{reason: :invalid_body}} =
               Message.request("GET", "https://example.com/", [], body)

      assert {:error, %Message.Error{reason: :invalid_body}} = Message.response(200, [], body)
    end

    for opts <- [
          [unknown: true],
          [digest: nil, digest: nil],
          [digest: []],
          [digest: ["md5"]],
          [digest: ["sha-256", "sha-256"]],
          %{},
          [1]
        ] do
      assert {:error, %Message.Error{}} =
               Message.request("GET", "https://example.com/", [], "", opts)

      assert {:error, %Message.Error{}} = Message.response(200, [], "", opts)
    end
  end

  test "digest generation rejects existing digests while the default preserves them" do
    headers = [{"Content-Digest", "caller bytes"}, {"Content-Digest", "more caller bytes"}]
    assert {:ok, request} = Message.request("GET", "https://example.com/", headers, nil)
    assert Enum.map(request.fields, &{&1.name, &1.value}) == headers

    assert {:error, %Message.Error{reason: :invalid_message}} =
             Message.request("GET", "https://example.com/", headers, nil, digest: ["sha-256"])

    assert {:error, %Message.Error{reason: :invalid_message}} =
             Message.response(200, headers, nil, digest: ["sha-256"])
  end

  test "spec signing handles absent metadata, covered length, related requests and explicit input" do
    secret = :crypto.strong_rand_bytes(32)
    signer = fn alg, base -> Crypto.sign(alg, base, {:hmac, secret}) end
    {:ok, message} = Message.request("POST", "https://example.com/a", [], "body")

    spec = %{
      spec("hmac-sha256")
      | components: ~s[("@method" "content-length")],
        digest: nil,
        parameters: %{
          created: false,
          expires_in: nil,
          nonce: nil,
          alg: false,
          keyid: nil,
          tag: nil
        }
    }

    message = %{
      message
      | fields: [%FieldOccurrence{name: "content-length", value: "4", section: :headers}]
    }

    assert {:ok, signed} =
             RequestSeal.sign(
               message,
               %{label: spec.label, algorithm: spec.algorithm, signature_input: spec.components},
               signer
             )

    assert Enum.find(signed.fields, &(&1.name == "content-length")).value == "4"

    assert Enum.find(signed.fields, &(&1.name == "Signature-Input")).value ==
             ~s[sig=("@method" "content-length")]

    assert {:ok, explicit} =
             RequestSeal.sign(
               %{message | fields: Enum.filter(signed.fields, &(&1.name == "content-length"))},
               %{label: "sig", algorithm: "hmac-sha256", signature_input: spec.components},
               signer
             )

    assert Enum.find(explicit.fields, &(&1.name == "Signature-Input")).value ==
             ~s[sig=("@method" "content-length")]

    {:ok, response} = Message.response(200, [], "response", request: message)

    response_spec = %{
      spec
      | parameters: %{spec.parameters | created: true, expires_in: 60},
        components: ~s[("@status" "@method";req)]
    }

    assert {:ok, signed_response} = RequestSeal.sign(response, response_spec, signer)

    {:ok, policy} =
      RequestSeal.Policy.new(%{
        algorithms: ["hmac-sha256"],
        components: response_spec.components,
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: "hmac-sha256",
             key: fn alg, base, signature ->
               Crypto.verify(alg, base, signature, {:hmac, secret})
             end
           }}
        end,
        freshness: :not_evaluated,
        content: :not_required,
        replay: :not_required
      })

    assert {:ok, _} = RequestSeal.verify(signed_response, policy, label: "sig")
  end

  test "spec signing matches Finch and Req signature bytes without nonce metadata" do
    {public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
    on_exit(fn -> RequestSeal.Custody.Local.release(handle) end)
    headers = [{"x-repeat", "one"}, {"x-repeat", "two"}]
    url = "https://example.com:8443/a%2Fb?x=1&x=2"
    spec = spec("ed25519")
    spec = %{spec | parameters: %{spec.parameters | nonce: nil}}
    opts = [clock: fn -> 1_700_000_000 end]
    {:ok, message} = Message.request("POST", url, headers, "body")
    assert {:ok, signed} = RequestSeal.sign(message, spec, handle, opts)

    assert {:ok, finch} =
             RequestSeal.Finch.sign(Finch.build(:post, url, headers, "body"), spec, handle, opts)

    assert Enum.map(signed.fields, &{&1.name, &1.value}) == finch.headers

    {:ok, req} =
      RequestSeal.Req.attach(
        Req.new(method: :post, url: url, headers: headers, body: "body"),
        [sign: spec, signer: handle, verify: :none] ++ opts
      )

    req = RequestSeal.Req.sign_attempt(req)
    assert signature_headers(req.headers) == signature_headers(finch.headers)
    {:ok, key} = PublicKey.import({:ed25519, public}, :raw)
    assert {:ok, result} = RequestSeal.verify(signed, policy("ed25519", key), label: "sig")
    refute Map.has_key?(result.signature.parameters, "nonce")
    assert result.signature.parameters["created"] == 1_700_000_000
    assert result.signature.parameters["expires"] == 1_700_000_060
    assert result.signature.parameters["tag"] == "example"
  end

  for algorithm <- Crypto.algorithms() do
    test "spec signing round trip and body rejection: #{algorithm}" do
      algorithm = unquote(algorithm)
      {private, public} = keys(algorithm)
      {:ok, message} = Message.request("POST", "https://example.com/a", [], "body")
      signer = fn alg, base -> Crypto.sign(alg, base, private) end

      assert {:ok, signed} =
               RequestSeal.sign(message, spec(algorithm), signer, clock: fn -> 1_700_000_000 end)

      assert {:ok, verified} = RequestSeal.verify(signed, policy(algorithm, public), label: "sig")
      assert verified.signature.crypto == :valid

      assert {:error, %{reason: :digest_mismatch}} =
               RequestSeal.verify(
                 %{signed | body: %{signed.body | bytes: "evil"}},
                 policy(algorithm, public),
                 label: "sig"
               )

      assert {:error, %{reason: :label_in_use}} =
               RequestSeal.sign(signed, spec(algorithm), signer)
    end
  end

  test "spec signing rejects malformed specs, options, messages, digest conflicts and signer faults" do
    {:ok, message} = Message.request("POST", "https://example.com/a", [], "body")
    secret = :crypto.strong_rand_bytes(32)
    signer = fn alg, base -> Crypto.sign(alg, base, {:hmac, secret}) end
    spec = spec("hmac-sha256")

    for invalid <- [
          Map.delete(spec, :components),
          %{spec | parameters: %{}},
          %{spec | digest: []},
          %{spec | components: ~s[("host")]},
          Map.put(spec, :unknown, true)
        ] do
      assert {:error, %RequestSeal.Error{}} = RequestSeal.sign(message, invalid, signer)
    end

    for opts <- [
          [clock: nil],
          [clock: fn -> :bad end],
          [clock: fn -> raise "secret" end],
          [nonce: "short"],
          [nonce: nil],
          [unknown: true],
          [body: :as_is],
          [clock: fn -> 1 end, clock: fn -> 2 end]
        ] do
      assert {:error, %RequestSeal.Error{}} = RequestSeal.sign(message, spec, signer, opts)
    end

    assert {:error, %RequestSeal.Error{reason: :invalid_message}} =
             RequestSeal.sign(%{message | method: ""}, spec, signer)

    assert {:error, %RequestSeal.Error{reason: :signer_failed}} =
             RequestSeal.sign(message, spec, fn _, _ -> raise "secret" end)

    {:ok, other} =
      Message.request("POST", "https://example.com/a", [], "other", digest: ["sha-256"])

    assert {:error, %RequestSeal.Error{reason: :digest_mismatch}} =
             RequestSeal.sign(%{other | body: message.body}, spec, signer)
  end

  defp spec(algorithm),
    do: %{
      label: "sig",
      algorithm: algorithm,
      components: ~s[("@method" "@authority" "@path" "content-digest")],
      parameters: %{
        created: true,
        expires_in: 60,
        nonce: :random,
        alg: true,
        keyid: "demo-key",
        tag: "example"
      },
      digest: ["sha-256"],
      field_schemas: %{}
    }

  defp policy(algorithm, key) do
    {:ok, policy} =
      RequestSeal.Policy.new(%{
        algorithms: [algorithm],
        components: spec(algorithm).components,
        key_resolver: fn
          %{keyid: "demo-key"} -> {:ok, %{algorithm: algorithm, key: key}}
          _ -> :error
        end,
        freshness: %{clock: fn -> 1_700_000_001 end, max_age: 60, skew: 0, require_expires: true},
        content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
        replay: :not_required
      })

    policy
  end

  defp signature_headers(headers) do
    headers
    |> Enum.filter(fn {name, _} -> String.downcase(name) in ["signature-input", "signature"] end)
    |> Map.new(fn {name, value} -> {String.downcase(name), IO.iodata_to_binary(value)} end)
  end

  defp keys("hmac-sha256") do
    key = {:hmac, :crypto.strong_rand_bytes(32)}
    {key, fn alg, base, signature -> Crypto.verify(alg, base, signature, key) end}
  end

  defp keys("ecdsa-p384-sha384") do
    {point, private} = :crypto.generate_key(:ecdh, :secp384r1)
    {:ok, public} = PublicKey.import({:ec, "P-384", point}, :raw)
    {{:ec, "P-384", private}, public}
  end

  defp keys(algorithm) do
    {id, type} =
      case algorithm do
        "rsa-v1_5-sha256" -> {"rsa", :rsa}
        "rsa-pss-sha512" -> {"rsa_pss", :rsa}
        "ecdsa-p256-sha256" -> {"p256", :ec}
        "ecdsa-p384-sha384" -> {"p384", :ec}
        "ed25519" -> {"ed25519", :ed25519}
      end

    root = Path.join(__DIR__, "fixtures/crypto")
    [entry] = :public_key.pem_decode(File.read!(Path.join(root, id <> "_private.pem")))
    decoded = :public_key.pem_entry_decode(entry)

    private =
      case type do
        :rsa -> {:rsa, if(id == "rsa_pss", do: elem(decoded, 0), else: decoded)}
        :ec -> {:ec, if(id == "p256", do: "P-256", else: "P-384"), elem(decoded, 2)}
        :ed25519 -> {:ed25519, elem(decoded, 2)}
      end

    {:ok, public} = PublicKey.import(File.read!(Path.join(root, id <> "_public.pem")), :pem)
    {private, public}
  end
end
