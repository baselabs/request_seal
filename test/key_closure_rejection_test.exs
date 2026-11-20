defmodule RequestSeal.KeyClosureRejectionTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{AcceptSignature, Custody, Message, Policy}
  alias RequestSeal.JOSE.{JWE, JWS, Nested}
  import RequestSeal.JOSEVectors

  test "every public signing and wrapping entry rejects a key closure before invocation" do
    owner = self()

    closure = fn _, _ ->
      send(owner, :key_closure_ran)
      raise "private"
    end

    handle =
      local(
        "ed25519",
        {:ed25519, hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")}
      )

    {:ok, key} = Custody.public_key(handle)
    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)
    explicit = %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method")]}
    generated = %{label: "sig", algorithm: "ed25519", components: ~s[("@method")], expires_in: 60}

    bot = %{
      label: "bot",
      algorithm: "ed25519",
      key: key,
      created: 10,
      expires: 70,
      nonce: nil,
      agent: %{location: "https://example.com", type: :directory}
    }

    {:ok, requests} = AcceptSignature.parse(~s[sig=("@method")], target: :request)
    chooser = fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end

    for result <- [
          RequestSeal.sign(message, explicit, closure),
          RequestSeal.sign(message, explicit, closure, []),
          RequestSeal.sign(message, generated, closure),
          RequestSeal.sign(message, generated, closure, []),
          RequestSeal.WebBotAuth.sign(message, bot, closure),
          RequestSeal.WebBotAuth.sign(message, bot, closure, []),
          AcceptSignature.fulfill(message, requests, chooser, closure, []),
          RequestSeal.Finch.sign(Finch.build(:get, "https://example.com/"), generated, closure),
          RequestSeal.Finch.sign(
            Finch.build(:get, "https://example.com/"),
            generated,
            closure,
            []
          ),
          RequestSeal.Req.attach(Req.new(url: "https://example.com/"),
            sign: generated,
            signer: closure,
            verify: :none
          ),
          JWS.sign([{"alg", "EdDSA"}], "payload", closure),
          JWS.sign([{"alg", "EdDSA"}], "payload", closure, []),
          JWS.sign_protected(~s({"alg":"EdDSA"}), "payload", closure),
          JWS.sign_protected(~s({"alg":"EdDSA"}), "payload", closure, []),
          JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", closure),
          JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", closure, [])
        ] do
      assert {:error, %{reason: :invalid_options}} = result
      refute_received :key_closure_ran
    end

    assert_raise RequestSeal.Adapter.Error, fn ->
      RequestSeal.Plug.SignResponse.init(
        sign: generated,
        signer: closure,
        signing_timeout: 5000,
        clock: fn -> 10 end,
        on_failure: {:respond, 500}
      )
    end

    refute_received :key_closure_ran
  end

  test "HTTP and JOSE resolver callbacks remain but their returned key closures reject" do
    owner = self()

    closure = fn _, _, _ ->
      send(owner, :key_closure_ran)
      :ok
    end

    handle =
      local(
        "ed25519",
        {:ed25519, hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")}
      )

    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)

    {:ok, signed} =
      RequestSeal.sign(
        message,
        %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method")]},
        handle
      )

    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: ~s[("@method")],
        key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: closure}} end,
        freshness: :not_evaluated,
        content: :not_required,
        replay: :not_required
      })

    assert {:error, %{reason: :key_resolver_failed, layer: :key}} =
             RequestSeal.verify(signed, policy, label: "sig")

    vector = fixture("rfc7515.json")["A.2"]

    jp = %{
      jws_policy(vector["key"], "RS256")
      | key_resolver: fn _ -> {:ok, %{algorithm: "RS256", key: closure}} end
    }

    assert {:error, %{reason: :key_resolver_failed, layer: :key}} =
             JWS.verify(vector["compact"], jp)

    kw = local({:jwe, "A256KW"}, {:aes, :crypto.strong_rand_bytes(32)})

    {:ok, outer} =
      JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}, {"cty", "JWT"}], vector["compact"], kw)

    p = %{
      algorithms: ["A256KW"],
      encryption: ["A256GCM"],
      max_plaintext: 65_536,
      timeout: 5000,
      resolve_timeout: 1000,
      unwrap_timeout: 1000,
      protected: %{expected: %{}, permitted: ["cty"]},
      key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: kw}} end
    }

    assert {:error, %{reason: :key_resolver_failed}} =
             Nested.verify(outer, p, jp, content_types: ["JWT"])

    unwrap = fn _, _ ->
      send(owner, :key_closure_ran)
      {:ok, <<0::256>>}
    end

    bad = %{p | key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", unwrap: unwrap}} end}
    assert {:error, %{reason: :key_resolver_failed}} = JWE.decrypt(outer, bad)

    batch =
      bad
      |> Map.put(:protected, %{permitted: ["cty"]})
      |> Map.merge(%{max_tokens: 1, max_total_input: 65_536, max_total_plaintext: 65_536})

    assert {:ok, [{:error, %{reason: :key_resolver_failed}}]} =
             JWE.decrypt_many([%{token: outer, expected: %{}}], batch)

    refute_received :key_closure_ran
  end
end
