defmodule RequestSeal.DenySetTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Conformance, Custody, DenySet, PublicKey}
  alias RequestSeal.Custody.{Local, SSHAgent}
  alias RequestSeal.JOSE.JWS
  alias RequestSeal.JOSEVectors, as: V

  @thumbprint "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
  @other Base.url_encode64(<<0::256>>, padding: false)
  @jwk :json.decode(File.read!("corpus/sources/rfc8037/rfc8037.json"))

  doctest DenySet

  test "set admission requires canonical SHA-256 thumbprints" do
    {:ok, key} = PublicKey.import(Map.delete(@jwk, "d"), :jwk)
    {:ok, set} = DenySet.new([@thumbprint, @thumbprint])
    {:ok, empty} = DenySet.new([])
    assert {:error, :key_denied} = DenySet.check(set, key)
    assert :ok = DenySet.check(empty, key)
    assert {:error, :key_fingerprint_unknown} = DenySet.check(empty, nil)
    assert {:error, :invalid_options} = DenySet.check([], key)
    assert :ok = DenySet.check(nil, nil)

    # The final sextet has two unused bits.
    noncanonical = binary_part(@thumbprint, 0, 42) <> "l"

    for entries <- [
          nil,
          [@thumbprint | :bad_tail],
          [noncanonical],
          [@thumbprint <> "="],
          [@thumbprint <> "x"],
          List.duplicate(@thumbprint, 65_537)
        ] do
      assert {:error, %{reason: :invalid_options}} = DenySet.new(entries)
    end

    assert {:ok, _} = DenySet.new(DenySet.published_test_keys())
  end

  test "verification screens the public key and still requires custody approval" do
    {:ok, deny} = DenySet.new([])
    {:ok, signing} = Local.generate("ed25519", capabilities: [:sign])
    {:ok, public} = Custody.public_key(signing)
    {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)

    spec = %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method")]}
    {:ok, signed} = RequestSeal.sign(message, spec, signing)

    attrs = %{
      algorithms: ["ed25519"],
      components: "()",
      key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public}} end,
      content: :not_required,
      freshness: :not_evaluated,
      replay: :not_required,
      deny: deny
    }

    {:ok, policy} = RequestSeal.Policy.new(attrs)
    assert {:ok, _} = RequestSeal.verify(signed, policy, label: "sig")
    assert {:ok, _} = RequestSeal.verify(signed, Map.delete(policy, :deny), label: "sig")

    # The handle claims verification. The real holder still grants signing only.
    handle = %{signing | capabilities: [:verify]}
    policy = %{policy | key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: handle}} end}

    assert {:error, %{reason: :verifier_failed}} =
             RequestSeal.verify(signed, policy, label: "sig")

    assert {:error, %{reason: :verifier_failed}} =
             RequestSeal.verify(signed, policy, label: "sig", capture: true)

    assert {:error, %{reason: :verifier_failed}} =
             RequestSeal.verify(signed, %{policy | deny: nil}, label: "sig", capture: true)

    assert :ok = Custody.release(signing)
    {:ok, jws_signing} = Local.generate({:jws, "EdDSA"}, capabilities: [:sign])
    {:ok, jws_public} = Custody.public_key(jws_signing)
    {:ok, jwk} = PublicKey.export(jws_public, :jwk)
    {:ok, compact} = JWS.sign([{"alg", "EdDSA"}], "payload", jws_signing)
    jws_policy = Map.put(V.jws_policy(jwk, "EdDSA"), :deny, deny)
    assert {:ok, _} = JWS.verify(compact, jws_policy)

    jws_handle = %{jws_signing | capabilities: [:verify]}
    jws_policy = %{jws_policy | key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: jws_handle}} end}

    assert {:error, %{reason: :invalid_signature}} = JWS.verify(compact, jws_policy)
    assert :ok = Custody.release(jws_signing)
  end

  test "policy rejects forged deny maps including text thumbprints" do
    {:ok, public} = PublicKey.import(Map.delete(@jwk, "d"), :jwk)

    attrs = %{
      algorithms: ["ed25519"],
      components: "()",
      key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public}} end,
      content: :not_required,
      freshness: :not_evaluated,
      replay: :not_required
    }

    raw = Base.url_decode64!(@thumbprint, padding: false)

    for entries <- [%{@thumbprint => true}, %{raw => false}] do
      forged = %DenySet{entries: entries}
      assert {:error, %{reason: :invalid_policy}} =
               RequestSeal.Policy.new(Map.put(attrs, :deny, forged))

      assert {:error, :invalid_options} = DenySet.check(forged, public)
    end
  end

  test "local screening precedes the private RSA possession probe" do
    [entry] = :public_key.pem_decode(File.read!("test/fixtures/crypto/rsa_private.pem"))
    private = :public_key.pem_entry_decode(entry)
    broken = {:rsa, put_elem(private, 5, 1)}
    {:ok, key} = PublicKey.import(File.read!("test/fixtures/crypto/rsa_public.pem"), :pem)
    {:ok, thumbprint} = PublicKey.thumbprint(key)
    {:ok, deny} = DenySet.new([thumbprint])

    assert {:error, %{reason: :invalid_key}} = Local.new("rsa-v1_5-sha256", broken)
    assert {:error, %{reason: :key_denied}} = Local.new("rsa-v1_5-sha256", broken, deny: deny)
    assert {:error, %{reason: :key_mismatch}} =
             Local.new("rsa-v1_5-sha256", broken, expected_thumbprint: @other)
  end

  test "local seed and import compare custody-derived key before admission" do
    seed = Base.url_decode64!(@jwk["d"], padding: false)
    {:ok, deny} = DenySet.new([@thumbprint])
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed}, expected_thumbprint: @thumbprint)
    assert {:ok, key} = Custody.public_key(handle)
    assert {:ok, @thumbprint} = PublicKey.thumbprint(key)
    assert :ok = Local.release(handle)

    for {opts, reason} <- [
          {[expected_thumbprint: @other], :key_mismatch},
          {[expected_thumbprint: nil], :invalid_options},
          {[deny: ["raw list"]], :invalid_options},
          {[deny: deny, expected_thumbprint: @thumbprint], :key_denied}
        ] do
      assert {:error, %{reason: ^reason}} = Local.new("ed25519", {:ed25519, seed}, opts)
      assert {:error, %{reason: ^reason}} = Local.import("ed25519", @jwk, :jwk, opts)
    end

    assert {:error, %{reason: :key_fingerprint_unknown}} =
             Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)}, deny: deny)

    assert {:error, %{reason: :key_denied}} =
             SSHAgent.new("ed25519", "/unused-agent.sock", key, deny: deny)
  end

  test "JWS verifies allowed material and rejects the same published signature when denied" do
    v = V.fixture("rfc7515.json")["A.2"]
    p = V.jws_policy(v["key"], "RS256")
    key = V.public(v["key"])
    {:ok, thumbprint} = PublicKey.thumbprint(key)
    {:ok, deny} = DenySet.new([thumbprint])
    assert {:ok, _} = JWS.verify(v["compact"], p)
    assert {:error, %{layer: :key, reason: :key_denied}} =
             JWS.verify(v["compact"], Map.put(p, :deny, deny))
  end

  test "generic deny policy keys on resolved material and rejects symmetric handles" do
    for {name, reason} <- [
          {"deny-allow-other-key", nil},
          {"deny-resolved-key", :key_denied},
          {"deny-symmetric-key", :key_fingerprint_unknown}
        ] do
      manifest = Conformance.json(File.read!("corpus/cases/verify/#{name}.json"))

      case Conformance.Surfaces.verify("corpus", manifest) do
        {:ok, _} -> assert reason == nil
        {:error, %{layer: :key, reason: actual}} -> assert actual == reason
      end
    end
  end
end
