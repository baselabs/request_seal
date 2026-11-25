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
