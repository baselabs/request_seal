defmodule RequestSeal.JOSEJWSTest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.JWS
  import RequestSeal.JOSEVectors

  test "JWS signing emits compact protected JSON in caller order" do
    v = fixture("rfc7515.json")["A.2"]
    assert {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "RS256"}, material(v["key"]))

    try do
      for {header, expected} <- [
            {[{"alg", "RS256"}, {"kid", "k1"}], ~s({"alg":"RS256","kid":"k1"})},
            {[{"kid", "k1"}, {"alg", "RS256"}], ~s({"kid":"k1","alg":"RS256"})}
          ] do
        assert {:ok, compact} = JWS.sign(header, "payload", handle)
        [protected, _, _] = String.split(compact, ".")
        assert b64(protected) == expected
        assert {:ok, result} = JWS.verify(compact, jws_policy(v["key"], "RS256"))
        assert result.payload == "payload"
      end
    after
      RequestSeal.Custody.Local.release(handle)
    end
  end

  test "serialized JWS signing preserves published bytes and rejects invalid inputs" do
    v = fixture("rfc7515.json")["A.2"]
    [protected, payload, _] = String.split(v["compact"], ".")
    json = b64(protected)
    assert {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "RS256"}, material(v["key"]))

    try do
      assert JWS.sign_protected(json, b64(payload), handle) == {:ok, v["compact"]}

      for {protected, payload, reason} <- [
            {json, "", :detached_payload},
            {~s({"alg":"RS256","alg":"RS256"}), "{}", :duplicate_member},
            {~s({"alg":"RS256","crit":["x"]}), "{}", :unsupported_critical_header},
            {~s({"alg":"none"}), "{}", :algorithm_not_permitted},
            {~s({"alg":"RS256","x":") <> :binary.copy("x", 16_384) <> ~s("}), "{}", :limit}
          ] do
        assert {:error, %{reason: ^reason}} = JWS.sign_protected(protected, payload, handle)
      end

      assert {:error, %{reason: :invalid_options}} =
               JWS.sign_protected(json, "{}", handle, timeout: 0)

      assert {:error, %{reason: :invalid_serialization}} =
               JWS.sign_protected(json, nil, handle)
    after
      RequestSeal.Custody.Local.release(handle)
    end
  end

  test "protected headers reject trailing U+2003" do
    assert_trailing_header_rejected("\u2003")
  end

  test "protected headers reject trailing U+00A0" do
    assert_trailing_header_rejected("\u00A0")
  end

  defp assert_trailing_header_rejected(suffix) do
    v = fixture("rfc7515.json")["A.2"]

    assert {:error, %{reason: :invalid_header}} =
             JWS.verify(
               header(v["compact"], ~s({"alg":"RS256"}) <> suffix),
               jws_policy(v["key"], "RS256")
             )
  end

  test "protected headers accept only trailing ASCII JSON whitespace" do
    json = ~s({"alg":"RS256"})

    for suffix <- ["", " ", "\t", "\n", "\r", " \t\n\r "] do
      assert RequestSeal.JOSE.Header.parse(enc(json <> suffix)) == %{"alg" => "RS256"}
    end
  end

  test "JWS rejects mismatched key kinds through PublicKey and the HMAC custodian path" do
    vectors = fixture("rfc7515.json")
    rsa_key = public(vectors["A.2"]["key"])
    secret = material(vectors["A.1"]["key"])

    for {name, alg, key} <- [
          {"A.1", "HS256", rsa_key},
          {"A.2", "RS256", %RequestSeal.PublicKey{material: secret}},
          {"A.2", "EdDSA", rsa_key}
        ] do
      v = vectors[name]

      compact =
        if alg == "EdDSA", do: header(v["compact"], ~s({"alg":"EdDSA"})), else: v["compact"]

      policy = %{
        algorithms: [alg],
        timeout: 5000,
        key_resolver: fn _ -> {:ok, %{algorithm: alg, key: key}} end
      }

      assert {:error, %{reason: :invalid_signature, layer: :crypto}} = JWS.verify(compact, policy)
    end

    v = vectors["A.2"]
    policy = jws_policy(vectors["A.1"]["key"], "RS256")

    assert {:error, %{reason: :key_mismatch}} =
             RequestSeal.Crypto.verify({:jws, "RS256"}, "input", <<1>>, secret)

    assert {:error, %{reason: :invalid_signature, layer: :crypto}} =
             JWS.verify(v["compact"], policy)
  end

  test "RFC 7515 published HMAC, RSA and ECDSA signatures verify received protected bytes" do
    vectors = fixture("rfc7515.json")

    for {name, alg} <- [{"A.1", "HS256"}, {"A.2", "RS256"}, {"A.3", "ES256"}] do
      v = vectors[name]
      assert {:ok, result} = JWS.verify(v["compact"], jws_policy(v["key"], alg))
      [protected, payload, _] = String.split(v["compact"], ".")
      assert result.protected == protected
      assert result.payload == b64(payload)
      assert result.crypto == :valid
      assert result.principal == :unattributed
      assert result.authorization == :not_evaluated
      refute inspect(result) =~ result.payload
    end

    for {name, alg} <- [{"A.1", "HS256"}, {"A.2", "RS256"}] do
      v = vectors[name]
      [protected, payload, _] = String.split(v["compact"], ".")
      assert {:ok, handle} = RequestSeal.Custody.Local.new({:jws, alg}, material(v["key"]))

      try do
        assert JWS.sign_protected(b64(protected), b64(payload), handle, timeout: 5000) ==
                 {:ok, v["compact"]}
      after
        RequestSeal.Custody.Local.release(handle)
      end
    end
  end

  test "RFC 7520 published compact signatures and serialization rejections" do
    for {name, alg} <- [
          {"4_1.rsa_v15_signature.json", "RS256"},
          {"4_2.rsa-pss_signature.json", "PS384"},
          {"4_4.hmac-sha2_integrity_protection.json", "HS256"}
        ] do
      v = fixture(name)
      assert {:ok, r} = JWS.verify(v["output"]["compact"], jws_policy(v["input"]["key"], alg))
      assert r.payload == v["input"]["payload"]

      for output <- ["json", "json_flat"] do
        assert {:error, %{reason: :unsupported_serialization}} =
                 JWS.verify(
                   :json.encode(v["output"][output]) |> IO.iodata_to_binary(),
                   jws_policy(v["input"]["key"], alg)
                 )
      end
    end

    v = fixture("4_5.signature_with_detached_content.json")

    assert {:error, %{reason: :detached_payload}} =
             JWS.verify(v["output"]["compact"], jws_policy(v["input"]["key"], v["input"]["alg"]))
  end

  test "policy and resolver algorithm bindings reject before cryptography" do
    v = fixture("rfc7515.json")["A.2"]
    policy = jws_policy(v["key"], "RS256")

    assert {:error, %{reason: :invalid_policy}} =
             JWS.verify(v["compact"], %{policy | algorithms: ["none"]})

    assert {:error, %{reason: :algorithm_not_permitted}} =
             JWS.verify(v["compact"], %{policy | algorithms: ["PS256"]})

    resolver = fn _ -> {:ok, %{algorithm: "PS256", key: public(v["key"])}} end

    assert {:error, %{reason: :algorithm_mismatch}} =
             JWS.verify(v["compact"], %{policy | key_resolver: resolver})

    assert {:error, %{reason: :unknown_key}} =
             JWS.verify(v["compact"], %{policy | key_resolver: fn _ -> :error end})
  end

  test "duplicate members, critical extensions, Base64 variants and segment bounds reject" do
    v = fixture("rfc7515.json")["A.2"]
    c = v["compact"]
    p = jws_policy(v["key"], "RS256")

    for json <- [~s({"alg":"RS256","alg":"RS256"}), ~s({"alg":"RS256","x5c":[{"a":1,"a":2}]})] do
      assert {:error, %{reason: :duplicate_member}} = JWS.verify(header(c, json), p)
    end

    for {json, reason} <- [
          {~s({"alg":"RS256","crit":[]}), :unsupported_critical_header},
          {~s({"alg":"RS256","zip":"DEF"}), :compression_unsupported},
          {~s({"alg":"RS256","b64":true}), :unsupported_header},
          {~s({"alg":"rs256"}), :algorithm_not_permitted}
        ] do
      assert {:error, %{reason: ^reason}} = JWS.verify(header(c, json), p)
    end

    for name <- ~w(jku x5u jwk) do
      assert {:error, %{reason: :unsupported_header}} =
               JWS.verify(header(c, ~s({"alg":"RS256","#{name}":"canary"})), p)
    end

    for segment <- ["e30=", "+w", "/w", "Zh"] do
      assert {:error, %{reason: :invalid_base64}} = JWS.verify(replace(c, 0, segment), p)
    end

    for count <- [2, 4, 6] do
      assert {:error, %{reason: :invalid_serialization}} =
               JWS.verify(Enum.join(List.duplicate("e30", count), "."), p)
    end

    assert {:error, %{reason: :invalid_signature}} = JWS.verify(replace(c, 2, ""), p)

    assert {:error, %{reason: :invalid_signature}} =
             JWS.verify(header(c, ~s({ "alg":"RS256"})), p)
  end

  test "bounded header tree, integers, arrays, members and compact input" do
    v = fixture("rfc7515.json")["A.2"]
    c = v["compact"]
    p = jws_policy(v["key"], "RS256")

    for value <- [-999_999_999_999_999, 999_999_999_999_999] do
      assert {:error, %{reason: :invalid_signature}} =
               JWS.verify(header(c, ~s({"alg":"RS256","n":#{value}})), p)
    end

    for value <- [-1_000_000_000_000_000, 1_000_000_000_000_000] do
      assert {:error, %{reason: :limit}} =
               JWS.verify(header(c, ~s({"alg":"RS256","n":#{value}})), p)
    end

    assert {:error, %{reason: :invalid_header}} =
             JWS.verify(header(c, ~s({"alg":"RS256","n":1.5})), p)

    for {n, reason} <- [{64, :invalid_signature}, {65, :limit}] do
      json =
        :json.encode(%{"alg" => "RS256", "a" => List.duplicate(nil, n)}) |> IO.iodata_to_binary()

      assert {:error, %{reason: ^reason}} = JWS.verify(header(c, json), p)
      members = Enum.map_join(1..(n - 1), ",", &~s("a#{&1}":null))

      assert {:error, %{reason: ^reason}} =
               JWS.verify(header(c, ~s({"alg":"RS256",#{members}})), p)
    end

    for {n, reason} <- [{4, :invalid_signature}, {5, :limit}] do
      value = String.duplicate("[", n - 1) <> "null" <> String.duplicate("]", n - 1)

      assert {:error, %{reason: ^reason}} =
               JWS.verify(header(c, ~s({"alg":"RS256","a":#{value}})), p)
    end

    for {n, reason} <- [{16384, :invalid_signature}, {16385, :limit}] do
      prefix = ~s({"alg":"RS256","s":")
      json = prefix <> String.duplicate("a", n - byte_size(prefix) - 2) <> ~s("})
      assert {:error, %{reason: ^reason}} = JWS.verify(header(c, json), p)
    end

    assert {:error, %{reason: :limit}} = JWS.verify(String.duplicate("a", 1_048_577), p)
  end
end
