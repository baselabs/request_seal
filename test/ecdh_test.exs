defmodule RequestSeal.ECDHTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Custody, PublicKey}
  alias RequestSeal.Custody.Local
  alias RequestSeal.JOSE.{JWE, JWS, KeyManagement, Error}
  alias RequestSeal.JOSE.KeyManagement.Agreement
  import RequestSeal.JOSEVectors, only: [b64: 1, enc: 1, hex: 1, replace: 3]
  @algs ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)
  @alice "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  @bob_pub "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

  test "RFC 7518 Appendix C Concat KDF reproduces the published key exactly" do
    z =
      :erlang.list_to_binary([
        158,
        86,
        217,
        29,
        129,
        113,
        53,
        211,
        114,
        131,
        66,
        131,
        191,
        132,
        38,
        156,
        251,
        49,
        110,
        163,
        218,
        128,
        106,
        72,
        246,
        218,
        167,
        121,
        140,
        254,
        144,
        196
      ])

    assert Agreement.kdf(z, "A128GCM", "Alice", "Bob", 128) ==
             {:ok, b64("VqqN6vgjbSBcIijNcacQGg")}
  end

  test "RFC 7748 section 6.1 shared secret and RFC 8037 A.6 epk reproduce exactly" do
    {:ok, bob} = PublicKey.import({:x25519, hex(@bob_pub)}, :raw)

    assert Agreement.shared_secret(bob, {:x25519, hex(@alice)}) ==
             hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    assert {:ok, result} =
             Agreement.run("ECDH-ES+A128KW", "A128GCM", bob, %{}, hex(@alice), <<0::128>>)

    assert result.header["epk"] == %{
             "kty" => "OKP",
             "crv" => "X25519",
             "x" => "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
           }
  end

  test "X25519 public keys import and export JWK and raw forms" do
    raw = {:x25519, hex(@bob_pub)}
    jwk = %{"kty" => "OKP", "crv" => "X25519", "x" => enc(hex(@bob_pub))}
    assert {:ok, key} = PublicKey.import(raw, :raw)
    assert PublicKey.export(key, :jwk) == {:ok, jwk}
    assert {:ok, imported} = PublicKey.import(jwk, :jwk)
    assert PublicKey.export(imported, :raw) == {:ok, raw}
    assert {:ok, _} = PublicKey.thumbprint(key)
  end

  test "X25519 signature use is algorithm_mismatch" do
    {:ok, key} = PublicKey.import({:x25519, hex(@bob_pub)}, :raw)
    token = enc(~s({"alg":"EdDSA"})) <> "." <> enc("message") <> "." <> enc(<<0::512>>)

    assert {:error, %{reason: :algorithm_mismatch, layer: :key}} =
             JWS.verify(token, %{
               algorithms: ["EdDSA"],
               timeout: 5000,
               key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: key}} end
             })
  end

  for curve <- ["P-256", "P-384", "X25519"], alg <- @algs, cipher <- ~w(A128GCM A256GCM) do
    test "#{alg} #{curve} #{cipher} encrypts PublicKey recipients and decrypts custody handles" do
      {public, material} = pair(unquote(curve))
      alg = unquote(alg)
      cipher = unquote(cipher)
      {:ok, handle} = Local.new({:jwe, alg}, material)

      try do
        assert handle.capabilities == [:unwrap]
        assert {:ok, ^public} = Custody.public_key(handle)

        assert {:ok, token} =
                 JWE.encrypt(
                   [
                     {"alg", alg},
                     {"enc", cipher},
                     {"apu", enc("Alice")},
                     {"apv", enc("Bob")},
                     {"kid", "public-example"}
                   ],
                   "sealed",
                   public
                 )

        assert {:ok, result} = JWE.decrypt(token, policy(alg, cipher, handle))
        assert result.plaintext == "sealed"
        assert result.header["apu"] == enc("Alice")
        assert result.header["apv"] == enc("Bob")
        assert result.header["kid"] == "public-example"
        refute Map.has_key?(result.header["epk"], "d")
        assert {:ok, one} = KeyManagement.agree(alg, cipher, public, %{})
        assert {:ok, two} = KeyManagement.agree(alg, cipher, public, %{})
        refute one.cek == two.cek
        refute one.header == two.header

        for result <- [one, two] do
          params = params(alg, cipher, result.header["epk"])

          assert KeyManagement.unwrap(alg, result.encrypted_key, params, {:ecdh, material}) ==
                   {:ok, result.cek}

          assert Custody.unwrap(handle, [{result.encrypted_key, params, bit_size(result.cek)}]) ==
                   {:ok, [{:ok, result.cek}]}
        end

        {pid, _} = handle.ref.()
        assert catch_error(:sys.get_state(pid)) == :unsupported_operation
      after
        Custody.release(handle)
      end
    end
  end

  test "ECDH function recipient is refused before any key work and never receives a CEK" do
    observer = self()

    callback = fn _, _ ->
      send(observer, :received_cek)
      raise "must not run"
    end

    for alg <- @algs do
      assert JWE.encrypt([{"alg", alg}, {"enc", "A256GCM"}], "payload", callback) ==
               {:error, Error.new(:invalid_options, :input)}
    end

    refute_receive :received_cek
  end

  test "epk addition cannot replace a caller member" do
    {public, _} = pair("P-256")

    assert {:error, %{reason: :duplicate_member}} =
             JWE.encrypt(
               [{"alg", "ECDH-ES"}, {"enc", "A128GCM"}, {"epk", %{}}],
               "payload",
               public
             )
  end

  test "ECDH refuses unsupported algorithms content ciphers and extra decoded parties" do
    {public, _} = pair("P-256")

    assert {:error, %{reason: :algorithm_not_permitted}} =
             KeyManagement.agree("A256KW", "A128GCM", public, %{})

    assert {:error, %{reason: :algorithm_not_permitted}} =
             KeyManagement.agree("ECDH-ES", "unsupported", public, %{})

    assert {:error, %{reason: :invalid_header}} =
             KeyManagement.agree("ECDH-ES", "A128GCM", public, %{extra: true})
  end

  test "ECDH public recipients reject signature keys and incompatible JWK restrictions" do
    {public, _} = pair("P-256")
    {ed, _} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, ed} = PublicKey.import({:ed25519, ed}, :raw)

    for key <- [
          ed,
          %{public | algorithm: "ECDH-ES+A128KW"},
          %{public | use: "sig"},
          %{public | operations: ["verify"]},
          %{public | operations: ["encrypt"]},
          %{public | material: {:ec, "P-256", <<0>>}}
        ] do
      assert {:error, %{reason: :algorithm_mismatch}} =
               KeyManagement.agree("ECDH-ES", "A128GCM", key, %{})
    end
  end

  test "X25519 rejects malformed public widths private public imports and unsupported export formats" do
    for n <- [0, 31, 33] do
      assert {:error, %{reason: :invalid_key}} =
               PublicKey.import({:x25519, :binary.copy(<<0>>, n)}, :raw)
    end

    {:ok, key} = PublicKey.import({:x25519, hex(@bob_pub)}, :raw)
    {:ok, jwk} = PublicKey.export(key, :jwk)

    assert {:error, %{reason: :invalid_key}} =
             PublicKey.import(Map.put(jwk, "d", enc(hex(@alice))), :jwk)

    for format <- [:pem, :der] do
      assert {:error, %{reason: :unsupported_format}} = PublicKey.export(key, format)
    end
  end

  test "ECDH unwrap-only handles refuse wrap at construction" do
    {_, material} = pair("P-256")

    for alg <- @algs do
      assert {:error, %{reason: :invalid_options}} =
               Local.new({:jwe, alg}, material, capabilities: [:wrap])
    end
  end

  test "private EC and X25519 JWK import narrows key operations" do
    for curve <- ["P-256", "P-384", "X25519"], alg <- @algs do
      {public, material} = pair(curve)
      {:ok, jwk} = PublicKey.export(public, :jwk)
      scalar = elem(material, tuple_size(material) - 1)

      private =
        Map.merge(jwk, %{
          "d" => enc(scalar),
          "alg" => alg,
          "use" => "enc",
          "key_ops" => ["deriveKey"]
        })

      assert {:ok, handle} = Local.import({:jwe, alg}, private, :jwk)
      assert handle.capabilities == [:unwrap]
      Custody.release(handle)

      assert {:error, %{reason: :key_mismatch}} =
               Local.import({:jwe, alg}, Map.put(private, "key_ops", ["encrypt"]), :jwk)

      assert {:error, %{reason: :invalid_options}} =
               Local.import({:jwe, alg}, private, :jwk, capabilities: [:wrap])

      assert {:error, %{reason: :invalid_key}} =
               Local.import({:jwe, alg}, Map.put(private, "d", enc(<<0>>)), :jwk)
    end
  end

  for party <- [:apu, :apv] do
    test "over-long #{party} is refused by the KDF" do
      params = Map.put(%{apu: "Alice", apv: "Bob"}, unquote(party), :binary.copy("x", 1025))
      {public, _} = pair("P-256")

      assert {:error, %{reason: :invalid_header}} =
               KeyManagement.agree("ECDH-ES", "A128GCM", public, params)
    end
  end

  test "equal apu and apv are refused by the KDF" do
    {public, _} = pair("P-256")

    assert {:error, %{reason: :invalid_header}} =
             KeyManagement.agree("ECDH-ES", "A128GCM", public, %{apu: "same", apv: "same"})
  end

  for refusal <- [
        :private_d,
        :extra_member,
        :unsupported_curve,
        :coordinate_width,
        :coordinate_at_p,
        :off_curve,
        :infinity,
        :x25519_width,
        :undecodable_apu,
        :undecodable_apv,
        :overlong_apu,
        :overlong_apv,
        :equal_parties,
        :equal_empty_parties
      ] do
    test "epk parse layer refuses #{refusal} before any resolver call" do
      v = vector("5_4")
      h = v["encrypting_content"]["protected"]
      h = malformed(h, unquote(refusal))
      token = replace(v["output"]["compact"], 0, enc(IO.iodata_to_binary(:json.encode(h))))
      observer = self()

      p = %{
        algorithms: ["ECDH-ES+A128KW"],
        encryption: ["A128GCM"],
        max_plaintext: 1024,
        timeout: 5000,
        key_resolver: fn _ ->
          send(observer, :resolved)
          :error
        end
      }

      assert JWE.decrypt(token, p) == {:error, Error.new(:invalid_header, :input)}
      refute_receive :resolved
    end
  end

  test "direct ECDH-ES nonempty encrypted key fails crypto with zero resolver calls" do
    {public, _} = pair("P-256")
    {:ok, token} = JWE.encrypt([{"alg", "ECDH-ES"}, {"enc", "A128GCM"}], "payload", public)
    observer = self()

    p = %{
      algorithms: ["ECDH-ES"],
      encryption: ["A128GCM"],
      max_plaintext: 1024,
      timeout: 5000,
      key_resolver: fn _ ->
        send(observer, :resolved)
        :error
      end
    }

    assert JWE.decrypt(replace(token, 1, enc("bad")), p) ==
             {:error, Error.new(:decryption_failed, :crypto)}

    refute_receive :resolved
  end

  test "held-key curve and type mismatch take the fallback CEK path" do
    {public, _} = pair("P-256")
    {:ok, token} = JWE.encrypt([{"alg", "ECDH-ES"}, {"enc", "A128GCM"}], "payload", public)

    for curve <- ["P-384", "X25519"] do
      {_, material} = pair(curve)
      {:ok, handle} = Local.new({:jwe, "ECDH-ES"}, material)

      try do
        assert JWE.decrypt(token, policy("ECDH-ES", "A128GCM", handle)) ==
                 {:error, Error.new(:decryption_failed, :crypto)}
      after
        Custody.release(handle)
      end
    end
  end

  test "all-zero X25519 Z is refused by agreement and held-key unwrap" do
    {:ok, zero} = PublicKey.import({:x25519, <<0::256>>}, :raw)
    assert {:error, _} = KeyManagement.agree("ECDH-ES", "A128GCM", zero, %{})
    {public, material} = pair("X25519")
    {:ok, token} = JWE.encrypt([{"alg", "ECDH-ES"}, {"enc", "A128GCM"}], "payload", public)
    [protected | _] = String.split(token, ".")

    h =
      :json.decode(b64(protected))
      |> Map.put("epk", %{"kty" => "OKP", "crv" => "X25519", "x" => enc(<<0::256>>)})

    {:ok, handle} = Local.new({:jwe, "ECDH-ES"}, material)

    try do
      assert JWE.decrypt(
               replace(token, 0, enc(IO.iodata_to_binary(:json.encode(h)))),
               policy("ECDH-ES", "A128GCM", handle)
             ) == {:error, Error.new(:decryption_failed, :crypto)}
    after
      Custody.release(handle)
    end
  end

  for refusal <- [
        :corrupted,
        :wrong_recipient,
        :truncated,
        :overlong,
        :released,
        :wrong_algorithm,
        :content_tag
      ] do
    test "ECDH-ES+KW #{refusal} produces one closed failure without key bytes" do
      for alg <- ~w(ECDH-ES+A128KW ECDH-ES+A256KW) do
        {public, material} = pair("P-256")
        {:ok, handle} = Local.new({:jwe, alg}, material)
        {:ok, token} = JWE.encrypt([{"alg", alg}, {"enc", "A128GCM"}], "payload", public)

        try do
          {token, selected} = corrupt(unquote(refusal), token, handle, alg)

          assert JWE.decrypt(token, policy(alg, "A128GCM", selected)) ==
                   {:error, Error.new(:decryption_failed, :crypto)}

          if selected != handle, do: Custody.release(selected)
        after
          Custody.release(handle)
        end
      end
    end
  end

  test "RFC 7520 section 5.4 decrypts byte-exact through a P-384 handle" do
    v = vector("5_4")
    assert {:ok, handle} = Local.import({:jwe, "ECDH-ES+A128KW"}, v["input"]["key"], :jwk)

    try do
      assert {:ok, result} =
               JWE.decrypt(v["output"]["compact"], policy("ECDH-ES+A128KW", "A128GCM", handle))

      assert result.plaintext == v["input"]["plaintext"]
    after
      Custody.release(handle)
    end
  end

  test "RFC 7520 sections 5.5 and 5.7 reject CBC envelopes before resolution" do
    for prefix <- ["5_5", "5_7"] do
      v = vector(prefix)

      p = %{
        algorithms: [v["input"]["alg"]],
        encryption: ["A128GCM"],
        max_plaintext: 1024,
        timeout: 5000,
        key_resolver: fn _ -> flunk("must not resolve") end
      }

      assert {:error, %{reason: :algorithm_not_permitted}} =
               JWE.decrypt(v["output"]["compact"], p)
    end
  end

  test "primitive ECDH params are closed and supplied epk structs are revalidated" do
    {public, material} = pair("P-256")
    {:ok, a} = KeyManagement.agree("ECDH-ES", "A128GCM", public, %{})
    p = params("ECDH-ES", "A128GCM", a.header["epk"])

    for invalid <- [
          Map.put(p, :extra, true),
          Map.delete(p, :apu),
          %{p | key_bits: 192},
          %{p | algorithm_id: "wrong"},
          %{p | epk: %{p.epk | material: {:ec, "P-256", <<0>>}}}
        ] do
      assert {:error, %{reason: :invalid_header}} =
               KeyManagement.unwrap("ECDH-ES", "", invalid, {:ecdh, material})
    end
  end

  defp pair("X25519") do
    {pub, priv} = :crypto.generate_key(:ecdh, :x25519)
    {:ok, public} = PublicKey.import({:x25519, pub}, :raw)
    {public, {:x25519, priv}}
  end

  defp pair(curve) do
    {native, _, _} = RequestSeal.Crypto.Algorithm.curve(curve)
    {pub, priv} = :crypto.generate_key(:ecdh, native)
    {:ok, public} = PublicKey.import({:ec, curve, pub}, :raw)
    {public, {:ec, curve, priv}}
  end

  defp policy(alg, cipher, handle),
    do: %{
      algorithms: [alg],
      encryption: [cipher],
      max_plaintext: 1024,
      timeout: 5000,
      key_resolver: fn _ -> {:ok, %{algorithm: alg, key: handle}} end
    }

  defp params(alg, cipher, jwk) do
    {:ok, epk} = PublicKey.import(jwk, :jwk)

    %{
      epk: epk,
      apu: "",
      apv: "",
      algorithm_id: if(alg == "ECDH-ES", do: cipher, else: alg),
      key_bits:
        if(alg == "ECDH-ES+A128KW" or (alg == "ECDH-ES" and cipher == "A128GCM"),
          do: 128,
          else: 256
        )
    }
  end

  defp vector(prefix),
    do:
      Path.wildcard("corpus/sources/rfc7520/" <> prefix <> "*")
      |> hd()
      |> File.read!()
      |> :json.decode()

  defp malformed(h, kind) do
    epk = h["epk"]

    case kind do
      :private_d ->
        Map.put(h, "epk", Map.put(epk, "d", "AA"))

      :extra_member ->
        Map.put(h, "epk", Map.put(epk, "kid", "extra"))

      :unsupported_curve ->
        Map.put(h, "epk", Map.put(epk, "crv", "P-521"))

      :coordinate_width ->
        Map.put(h, "epk", Map.put(epk, "x", enc(<<0::376>>)))

      :coordinate_at_p ->
        Map.put(
          h,
          "epk",
          Map.put(
            epk,
            "x",
            enc(
              hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
              )
            )
          )
        )

      :off_curve ->
        Map.put(h, "epk", Map.merge(epk, %{"x" => enc(<<0::384>>), "y" => enc(<<0::384>>)}))

      :infinity ->
        Map.put(h, "epk", Map.merge(epk, %{"x" => "", "y" => ""}))

      :x25519_width ->
        Map.put(h, "epk", %{"kty" => "OKP", "crv" => "X25519", "x" => enc(<<0::248>>)})

      :undecodable_apu ->
        Map.put(h, "apu", "*")

      :undecodable_apv ->
        Map.put(h, "apv", "*")

      :overlong_apu ->
        Map.put(h, "apu", enc(:binary.copy("x", 1025)))

      :overlong_apv ->
        Map.put(h, "apv", enc(:binary.copy("x", 1025)))

      :equal_parties ->
        Map.merge(h, %{"apu" => enc("same"), "apv" => enc("same")})

      :equal_empty_parties ->
        Map.merge(h, %{"apu" => "", "apv" => ""})
    end
  end

  defp corrupt(:wrong_recipient, token, _, alg) do
    {_, material} = pair("P-256")
    {:ok, handle} = Local.new({:jwe, alg}, material)
    {token, handle}
  end

  defp corrupt(:released, token, handle, _),
    do:
      (
        Custody.release(handle)
        {token, handle}
      )

  defp corrupt(:wrong_algorithm, token, handle, _),
    do: {token, %{handle | algorithm: {:jwe, "ECDH-ES"}}}

  defp corrupt(kind, token, handle, _) do
    parts = String.split(token, ".")
    index = if kind == :content_tag, do: 4, else: 1
    original = parts |> Enum.at(index) |> b64()

    replacement =
      case kind do
        :truncated ->
          binary_part(original, 0, byte_size(original) - 1)

        :overlong ->
          original <> <<0::64>>

        _ ->
          <<Bitwise.bxor(:binary.first(original), 1)>> <>
            binary_part(original, 1, byte_size(original) - 1)
      end

    {replace(token, index, enc(replacement)), handle}
  end
end
