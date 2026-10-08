defmodule RequestSeal.CryptoTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Crypto, PublicKey}

  @root Path.join(__DIR__, "fixtures/crypto")
  @vectors :json.decode(File.read!(Path.join(@root, "rfc9421.json")))
  @p384 :json.decode(File.read!(Path.join(@root, "rfc6979.json")))
  @ed :json.decode(File.read!(Path.join(@root, "rfc8032.json")))

  # Canonical small-order points from libsodium 1.0.18 ge25519_has_small_order,
  # expanding its sign-bit mask. These are public rejection vectors, not keys.
  # https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c (ge25519_has_small_order)
  @small_order_ed25519 ~w(
    0000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000080
    0100000000000000000000000000000000000000000000000000000000000000
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
  )

  for algorithm <- ["hmac-sha256", {:jws, "HS256"}], direction <- [:sign, :verify] do
    @tag :review_fix
    test "HMAC 31-byte rejection and 32-byte acceptance: #{inspect(algorithm)} #{direction}" do
      algorithm = unquote(Macro.escape(algorithm))
      message = "minimum HMAC key length"
      accepted = :binary.copy(<<0x42>>, 32)
      rejected = binary_part(accepted, 0, 31)

      case unquote(direction) do
        :sign ->
          assert {:ok, signature} = Crypto.sign(algorithm, message, {:hmac, accepted})
          assert signature == :crypto.mac(:hmac, :sha256, accepted, message)
          assert_error(Crypto.sign(algorithm, message, {:hmac, rejected}), :invalid_key)

        :verify ->
          signature = :crypto.mac(:hmac, :sha256, accepted, message)
          assert :ok = Crypto.verify(algorithm, message, signature, {:hmac, accepted})
          short_signature = :crypto.mac(:hmac, :sha256, rejected, message)

          assert_error(
            Crypto.verify(algorithm, message, short_signature, {:hmac, rejected}),
            :invalid_key
          )
      end
    end
  end

  for {point, index} <- Enum.with_index(@small_order_ed25519),
      format <- [:raw, :der, :pem, :jwk] do
    @tag :review_fix
    test "Ed25519 small-order point #{index} rejects at #{format} import" do
      format = unquote(format)
      valid = hex(hd(@ed)["PUBLIC KEY:"])
      assert {:ok, key} = PublicKey.import(ed25519_input(valid, format), format)
      assert key.material == {:ed25519, valid}

      assert_error(
        PublicKey.import(ed25519_input(hex(unquote(point)), format), format),
        :invalid_key
      )
    end
  end

  @tag :review_fix
  test "Ed25519 identity-key forgery rejects at import and supplied-struct validation" do
    identity = <<1>> <> :binary.copy(<<0>>, 31)
    signature = identity <> :binary.copy(<<0>>, 32)

    assert_error(
      Crypto.verify("ed25519", "a", signature, verification_key("ed25519")),
      :invalid_signature
    )

    assert_error(PublicKey.import({:ed25519, identity}, :raw), :invalid_key)

    for message <- ["a", "b", "completely different"] do
      assert_error(
        Crypto.verify("ed25519", message, signature, %PublicKey{material: {:ed25519, identity}}),
        :invalid_key
      )
    end
  end

  @tag :review_fix
  test "NOTICE locates the RFC 6979 P-256 key separately from P-384 fixtures" do
    notice = File.read!(Path.join(__DIR__, "../NOTICE"))
    assert notice =~ "RFC 6979 Appendix A.2.6"

    assert notice =~
             "The RFC 6979 Appendix A.2.5 P-256 public key is embedded in test/crypto_test.exs."
  end

  test "all six exact HTTP identifiers verify independent published vectors" do
    assert Crypto.algorithms() ==
             ~w(rsa-pss-sha512 rsa-v1_5-sha256 hmac-sha256 ecdsa-p256-sha256 ecdsa-p384-sha384 ed25519)

    assert length(@vectors) == 7

    for v <- @vectors do
      key = verification_key(v["key"])
      signature = Base.decode64!(v["signature"])
      assert :ok = Crypto.verify(v["algorithm"], v["base"], signature, key)

      assert_error(
        Crypto.verify(v["algorithm"], v["base"] <> "\n", signature, key),
        :invalid_signature
      )

      assert_error(
        Crypto.verify(v["algorithm"], v["base"], tamper(signature), key),
        :invalid_signature
      )

      assert {:ok, signed} = Crypto.sign(v["algorithm"], v["base"], signing_key(v["key"]))
      assert :ok = Crypto.verify(v["algorithm"], v["base"], signed, key)
      if v["key"] in ["rsa", "hmac", "ed25519"], do: assert(signed == signature)
    end

    assert {:ok, key} =
             PublicKey.import({:ec, "P-384", <<4>> <> hex(@p384["Ux"]) <> hex(@p384["Uy"])}, :raw)

    signature = hex(@p384["r"] <> @p384["s"])
    assert :ok = Crypto.verify("ecdsa-p384-sha384", "sample", signature, key)

    assert {:ok, signed} =
             Crypto.sign("ecdsa-p384-sha384", "sample", {:ec, "P-384", hex(@p384["x"])})

    assert :ok = Crypto.verify("ecdsa-p384-sha384", "sample", signed, key)
    assert_error(Crypto.verify("ecdsa-p384-sha384", "test", signature, key), :invalid_signature)
  end

  test "RFC 8032 Ed25519 vectors sign exact bytes without prehash" do
    for v <- @ed do
      assert {:ok, key} = PublicKey.import({:ed25519, hex(v["PUBLIC KEY:"])}, :raw)
      signature = hex(v["SIGNATURE:"])

      assert {:ok, ^signature} =
               Crypto.sign("ed25519", hex(v["MESSAGE"]), {:ed25519, hex(v["SECRET KEY:"])})

      assert :ok = Crypto.verify("ed25519", hex(v["MESSAGE"]), signature, key)
    end
  end

  test "SignatureBase output feeds published cryptographic cases unchanged" do
    inputs = :json.decode(File.read!(Path.join(__DIR__, "fixtures/signature_base/rfc9421.json")))

    for v <- @vectors, String.starts_with?(v["section"], "B.2.") do
      input = Enum.find(inputs, &(&1["section"] == v["section"]))
      assert input != nil
      m = input["message"]

      fields =
        Enum.map(m["fields"], fn [name, value] ->
          {:ok, field} =
            RequestSeal.FieldOccurrence.new(%{
              name: name,
              value: value,
              section: :headers,
              provenance: :http1
            })

          field
        end)

      {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
      {:ok, transport} = RequestSeal.TransportFacts.new(%{})
      attrs = %{fields: fields, body: body, transport: transport, trailers: :unavailable}

      {:ok, message} =
        if m["kind"] == "request" do
          RequestSeal.Message.new(
            Map.merge(attrs, %{
              kind: :request,
              method: m["method"],
              raw_target: m["raw_target"],
              target_form: :origin,
              scheme: m["scheme"],
              authority: m["authority"]
            })
          )
        else
          RequestSeal.Message.new(Map.merge(attrs, %{kind: :response, status: m["status"]}))
        end

      assert {:ok, base} = RequestSeal.SignatureBase.build(message, input["parameters"])
      assert base == v["base"]

      assert :ok =
               Crypto.verify(
                 v["algorithm"],
                 base,
                 Base.decode64!(v["signature"]),
                 verification_key(v["key"])
               )
    end
  end

  test "JWS extensions require explicit selection and keep HTTP and JOSE identifiers separate" do
    for name <- ["Ed25519", "RSA-PSS-SHA512", "PS256", "EdDSA", "none", "unknown", nil, :ed25519] do
      assert_error(Crypto.sign(name, "", signing_key("ed25519")), :unsupported_algorithm)
    end

    for name <- ["none", "RSA1_5", "rs256", "unknown"] do
      assert_error(Crypto.sign({:jws, name}, "", signing_key("rsa")), :unsupported_algorithm)
    end

    for {jws, http, id} <- [
          {"RS256", "rsa-v1_5-sha256", "rsa"},
          {"PS512", "rsa-pss-sha512", "rsa_pss"},
          {"ES256", "ecdsa-p256-sha256", "p256"},
          {"HS256", "hmac-sha256", "hmac"},
          {"EdDSA", "ed25519", "ed25519"}
        ] do
      v = Enum.find(@vectors, &(&1["algorithm"] == http))

      assert :ok =
               Crypto.verify(
                 {:jws, jws},
                 v["base"],
                 Base.decode64!(v["signature"]),
                 verification_key(id)
               )
    end

    for name <- ["PS256", "PS384"] do
      assert {:ok, signature} = Crypto.sign({:jws, name}, "sample", signing_key("rsa_pss"))
      assert :ok = Crypto.verify({:jws, name}, "sample", signature, verification_key("rsa_pss"))

      assert_error(
        Crypto.verify("rsa-pss-sha512", "sample", signature, verification_key("rsa_pss")),
        :invalid_signature
      )
    end
  end

  test "key types curves and algorithm restrictions reject cross-algorithm substitution" do
    for v <- @vectors,
        id <- ["rsa", "p256", "ed25519", "hmac"],
        id != v["key"],
        not (id == "rsa" and v["key"] == "rsa_pss") do
      assert_error(
        Crypto.verify(
          v["algorithm"],
          v["base"],
          Base.decode64!(v["signature"]),
          verification_key(id)
        ),
        :key_mismatch
      )

      assert_error(Crypto.sign(v["algorithm"], v["base"], signing_key(id)), :key_mismatch)
    end

    assert_error(
      Crypto.verify("rsa-v1_5-sha256", "", :binary.copy(<<0>>, 256), pss_only_key()),
      :key_mismatch
    )

    assert {:ok, jwk} = PublicKey.export(verification_key("p256"), :jwk)

    for {metadata, reason} <- [
          {%{"alg" => "ES384"}, :key_mismatch},
          {%{"use" => "enc"}, :key_mismatch},
          {%{"key_ops" => ["sign"]}, :key_mismatch}
        ] do
      assert {:ok, key} = PublicKey.import(Map.merge(jwk, metadata), :jwk)
      v = Enum.find(@vectors, &(&1["key"] == "p256"))

      assert_error(
        Crypto.verify(v["algorithm"], v["base"], Base.decode64!(v["signature"]), key),
        reason
      )
    end
  end

  test "signature lengths scalars DER confusion and Ed25519 canonical S reject" do
    for v <- @vectors do
      key = verification_key(v["key"])
      sig = Base.decode64!(v["signature"])

      for invalid <- [nil, [], "", binary_part(sig, 0, byte_size(sig) - 1), sig <> <<0>>] do
        assert_error(Crypto.verify(v["algorithm"], v["base"], invalid, key), :invalid_signature)
      end
    end

    v = Enum.find(@vectors, &(&1["key"] == "p256"))
    <<r::unsigned-big-256, s::unsigned-big-256>> = Base.decode64!(v["signature"])
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})

    for sig <- [
          der,
          :binary.copy(<<0>>, 64),
          <<0::256, s::256>>,
          <<r::256, 0::256>>,
          :binary.copy(<<255>>, 64)
        ] do
      assert_error(
        Crypto.verify(v["algorithm"], v["base"], sig, verification_key("p256")),
        :invalid_signature
      )
    end

    ed = hd(@ed)
    <<r::binary-size(32), s::little-unsigned-256>> = hex(ed["SIGNATURE:"])
    order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

    assert_error(
      Crypto.verify("ed25519", "", <<r::binary, s + order::little-256>>, verification_key_ed(ed)),
      :invalid_signature
    )
  end

  test "malformed primitive keys and oversized data return bounded errors" do
    for {alg, key} <- [
          {"ed25519", {:ed25519, <<0>>}},
          {"ed25519", {:ed25519, :binary.copy(<<0>>, 64)}},
          {"hmac-sha256", {:hmac, ""}},
          {"hmac-sha256", {:hmac, :bad}},
          {"ecdsa-p256-sha256", {:ec, "P-256", :binary.copy(<<0>>, 32)}},
          {"ecdsa-p256-sha256", {:ec, "P-256", :binary.copy(<<255>>, 32)}},
          {"rsa-v1_5-sha256", {:rsa, :bad}}
        ] do
      assert_error(Crypto.sign(alg, "sample", key), :invalid_key)
    end

    for data <- [nil, [], :binary.copy(<<0>>, 1_048_577)] do
      assert_error(Crypto.sign("ed25519", data, signing_key("ed25519")), :invalid_data)
    end

    assert_error(Crypto.verify("ed25519", "", <<0::512>>, :bad), :invalid_key)
    assert_error(Crypto.verify("ed25519", "", <<0::512>>, struct(PublicKey)), :invalid_key)
  end

  test "published SPKI bytes survive import and export on the active runtime" do
    for id <- ~w(rsa_pss p256 ed25519) do
      pem = File.read!(Path.join(@root, id <> "_public.pem"))
      [{:SubjectPublicKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)
      assert {:ok, key} = PublicKey.import(pem, :pem)
      assert {:ok, ^der} = PublicKey.export(key, :der)
    end
  end

  test "public PEM DER JWK and raw imports export equal public components" do
    for id <- ["rsa", "p256", "ed25519"] do
      key = verification_key(id)

      for format <- [:jwk, :pem, :der, :raw] do
        assert {:ok, encoded} = PublicKey.export(key, format)
        assert {:ok, imported} = PublicKey.import(encoded, format)
        assert imported == key
      end
    end

    key = pss_only_key()

    for format <- [:pem, :der, :raw] do
      assert {:ok, value} = PublicKey.export(key, format)
      assert PublicKey.import(value, format) == {:ok, key}
    end

    assert_error(PublicKey.export(key, :jwk), :unsupported_format)
  end

  test "public imports reject private material malformed integers points and metadata" do
    for id <- ["rsa", "rsa_pss", "p256", "ed25519"] do
      assert_error(
        PublicKey.import(File.read!(Path.join(@root, id <> "_private.pem")), :pem),
        :invalid_key
      )
    end

    assert {:ok, jwk} = PublicKey.export(verification_key("p256"), :jwk)

    for bad <- [
          Map.put(jwk, "d", "private-canary"),
          Map.put(jwk, "x", jwk["x"] <> "="),
          Map.put(jwk, "x", ""),
          Map.put(jwk, "x", Base.url_encode64(<<0>>, padding: false)),
          Map.put(jwk, "y", Base.url_encode64(:binary.copy(<<0>>, 32), padding: false)),
          Map.put(jwk, "crv", "P-384"),
          Map.put(jwk, "key_ops", ["verify", "verify"]),
          Map.put(jwk, "use", :sig),
          Map.put(jwk, "alg", :ES256),
          %{"kty" => "oct", "k" => "private-canary"}
        ] do
      assert_error(PublicKey.import(bad, :jwk), :invalid_key)
    end

    assert {:ok, rsa} = PublicKey.export(verification_key("rsa"), :jwk)

    for bad <- [
          Map.put(rsa, "n", "AA" <> rsa["n"]),
          Map.put(rsa, "e", "Ag"),
          Map.put(rsa, "n", "AQ"),
          Map.put(rsa, "oth", [])
        ] do
      assert_error(PublicKey.import(bad, :jwk), :invalid_key)
    end

    for bad <- [
          :bad,
          <<0>>,
          File.read!(Path.join(@root, "p256_public.pem")) <>
            File.read!(Path.join(@root, "rsa_public.pem"))
        ] do
      assert_error(PublicKey.import(bad, :pem), :invalid_key)
    end

    assert_error(PublicKey.import(<<0>>, :der), :invalid_key)
    assert_error(PublicKey.import({:ec, "P-256", <<4, 0::512>>}, :raw), :invalid_key)
    assert_error(PublicKey.import({:ed25519, <<0>>}, :raw), :invalid_key)
    assert_error(PublicKey.import({:rsa, -1, 65537}, :raw), :invalid_key)
    assert_error(PublicKey.import(jwk, :unknown), :unsupported_format)
    assert {:error, error} = PublicKey.import(Map.put(jwk, "d", "private-canary"), :jwk)
    refute inspect(error) =~ "private-canary"
  end

  test "fixture integrity inventory covers every published artifact" do
    lines = File.read!(Path.join(@root, "SHA256SUMS")) |> String.split("\n", trim: true)
    assert length(lines) == 12

    for line <- lines do
      [hash, name] = String.split(line, "  ")

      assert Base.encode16(:crypto.hash(:sha256, File.read!(Path.join(@root, name))),
               case: :lower
             ) == hash
    end

    assert Enum.sort(Enum.map(lines, &(String.split(&1, "  ") |> List.last()))) ==
             Enum.sort(File.ls!(@root) -- ["SHA256SUMS"])
  end

  test "RSA signing rejects inconsistent private components" do
    {:rsa, key} = signing_key("rsa")

    for index <- 4..9 do
      corrupt = put_elem(key, index, elem(key, index) + 2)
      assert_error(Crypto.sign("rsa-v1_5-sha256", "sample", {:rsa, corrupt}), :invalid_key)
    end

    assert_error(
      Crypto.sign("rsa-v1_5-sha256", "sample", {:rsa, put_elem(key, 1, :bad)}),
      :invalid_key
    )
  end

  test "every fixture checksum inventory exactly matches its directory" do
    manifests = Path.wildcard(Path.join(__DIR__, "fixtures/**/SHA256SUMS"))
    assert Path.join(@root, "SHA256SUMS") in manifests

    for manifest <- manifests do
      names =
        File.read!(manifest)
        |> String.split("\n", trim: true)
        |> Enum.map(&(String.split(&1, "  ") |> List.last()))

      root = Path.dirname(manifest)

      files =
        Path.wildcard(Path.join(root, "**/*"), match_dot: true)
        |> Enum.filter(&File.regular?/1)
        |> Enum.map(&Path.relative_to(&1, root))

      assert Enum.sort(names) == Enum.sort(files -- ["SHA256SUMS"]),
             "Fixture inventory mismatch: #{manifest}"
    end
  end

  test "public format limits canonical DER and preserved restrictions are enforced" do
    key = verification_key("p256")
    {:ok, jwk} = PublicKey.export(key, :jwk)
    {:ok, der} = PublicKey.export(key, :der)
    assert_error(PublicKey.import(der <> <<0>>, :der), :invalid_key)

    for format <- [:der, :pem] do
      assert_error(PublicKey.import(:binary.copy(<<0>>, 16_385), format), :invalid_key)
    end

    for bad <- [
          Map.put(jwk, "alg", nil),
          Map.put(jwk, "alg", String.duplicate("a", 65)),
          Map.put(jwk, "use", nil),
          Map.put(jwk, "key_ops", nil),
          Map.put(jwk, "key_ops", ["unknown"]),
          Map.put(jwk, "x", String.duplicate("a", 1367)),
          Map.merge(jwk, Map.new(1..33, &{Integer.to_string(&1), "a"}))
        ] do
      assert_error(PublicKey.import(bad, :jwk), :invalid_key)
    end

    assert {:ok, restricted} =
             PublicKey.import(
               Map.merge(jwk, %{"alg" => "ES256", "use" => "sig", "key_ops" => ["verify"]}),
               :jwk
             )

    assert PublicKey.export(restricted, :jwk) ==
             {:ok, Map.merge(jwk, %{"alg" => "ES256", "use" => "sig", "key_ops" => ["verify"]})}

    for format <- [:raw, :der, :pem],
        do: assert_error(PublicKey.export(restricted, format), :unsupported_format)

    assert_error(PublicKey.export(key, :unknown), :unsupported_format)
    assert_error(PublicKey.export(struct(PublicKey), :raw), :invalid_key)

    for bad <- [
          Map.put(key, :extra, :value),
          %{key | material: {:ec, "P-256", <<4, 0::512>>}},
          %{key | operations: ["unknown"]}
        ],
        do: assert_error(PublicKey.export(bad, :raw), :invalid_key)

    assert_error(
      PublicKey.import(
        {:ed25519,
         <<0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED::little-256>>},
        :raw
      ),
      :invalid_key
    )

    assert_error(PublicKey.import({:rsa, Bitwise.bsl(1, 8192) + 1, 65537}, :raw), :invalid_key)

    assert_error(
      PublicKey.import({:rsa, elem(verification_key("rsa").material, 1), 0x100000001}, :raw),
      :invalid_key
    )

    assert_error(
      Crypto.sign("hmac-sha256", "sample", {:hmac, :binary.copy(<<0>>, 16_385)}),
      :invalid_key
    )

    assert_error(Crypto.verify("hmac-sha256", "sample", <<0::256>>, {:hmac, ""}), :invalid_key)
    assert {:ok, empty_ops} = PublicKey.import(Map.put(jwk, "key_ops", []), :jwk)

    assert_error(
      Crypto.verify("ecdsa-p256-sha256", "sample", <<0::512>>, empty_ops),
      :key_mismatch
    )
  end

  test "P-384 rejects malformed signatures scalars and P-256 substitution symmetrically" do
    point = <<4>> <> hex(@p384["Ux"]) <> hex(@p384["Uy"])
    {:ok, key} = PublicKey.import({:ec, "P-384", point}, :raw)
    signature = hex(@p384["r"] <> @p384["s"])

    for malformed <- [
          binary_part(signature, 0, 95),
          signature <> <<0>>,
          raw_to_der(signature),
          <<0::768>>,
          <<0::384, 1::384>>,
          :binary.copy(<<255>>, 96)
        ] do
      assert_error(
        Crypto.verify("ecdsa-p384-sha384", "sample", malformed, key),
        :invalid_signature
      )
    end

    for scalar <- [<<0::384>>, :binary.copy(<<255>>, 48), binary_part(hex(@p384["x"]), 0, 47)] do
      assert_error(
        Crypto.sign("ecdsa-p384-sha384", "sample", {:ec, "P-384", scalar}),
        :invalid_key
      )
    end

    assert_error(Crypto.verify("ecdsa-p256-sha256", "sample", signature, key), :key_mismatch)

    assert_error(
      Crypto.verify("ecdsa-p384-sha384", "sample", signature, verification_key("p256")),
      :key_mismatch
    )

    assert_error(Crypto.sign("ecdsa-p384-sha384", "sample", signing_key("p256")), :key_mismatch)
    assert_error(PublicKey.import({:ec, "P-384", <<4, 0::768>>}, :raw), :invalid_key)
    assert_error(PublicKey.import({:ec, "unknown", point}, :raw), :invalid_key)
  end

  test "different published keys of the same type cannot verify each other" do
    for {id, other} <- [{"rsa", "rsa_pss"}, {"rsa_pss", "rsa"}] do
      v = Enum.find(@vectors, &(&1["key"] == id))

      assert_error(
        Crypto.verify(
          v["algorithm"],
          v["base"],
          Base.decode64!(v["signature"]),
          verification_key(other)
        ),
        :invalid_signature
      )
    end

    v = hd(@ed)

    assert_error(
      Crypto.verify(
        "ed25519",
        hex(v["MESSAGE"]),
        hex(v["SIGNATURE:"]),
        verification_key_ed(Enum.at(@ed, 1))
      ),
      :invalid_signature
    )

    v = Enum.find(@vectors, &(&1["key"] == "hmac"))
    {:hmac, secret} = verification_key("hmac")

    assert_error(
      Crypto.verify(
        "hmac-sha256",
        v["base"],
        Base.decode64!(v["signature"]),
        {:hmac, tamper(secret)}
      ),
      :invalid_signature
    )

    # Independent public key from RFC 6979 Appendix A.2.5.
    point =
      <<4>> <>
        hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6") <>
        hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")

    {:ok, other} = PublicKey.import({:ec, "P-256", point}, :raw)
    v = Enum.find(@vectors, &(&1["key"] == "p256"))

    assert_error(
      Crypto.verify(v["algorithm"], v["base"], Base.decode64!(v["signature"]), other),
      :invalid_signature
    )
  end

  test "unknown public formats cannot guess a supported key type or curve" do
    assert_error(PublicKey.export(:bad, :raw), :invalid_key)
    assert_error(PublicKey.import(%{"kty" => "unknown"}, :jwk), :invalid_key)
    {:ok, der} = PublicKey.export(verification_key("p256"), :der)

    {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, _}, point} =
      :public_key.der_decode(:SubjectPublicKeyInfo, der)

    bad_curve =
      spki_encode(oid, :EcpkParameters, {:namedCurve, {1, 3, 132, 0, 10}}, point)

    assert_error(PublicKey.import(bad_curve, :der), :invalid_key)

    bad_algorithm =
      :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 3, 101, 110}, :asn1_NOVALUE}, point}
      )

    assert_error(PublicKey.import(bad_algorithm, :der), :invalid_key)
    pss = pss_only_key()
    {:ok, der} = PublicKey.export(pss, :der)

    {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, _}, point} =
      :public_key.der_decode(:SubjectPublicKeyInfo, der)

    constrained =
      spki_encode(
        oid,
        :"RSASSA-PSS-params",
        {:"RSASSA-PSS-params", :asn1_DEFAULT, :asn1_DEFAULT, :asn1_DEFAULT, :asn1_DEFAULT},
        point
      )

    assert_error(PublicKey.import(constrained, :der), :invalid_key)
  end

  test "JWK algorithm ASCII and use-operation consistency reject before use" do
    {:ok, jwk} = PublicKey.export(verification_key("p256"), :jwk)

    for bad <- [
          Map.put(jwk, "alg", "é"),
          Map.merge(jwk, %{"use" => "sig", "key_ops" => ["encrypt"]}),
          Map.merge(jwk, %{"use" => "sig", "key_ops" => ["verify", "decrypt"]}),
          Map.merge(jwk, %{"use" => "enc", "key_ops" => ["verify"]})
        ] do
      assert_error(PublicKey.import(bad, :jwk), :invalid_key)
    end
  end

  test "OpenSSL reciprocally verifies all six primitives and each supported JWS extension" do
    assert System.find_executable("openssl") != nil
    {version, 0} = System.cmd("openssl", ["version"])
    IO.puts("RECIPROCAL TOOL: " <> String.trim(version))

    dir =
      Path.join(
        System.tmp_dir!(),
        "requestseal-crypto-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir!(dir)

    try do
      p384_key =
        {:ECPrivateKey, :ecPrivkeyVer1, hex(@p384["x"]), {:namedCurve, {1, 3, 132, 0, 34}},
         <<4>> <> hex(@p384["Ux"]) <> hex(@p384["Uy"]), :asn1_NOVALUE}

      File.write!(
        Path.join(dir, "p384_private.pem"),
        :public_key.pem_encode([ec_private_entry(p384_key)])
      )

      {:ok, p384_public} =
        PublicKey.import({:ec, "P-384", <<4>> <> hex(@p384["Ux"]) <> hex(@p384["Uy"])}, :raw)

      {:ok, p384_pem} = PublicKey.export(p384_public, :pem)
      File.write!(Path.join(dir, "p384_public.pem"), p384_pem)

      selectors =
        Crypto.algorithms() ++
          Enum.map(~w(RS256 PS256 PS384 PS512 ES256 ES384 HS256 EdDSA), &{:jws, &1})

      for selector <- selectors do
        {id, digest, pss, size} = reciprocal_parameters(selector)

        private =
          if id == "p384",
            do: Path.join(dir, "p384_private.pem"),
            else: Path.join(@root, id <> "_private.pem")

        public = if id == "p384", do: p384_public, else: verification_key(id)
        material = if id == "p384", do: {:ec, "P-384", hex(@p384["x"])}, else: signing_key(id)

        base =
          if id == "p384", do: "sample", else: Enum.find(@vectors, &(&1["key"] == id))["base"]

        input = Path.join(dir, "base")
        output = Path.join(dir, "signature")
        File.write!(input, base)
        assert {:ok, signature} = Crypto.sign(selector, base, material)

        cond do
          id == "hmac" ->
            {:hmac, secret} = material

            {mac, 0} =
              System.cmd("openssl", [
                "dgst",
                "-sha256",
                "-mac",
                "HMAC",
                "-macopt",
                "hexkey:" <> Base.encode16(secret),
                "-binary",
                input
              ])

            assert mac == signature
            assert :ok = Crypto.verify(selector, base, mac, public)

          true ->
            {:ok, pem} = PublicKey.export(public, :pem)
            public_file = Path.join(dir, "public.pem")
            File.write!(public_file, pem)

            options =
              if pss,
                do: [
                  "-sigopt",
                  "rsa_padding_mode:pss",
                  "-sigopt",
                  "rsa_pss_saltlen:" <> Integer.to_string(size),
                  "-sigopt",
                  "rsa_mgf1_md:" <> digest
                ],
                else: []

            File.write!(
              output,
              if(id in ["p256", "p384"], do: raw_to_der(signature), else: signature)
            )

            verify_args =
              if id == "ed25519",
                do: [
                  "pkeyutl",
                  "-verify",
                  "-pubin",
                  "-inkey",
                  public_file,
                  "-rawin",
                  "-in",
                  input,
                  "-sigfile",
                  output
                ],
                else:
                  ["dgst", "-" <> digest, "-verify", public_file, "-signature", output] ++
                    options ++ [input]

            {result, status} = System.cmd("openssl", verify_args, stderr_to_stdout: true)
            assert status == 0, result

            sign_args =
              if id == "ed25519",
                do: [
                  "pkeyutl",
                  "-sign",
                  "-inkey",
                  private,
                  "-rawin",
                  "-in",
                  input,
                  "-out",
                  output
                ],
                else:
                  ["dgst", "-" <> digest, "-sign", private, "-out", output] ++ options ++ [input]

            {result, status} = System.cmd("openssl", sign_args, stderr_to_stdout: true)
            assert status == 0, result
            peer = File.read!(output)
            peer = if id in ["p256", "p384"], do: der_to_raw(peer, size), else: peer
            assert :ok = Crypto.verify(selector, base, peer, public)
        end

        IO.puts("RECIPROCAL PASS: #{inspect(selector)} OTP -> OpenSSL and OpenSSL -> OTP")
      end

      input = Path.join(dir, "base")
      output = Path.join(dir, "signature")
      File.write!(input, Enum.find(@vectors, &(&1["key"] == "rsa_pss"))["base"])

      for {salt, mgf} <- [{32, "sha512"}, {64, "sha256"}] do
        {result, status} =
          System.cmd(
            "openssl",
            [
              "dgst",
              "-sha512",
              "-sign",
              Path.join(@root, "rsa_pss_private.pem"),
              "-out",
              output,
              "-sigopt",
              "rsa_padding_mode:pss",
              "-sigopt",
              "rsa_pss_saltlen:" <> Integer.to_string(salt),
              "-sigopt",
              "rsa_mgf1_md:" <> mgf,
              input
            ],
            stderr_to_stdout: true
          )

        assert status == 0, result

        assert_error(
          Crypto.verify(
            "rsa-pss-sha512",
            File.read!(input),
            File.read!(output),
            verification_key("rsa_pss")
          ),
          :invalid_signature
        )
      end
    after
      File.rm_rf!(dir)
    end
  end

  defp reciprocal_parameters(selector) do
    case selector do
      x when x in ["rsa-v1_5-sha256", {:jws, "RS256"}] -> {"rsa", "sha256", false, 0}
      x when x in ["rsa-pss-sha512", {:jws, "PS512"}] -> {"rsa_pss", "sha512", true, 64}
      {:jws, "PS256"} -> {"rsa_pss", "sha256", true, 32}
      {:jws, "PS384"} -> {"rsa_pss", "sha384", true, 48}
      x when x in ["ecdsa-p256-sha256", {:jws, "ES256"}] -> {"p256", "sha256", false, 32}
      x when x in ["ecdsa-p384-sha384", {:jws, "ES384"}] -> {"p384", "sha384", false, 48}
      x when x in ["hmac-sha256", {:jws, "HS256"}] -> {"hmac", "sha256", false, 32}
      x when x in ["ed25519", {:jws, "EdDSA"}] -> {"ed25519", "none", false, 0}
    end
  end

  defp raw_to_der(signature) do
    size = div(byte_size(signature), 2)
    <<r::unsigned-big-size(^size * 8), s::unsigned-big-size(^size * 8)>> = signature
    :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
  end

  defp der_to_raw(signature, size) do
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", signature)
    <<r::unsigned-big-size(size * 8), s::unsigned-big-size(size * 8)>>
  end

  defp pss_only_key do
    {:rsa, n, e} = verification_key("rsa_pss").material
    {:ok, key} = PublicKey.import({:rsa_pss, n, e}, :raw)
    key
  end

  defp verification_key("hmac"),
    do: {:hmac, File.read!(Path.join(@root, "hmac.txt")) |> String.trim() |> Base.decode64!()}

  defp verification_key(id) do
    {:ok, key} = PublicKey.import(File.read!(Path.join(@root, id <> "_public.pem")), :pem)
    key
  end

  defp signing_key("hmac"), do: verification_key("hmac")

  defp signing_key(id) do
    [entry] = :public_key.pem_decode(File.read!(Path.join(@root, id <> "_private.pem")))
    key = :public_key.pem_entry_decode(entry)

    case id do
      "rsa" -> {:rsa, key}
      "rsa_pss" -> {:rsa, elem(key, 0)}
      "p256" -> {:ec, "P-256", elem(key, 2)}
      "ed25519" -> {:ed25519, elem(key, 2)}
    end
  end

  defp verification_key_ed(v) do
    {:ok, key} = PublicKey.import({:ed25519, hex(v["PUBLIC KEY:"])}, :raw)
    key
  end

  defp spki_encode(oid, parameter_type, params, point) do
    :public_key.der_encode(
      :SubjectPublicKeyInfo,
      {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, params}, point}
    )
  rescue
    _ ->
      :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo,
         {:AlgorithmIdentifier, oid, :public_key.der_encode(parameter_type, params)}, point}
      )
  end

  defp ec_private_entry(key) do
    :public_key.pem_entry_encode(:ECPrivateKey, key)
  rescue
    _ -> :public_key.pem_entry_encode(:ECPrivateKey, put_elem(key, 1, 1))
  end

  defp ed25519_input(bytes, :raw), do: {:ed25519, bytes}

  defp ed25519_input(bytes, :jwk),
    do: %{"kty" => "OKP", "crv" => "Ed25519", "x" => Base.url_encode64(bytes, padding: false)}

  defp ed25519_input(bytes, :der) do
    :public_key.der_encode(
      :SubjectPublicKeyInfo,
      {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 3, 101, 112}, :asn1_NOVALUE}, bytes}
    )
  end

  defp ed25519_input(bytes, :pem),
    do:
      :public_key.pem_encode([
        {:SubjectPublicKeyInfo, ed25519_input(bytes, :der), :not_encrypted}
      ])

  defp hex(s), do: Base.decode16!(s, case: :mixed)
  defp tamper(<<b, rest::binary>>), do: <<Bitwise.bxor(b, 1), rest::binary>>

  defp assert_error(result, reason),
    do: assert(match?({:error, %{__struct__: RequestSeal.Crypto.Error, reason: ^reason}}, result))
end
