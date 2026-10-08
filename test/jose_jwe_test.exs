defmodule RequestSeal.JOSEJWETest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.{JWE, KeyManagement, Nested}
  import RequestSeal.JOSEVectors

  test "JWE encryption emits compact protected JSON with ordered wrapping additions" do
    v = fixture("5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json")
    key = {:aes, b64(v["input"]["key"]["k"])}
    wrap = fn alg, cek -> KeyManagement.wrap(alg, cek, %{}, key) end
    header = [{"alg", "A256GCMKW"}, {"kid", "k1"}, {"enc", "A128GCM"}]

    assert {:ok, compact} = JWE.encrypt(header, "plaintext", wrap)
    [protected, _, _, _, _] = String.split(compact, ".")
    json = b64(protected)
    additions = :json.decode(json)

    assert json ==
             ~s({"alg":"A256GCMKW","kid":"k1","enc":"A128GCM","iv":"#{additions["iv"]}","tag":"#{additions["tag"]}"})

    policy = %{
      algorithms: ["A256GCMKW"],
      encryption: ["A128GCM"],
      max_plaintext: 1_048_576,
      timeout: 5000,
      key_resolver: fn _ ->
        {:ok,
         %{
           algorithm: "A256GCMKW",
           unwrap: fn ek, h -> KeyManagement.unwrap("A256GCMKW", ek, h, key) end
         }}
      end
    }

    assert {:ok, result} = JWE.decrypt(compact, policy)
    assert result.plaintext == "plaintext"
  end

  test "RFC 7516 and RFC 7520 OAEP/GCM decrypt published bytes and exact stages" do
    a = fixture("rfc7516.json")
    b = fixture("5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json")

    for {compact, key, plaintext, cek, iv} <- [
          {a["compact"], a["key"], a["plaintext"], :binary.list_to_bin(a["cek"]),
           :binary.list_to_bin(a["iv"])},
          {b["output"]["compact"], b["input"]["key"], b["input"]["plaintext"],
           b64(b["generated"]["cek"]), b64(b["generated"]["iv"])}
        ] do
      [protected, ek, iv_wire, ct, tag] = String.split(compact, ".")
      h = b64(protected) |> :json.decode()
      assert KeyManagement.unwrap("RSA-OAEP", b64(ek), h, rsa(key)) == {:ok, cek}
      assert b64(iv_wire) == iv

      assert :crypto.crypto_one_time_aead(
               :aes_256_gcm,
               cek,
               iv,
               b64(ct),
               protected,
               b64(tag),
               false
             ) == plaintext

      assert {:ok, r} = JWE.decrypt(compact, jwe_policy(key, "RSA-OAEP", "A256GCM"))
      assert r.plaintext == plaintext
      assert r.protected == protected

      assert r.recipient_integrity == :valid and r.origin == :unbound and
               r.authorization == :not_evaluated

      refute inspect(r) =~ plaintext
    end
  end

  test "RFC 7520 direct GCM and GCM key unwrap stage" do
    v = fixture("5_6.direct_encryption_using_aes-gcm.json")

    assert {:ok, r} =
             JWE.decrypt(v["output"]["compact"], jwe_policy(v["input"]["key"], "dir", "A128GCM"))

    assert r.plaintext == v["input"]["plaintext"]
    w = fixture("5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json")

    assert KeyManagement.unwrap(
             "A256GCMKW",
             b64(w["encrypting_key"]["encrypted_key"]),
             w["encrypting_content"]["protected"],
             {:aes, b64(w["input"]["key"]["k"])}
           ) == {:ok, b64(w["generated"]["cek"])}
  end

  test "RFC 7520 one signed JWT nested in one JWE" do
    v = fixture("6.nesting_signatures_and_encryption.json")
    jp = jwe_policy(v["encrypt"]["input"]["key"], "RSA-OAEP", "A128GCM")
    sp = jws_policy(v["sign"]["input"]["key"], "PS256")

    assert {:ok, %{jws: s}} =
             Nested.verify(v["encrypt"]["output"]["compact"], jp, sp, content_types: ["JWT"])

    assert s.payload == v["sign"]["input"]["payload"]

    assert {:error, %{reason: :content_type_mismatch}} =
             Nested.verify(v["encrypt"]["output"]["compact"], jp, sp, content_types: ["JWS"])
  end

  test "IV/tag widths, tampering, empty encrypted key and plaintext bounds reject" do
    v = fixture("5_6.direct_encryption_using_aes-gcm.json")
    c = v["output"]["compact"]
    p = jwe_policy(v["input"]["key"], "dir", "A128GCM")

    for {index, width, reason} <- [{2, 12, :invalid_iv}, {4, 16, :invalid_tag}],
        n <- [width - 1, width + 1, 15, 17],
        n != width do
      assert {:error, %{reason: ^reason}} =
               JWE.decrypt(replace(c, index, enc(:crypto.strong_rand_bytes(n))), p)
    end

    [_, _, _, ct, tag] = String.split(c, ".")
    <<first, rest::binary>> = b64(tag)

    for bad <- [
          replace(c, 4, enc(<<Bitwise.bxor(first, 1), rest::binary>>)),
          replace(c, 3, enc(binary_part(b64(ct), 0, byte_size(b64(ct)) - 1))),
          header(
            c,
            ~s({ "alg":"dir","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a","enc":"A128GCM"})
          )
        ] do
      assert {:error, %{reason: :decryption_failed}} = JWE.decrypt(bad, p)
    end

    assert {:error, %{reason: :decryption_failed}} = JWE.decrypt(replace(c, 1, "YQ"), p)

    assert {:error, %{reason: :limit}} =
             JWE.decrypt(c, %{p | max_plaintext: byte_size(v["input"]["plaintext"]) - 1})

    assert {:ok, _} = JWE.decrypt(c, %{p | max_plaintext: byte_size(v["input"]["plaintext"])})
    a = fixture("rfc7516.json")
    ap = jwe_policy(a["key"], "RSA-OAEP", "A256GCM")

    assert {:error, %{reason: :decryption_failed}} =
             JWE.decrypt(replace(a["compact"], 1, "YQ"), ap)

    assert {:error, %{reason: :decryption_failed}} =
             JWE.decrypt(
               header(a["compact"], ~s({"alg":"RSA-OAEP-256","enc":"A256GCM"})),
               %{
                 ap
                 | algorithms: ["RSA-OAEP-256"],
                   key_resolver: fn _ ->
                     {:ok,
                      %{
                        algorithm: "RSA-OAEP-256",
                        unwrap: fn ek, h ->
                          KeyManagement.unwrap("RSA-OAEP-256", ek, h, rsa(a["key"]))
                        end
                      }}
                   end
               }
               |> then(& &1)
             )
  end

  test "Wycheproof inventory and all OAEP padding cases with real private key" do
    v = fixture("rsa_oaep_2048_sha256_mgf1sha256_test.json")
    assert v["numberOfTests"] == 37
    assert Enum.sum(Enum.map(v["testGroups"], &length(&1["tests"]))) == 37

    for g <- v["testGroups"], t <- g["tests"] do
      actual = KeyManagement.unwrap("RSA-OAEP-256", hex(t["ct"]), %{}, rsa(g["privateKeyJwk"]))

      if t["result"] == "valid" and t["label"] == "",
        do: assert(actual == {:ok, hex(t["msg"])}),
        else: assert(match?({:error, %{reason: :decryption_failed}}, actual))
    end

    assert hd(hd(v["testGroups"])["tests"])["result"] == "valid"
  end

  test "Wycheproof AES GCM inventory, tags and IV groups" do
    v = fixture("aes_gcm_test.json")
    assert v["numberOfTests"] == 316
    assert Enum.sum(Enum.map(v["testGroups"], &length(&1["tests"]))) == 316

    for g <- v["testGroups"], t <- g["tests"] do
      # GCMKW has empty AAD; published nonempty-AAD cases exercise the OTP
      # primitive separately and the envelope parser still enforces IV widths.
      key = hex(t["key"])
      iv = hex(t["iv"])
      ct = hex(t["ct"])
      tag = hex(t["tag"])

      if g["keySize"] in [128, 256] do
        alg = if g["keySize"] == 128, do: "A128GCMKW", else: "A256GCMKW"
        actual = KeyManagement.unwrap(alg, ct, %{"iv" => enc(iv), "tag" => enc(tag)}, {:aes, key})

        cond do
          byte_size(iv) != 12 -> assert match?({:error, %{reason: :invalid_iv}}, actual)
          byte_size(tag) != 16 -> assert match?({:error, %{reason: :invalid_tag}}, actual)
          t["aad"] == "" and t["result"] == "valid" -> assert actual == {:ok, hex(t["msg"])}
          true -> assert match?({:error, %{reason: :decryption_failed}}, actual)
        end
      end

      if byte_size(iv) == 12 and byte_size(tag) == 16 do
        result = :crypto.crypto_one_time_aead(:aes_gcm, key, iv, ct, hex(t["aad"]), tag, false)

        if t["result"] == "valid",
          do: assert(result == hex(t["msg"])),
          else: assert(result == :error)
      end
    end

    assert hd(hd(v["testGroups"])["tests"])["result"] == "valid"
  end
end

defmodule RequestSeal.JOSESafetyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.{JWE, JWS, KeyManagement, Nested}
  import RequestSeal.JOSEVectors
  import ExUnit.CaptureLog

  test "real CSPRNG failure while published AES still works emits only the safe marker" do
    assert byte_size(:crypto.strong_rand_bytes(16)) == 16

    dir =
      Path.join(System.tmp_dir!(), "requestseal-entropy-#{System.unique_integer([:positive])}")

    File.mkdir!(dir)
    conf = Path.join(dir, "openssl.cnf")

    File.write!(
      conf,
      "config_diagnostics = 1\nopenssl_conf = init\n[init]\nrandom = rng\n[rng]\nrandom = requestseal_nonexistent_random\nseed = requestseal_nonexistent_seed\n"
    )

    try do
      {out, status} =
        System.cmd(
          "elixir",
          [
            "-pa",
            Application.app_dir(:request_seal, "ebin"),
            "test/support/jose_entropy_check.exs"
          ],
          env: [{"OPENSSL_CONF", conf}],
          stderr_to_stdout: true
        )

      assert status == 0, out
      assert out == "CSPRNG FAILED; PUBLISHED AES WORKS; ENCRYPT/DECRYPT ENTROPY FAILURE\n"
    after
      File.rm_rf!(dir)
    end
  end

  test "every unsupported published serialization and selected algorithm rejects" do
    p = jws_policy(fixture("rfc7515.json")["A.2"]["key"], "RS256")

    for v <- [fixture("rfc7515.json")["A.4"], fixture("4_3.ecdsa_signature.json")["output"]] do
      assert {:error, %{reason: :algorithm_not_permitted}} = JWS.verify(v["compact"], p)
    end

    for name <-
          ~w(4_6.protecting_specific_header_fields.json 4_7.protecting_content_only.json 4_8.multiple_signatures.json) do
      v = fixture(name)

      for type <- ["json", "json_flat"], output = v["output"][type], output != nil do
        wire = :json.encode(output) |> IO.iodata_to_binary()
        assert {:error, %{reason: :unsupported_serialization}} = JWS.verify(wire, p)
      end
    end

    dir = fixture("5_6.direct_encryption_using_aes-gcm.json")
    jp = jwe_policy(dir["input"]["key"], "dir", "A128GCM")

    for name <-
          ~w(5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json 5_9.compressed_content.json 5_10.including_additional_authentication_data.json 5_11.protecting_specific_header_fields.json 5_12.protecting_content_only.json) do
      v = fixture(name)

      reason =
        if String.starts_with?(name, "5_9"),
          do: :compression_unsupported,
          else: :algorithm_not_permitted

      if v["output"]["compact"] do
        assert {:error, %{reason: ^reason}} = JWE.decrypt(v["output"]["compact"], jp)
      end

      for type <- ["json", "json_flat"], output = v["output"][type], output != nil do
        assert {:error, %{reason: :unsupported_serialization}} =
                 JWE.decrypt(:json.encode(output) |> IO.iodata_to_binary(), jp)
      end
    end
  end

  test "protected bytes are authenticated, CEK widths and selected encryption are enforced" do
    v = fixture("5_6.direct_encryption_using_aes-gcm.json")
    c = v["output"]["compact"]
    p = jwe_policy(v["input"]["key"], "dir", "A128GCM")

    assert {:error, %{reason: :algorithm_not_permitted}} =
             JWE.decrypt(c, %{p | encryption: ["A256GCM"]})

    assert {:error, %{reason: :duplicate_member}} =
             JWE.decrypt(header(c, ~s({"alg":"dir","enc":"A128GCM","enc":"A128GCM"})), p)

    for size <- [0, 15, 17, 31, 33] do
      key = :crypto.strong_rand_bytes(size)

      resolver = fn _ ->
        {:ok,
         %{
           algorithm: "dir",
           unwrap: fn ek, h -> KeyManagement.unwrap("dir", ek, h, {:cek, key}) end
         }}
      end

      assert {:error, %{reason: :decryption_failed}} =
               JWE.decrypt(c, %{p | key_resolver: resolver})
    end

    assert {:error, %{reason: :algorithm_mismatch}} =
             KeyManagement.wrap(
               "A128GCMKW",
               b64(v["input"]["key"]["k"]),
               %{},
               {:aes, :crypto.strong_rand_bytes(15)}
             )

    assert {:error, %{reason: :decryption_failed}} =
             KeyManagement.unwrap("dir", "nonempty", %{}, {:cek, b64(v["input"]["key"]["k"])})

    assert {:error, %{reason: :invalid_serialization}} =
             JWE.decrypt(String.duplicate("a", 1_048_576), p)

    assert {:error, %{reason: :limit}} = JWE.decrypt(String.duplicate("a", 1_048_577), p)
  end

  test "errors and actual crash/deadline paths withhold plaintext and secret diagnostics" do
    canary = "JOSE_sensitive_error_canary"
    v = fixture("5_6.direct_encryption_using_aes-gcm.json")
    p = jwe_policy(v["input"]["key"], "dir", "A128GCM")

    log =
      capture_log(fn ->
        crashing = fn _ -> raise canary end

        assert {:error, error} =
                 JWE.decrypt(v["output"]["compact"], %{p | key_resolver: crashing})

        assert error.reason == :key_resolver_failed
        refute inspect(error) =~ canary
        refute :erlang.term_to_binary(error) =~ canary
        refute :erlang.term_to_binary(error) =~ v["input"]["plaintext"]

        slow = fn request ->
          Process.sleep(100)
          p.key_resolver.(request)
        end

        assert {:error, %{reason: :deadline_exceeded, retryable: true}} =
                 JWE.decrypt(v["output"]["compact"], %{p | timeout: 1, key_resolver: slow})

        resolver = fn _ -> {:ok, %{algorithm: "dir", unwrap: fn _, _ -> raise canary end}} end

        assert {:error, %{reason: :decryption_failed, retryable: false}} =
                 JWE.decrypt(v["output"]["compact"], %{p | key_resolver: resolver})
      end)

    refute log =~ canary
    refute log =~ v["input"]["plaintext"]
  end

  test "callbacks run in sensitive workers and signers obey deadlines and handle bindings" do
    v = fixture("rfc7515.json")["A.2"]
    key = material(v["key"])
    owner = self()

    signer = fn alg, base ->
      send(owner, {:sign_worker, self(), {:sensitive, Process.flag(:sensitive, true)}})
      RequestSeal.Crypto.sign(alg, base, key)
    end

    assert {:ok, c} = JWS.sign([{"alg", "RS256"}], "payload", signer, timeout: 5000)
    assert_receive {:sign_worker, pid, {:sensitive, true}}
    assert pid != self()
    assert {:ok, _} = JWS.verify(c, jws_policy(v["key"], "RS256"))

    signer = fn alg, base ->
      Process.sleep(100)
      RequestSeal.Crypto.sign(alg, base, key)
    end

    assert {:error, %{reason: :deadline_exceeded}} =
             JWS.sign([{"alg", "RS256"}], "payload", signer, timeout: 1)

    assert {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "PS256"}, key)

    try do
      assert {:error, %{reason: :algorithm_mismatch}} =
               JWS.sign([{"alg", "RS256"}], "payload", handle, timeout: 5000)
    after
      RequestSeal.Custody.Local.release(handle)
    end
  end

  test "nested cty and depth reject without releasing the outer result" do
    v = fixture("6.nesting_signatures_and_encryption.json")
    jp = jwe_policy(v["encrypt"]["input"]["key"], "RSA-OAEP", "A128GCM")
    sp = jws_policy(v["sign"]["input"]["key"], "PS256")
    recipient = public(v["encrypt"]["input"]["key"])

    for payload <- [v["encrypt"]["output"]["compact"], "not-an-envelope"] do
      assert {:ok, c} =
               JWE.encrypt(
                 [{"alg", "RSA-OAEP"}, {"enc", "A128GCM"}, {"cty", "JWT"}],
                 payload,
                 recipient
               )

      assert {:error, %{reason: :nesting_depth}} =
               Nested.verify(c, jp, sp, content_types: ["JWT"])
    end

    signer = fn alg, base ->
      RequestSeal.Crypto.sign(alg, base, rsa(v["sign"]["input"]["key"]))
    end

    assert {:ok, inner} =
             JWS.sign([{"alg", "PS256"}, {"cty", "JWT"}], v["sign"]["input"]["payload"], signer)

    assert {:ok, c} =
             JWE.encrypt(
               [{"alg", "RSA-OAEP"}, {"enc", "A128GCM"}, {"cty", "JWT"}],
               inner,
               recipient
             )

    assert {:error, %{reason: :nesting_depth}} = Nested.verify(c, jp, sp, content_types: ["JWT"])

    assert {:ok, c} =
             JWE.encrypt(
               [{"alg", "RSA-OAEP"}, {"enc", "A128GCM"}],
               v["sign"]["output"]["compact"],
               recipient
             )

    assert {:error, %{reason: :content_type_mismatch}} =
             Nested.verify(c, jp, sp, content_types: ["JWT"])
  end
end

defmodule RequestSeal.JOSEGuardTest do
  use ExUnit.Case, async: false
  import RequestSeal.JOSEVectors
  alias RequestSeal.JOSE.{JWE, JWS, Header, Support, KeyManagement}

  test "nested options validate without calculating an unused timeout" do
    v = fixture("6.nesting_signatures_and_encryption.json")
    jp = jwe_policy(v["encrypt"]["input"]["key"], "RSA-OAEP", "A128GCM")
    sp = jws_policy(v["sign"]["input"]["key"], "PS256")

    for opts <- [
          nil,
          %{},
          [],
          [content_types: ["JWT"], content_types: ["JWT"]],
          [content_types: ["JWT"], timeout: 5000],
          [content_types: ["JWT"], extra: true]
        ] do
      assert {:error, %{reason: :invalid_options}} =
               RequestSeal.JOSE.Nested.verify(v["encrypt"]["output"]["compact"], jp, sp, opts)
    end

    assert {:ok, _} =
             RequestSeal.JOSE.Nested.verify(v["encrypt"]["output"]["compact"], jp, sp,
               content_types: ["JWT"]
             )
  end

  test "crypto faults and catchable shutdown exits share the redacted safe result" do
    faults =
      [fn -> :erlang.error(:badarg) end, fn -> throw("private-canary") end] ++
        Enum.map(
          [:shutdown, {:shutdown, "private-canary"}, :timeout, :normal],
          fn reason -> fn -> exit(reason) end end
        )

    for {reason, layer} <- [{:decryption_failed, :crypto}, {:invalid_signature, :crypto}],
        fault <- faults do
      assert {:error, error} = Support.safe(fault, reason, layer)
      assert error == RequestSeal.JOSE.Error.new(reason, layer)
      refute inspect(error) =~ "private-canary"
    end
  end

  test "public constructors and direct structs obey policy and option bounds" do
    v = fixture("rfc7515.json")["A.2"]
    p = jws_policy(v["key"], "RS256")
    signer = fn a, b -> RequestSeal.Crypto.sign(a, b, rsa(v["key"])) end

    for opts <- [
          [timeout: 0],
          [timeout: 300_001],
          [timeout: 5000, timeout: 5000],
          [unknown: true],
          nil
        ] do
      assert {:error, %{reason: :invalid_options}} =
               JWS.sign([{"alg", "RS256"}], "payload", signer, opts)
    end

    for policy <- [
          Map.delete(p, :timeout),
          Map.put(p, :unknown, true),
          %{p | timeout: 0},
          %{p | timeout: 300_001},
          %{p | key_resolver: nil},
          %{p | algorithms: []},
          %{p | algorithms: ["RS256", "RS256"]}
        ] do
      assert {:error, %{reason: :invalid_policy}} = JWS.verify(v["compact"], policy)
    end

    dir = fixture("5_6.direct_encryption_using_aes-gcm.json")
    jp = jwe_policy(dir["input"]["key"], "dir", "A128GCM")

    for policy <- [
          %{jp | max_plaintext: 0},
          %{jp | max_plaintext: 1_048_577},
          %{jp | encryption: []}
        ] do
      assert {:error, %{reason: :invalid_policy}} = JWE.decrypt(dir["output"]["compact"], policy)
    end

    assert {:error, %{reason: :detached_payload}} = JWS.sign([{"alg", "RS256"}], "", signer)

    assert {:error, %{reason: :duplicate_member}} =
             JWS.sign([{"alg", "RS256"}, {"alg", "RS256"}], "payload", signer)

    assert {:error, %{reason: :invalid_header}} = JWS.sign([{"alg", nil}], "payload", signer)

    assert {:error, %{reason: :invalid_header}} =
             JWS.sign([{"alg", "RS256"}, {"float", 1.0}], "payload", signer)

    assert {:error, %{reason: :invalid_header}} =
             JWS.sign([{"alg", "RS256"}, {"invalid", <<255>>}], "payload", signer)

    for value <- [
          List.duplicate(true, 65),
          Enum.reduce(1..4, nil, fn _, acc -> [acc] end),
          Map.new(1..65, &{Integer.to_string(&1), true})
        ] do
      assert {:error, %{reason: :limit}} =
               JWS.sign([{"alg", "RS256"}, {"value", value}], "payload", signer)
    end

    assert {:error, %{reason: :limit}} =
             JWS.sign(
               [{"alg", "RS256"} | Enum.map(1..64, &{Integer.to_string(&1), true})],
               "payload",
               signer
             )

    pss =
      File.read!("test/fixtures/crypto/rsa_pss_public.pem")
      |> then(&RequestSeal.PublicKey.import(&1, :pem))
      |> elem(1)

    assert {:error, %{reason: :invalid_signature}} =
             JWS.verify(v["compact"], %{
               p
               | key_resolver: fn _ -> {:ok, %{algorithm: "RS256", key: pss}} end
             })
  end

  test "headers expose JSON null consistently and complete objects reject trailing data" do
    assert Header.from_pairs([{"alg", "RS256"}, {"null", nil}])["null"] == nil
    {protected, h} = Header.serialize([{"alg", "RS256"}, {"null", nil}])
    assert h["null"] == nil
    assert b64(protected) =~ "null"

    assert {:error, %{reason: :invalid_header}} =
             Support.safe(fn -> Header.json(~s({"alg":"RS256"} trailing)) end)

    assert {:error, %{reason: :invalid_header}} =
             Support.safe(fn -> Header.json(~s(["RS256"])) end)

    assert {:error, %{reason: :invalid_header}} =
             Support.safe(fn -> Header.json(~s({"alg":"RS256")) end)

    assert {:error, %{reason: :invalid_base64}} =
             Support.safe(fn -> apply(Support, :decode, [nil]) end)

    assert {:error, %{reason: :invalid_serialization}} =
             JWS.verify(nil, jws_policy(fixture("rfc7515.json")["A.2"]["key"], "RS256"))
  end

  test "default Inspect hides explicit-access canaries, protected bytes and header selectors" do
    canary = "JOSE_sensitive_success_canary"
    v = fixture("rfc7515.json")["A.2"]
    signer = fn alg, base -> RequestSeal.Crypto.sign(alg, base, rsa(v["key"])) end
    assert {:ok, c} = JWS.sign([{"alg", "RS256"}, {"kid", canary}], canary, signer)
    assert {:ok, r} = JWS.verify(c, jws_policy(v["key"], "RS256"))
    assert r.payload == canary and r.header["kid"] == canary
    refute inspect(r) =~ canary
    refute inspect(r) =~ r.protected
    recipient = public(fixture("rfc7516.json")["key"])

    assert {:ok, c} =
             JWE.encrypt(
               [{"alg", "RSA-OAEP"}, {"enc", "A256GCM"}, {"kid", canary}],
               canary,
               recipient
             )

    assert {:ok, r} =
             JWE.decrypt(c, jwe_policy(fixture("rfc7516.json")["key"], "RSA-OAEP", "A256GCM"))

    assert r.plaintext == canary and r.header["kid"] == canary
    refute inspect(r) =~ canary
    refute inspect(r) =~ r.protected
  end

  test "RSA width rejects before the real OTP decrypt call; trace observes a known positive" do
    key = rsa(fixture("rfc7516.json")["key"])
    [_, encrypted, _, _, _] = String.split(fixture("rfc7516.json")["compact"], ".")
    owner = self()
    collector = spawn(fn -> collect(owner) end)
    :erlang.trace_pattern({:public_key, :decrypt_private, 3}, true, [:local])
    :erlang.trace(self(), true, [:call, {:tracer, collector}])

    try do
      assert {:ok, _} = KeyManagement.unwrap("RSA-OAEP", b64(encrypted), %{}, key)
      delivered = :erlang.trace_delivered(self())
      assert_receive {:trace_delivered, _, ^delivered}
      send(collector, {:drain, self()})
      assert_receive {:observed, positive}
      assert positive > 0

      for length <- [255, 257] do
        assert {:error, %{reason: :decryption_failed}} =
                 KeyManagement.unwrap("RSA-OAEP", :crypto.strong_rand_bytes(length), %{}, key)
      end

      delivered = :erlang.trace_delivered(self())
      assert_receive {:trace_delivered, _, ^delivered}
      send(collector, {:drain, self()})
      assert_receive {:observed, 0}
    after
      :erlang.trace(self(), false, [:call])
      :erlang.trace_pattern({:public_key, :decrypt_private, 3}, false, [:local])
      send(collector, :stop)
    end
  end

  defp collect(owner, n \\ 0) do
    receive do
      {:trace, ^owner, :call, {:public_key, :decrypt_private, _}} ->
        collect(owner, n + 1)

      {:drain, ^owner} ->
        send(owner, {:observed, n})
        collect(owner, 0)

      :stop ->
        :ok
    end
  end
end

defmodule RequestSeal.JOSECompositionTest do
  use ExUnit.Case, async: false
  import RequestSeal.JOSEVectors
  alias RequestSeal.JOSE.{JWE, JWS, KeyManagement}

  test "recipient public key restrictions and real wrapper additions cannot broaden selection" do
    v = fixture("rfc7516.json")
    p = public(v["key"])

    for bad <- [
          %{p | algorithm: "RSA-OAEP-256"},
          %{p | use: "sig"},
          %{p | operations: ["verify"]},
          public(fixture("rfc7515.json")["A.3"]["key"])
        ] do
      assert {:error, %{reason: :algorithm_mismatch}} =
               JWE.encrypt([{"alg", "RSA-OAEP"}, {"enc", "A256GCM"}], v["plaintext"], bad)
    end

    kek = :crypto.strong_rand_bytes(32)

    for {extra, reason} <- [
          {%{"zip" => "DEF"}, :unsupported_header},
          {%{"iv" => "duplicate"}, :duplicate_member}
        ] do
      wrapper = fn alg, cek ->
        {:ok, wrapped} = KeyManagement.wrap(alg, cek, %{}, {:aes, kek})
        additions = Map.merge(wrapped.header, extra)
        {:ok, %{wrapped | header: additions}}
      end

      header =
        if reason == :duplicate_member,
          do: [{"alg", "A256GCMKW"}, {"enc", "A256GCM"}, {"iv", "caller-iv"}],
          else: [{"alg", "A256GCMKW"}, {"enc", "A256GCM"}]

      assert {:error, %{reason: ^reason}} = JWE.encrypt(header, v["plaintext"], wrapper)
    end

    for n <- [15, 17] do
      wrapper = fn alg, cek ->
        {:ok, wrapped} = KeyManagement.wrap(alg, cek, %{}, {:aes, kek})
        header = Map.put(wrapped.header, "tag", enc(:crypto.strong_rand_bytes(n)))
        {:ok, %{wrapped | header: header}}
      end

      assert {:error, %{reason: :invalid_tag}} =
               JWE.encrypt([{"alg", "A256GCMKW"}, {"enc", "A256GCM"}], v["plaintext"], wrapper)
    end

    assert {:error, %{reason: :algorithm_mismatch}} =
             KeyManagement.wrap(
               "dir",
               :crypto.strong_rand_bytes(16),
               %{},
               {:cek, :crypto.strong_rand_bytes(16)}
             )

    assert {:error, %{reason: :algorithm_not_permitted}} =
             KeyManagement.wrap(
               "A128KW",
               :crypto.strong_rand_bytes(16),
               %{},
               {:aes, :crypto.strong_rand_bytes(16)}
             )

    assert {:error, %{reason: :algorithm_not_permitted}} =
             KeyManagement.unwrap(
               "A128KW",
               :crypto.strong_rand_bytes(16),
               %{},
               {:aes, :crypto.strong_rand_bytes(16)}
             )
  end

  test "resolver return shape remains closed" do
    v = fixture("rfc7515.json")["A.2"]
    p = jws_policy(v["key"], "RS256")

    resolver = fn request ->
      {:ok, entry} = p.key_resolver.(request)
      {:ok, Map.put(entry, :extra, true)}
    end

    assert {:error, %{reason: :key_resolver_failed}} =
             JWS.verify(v["compact"], %{p | key_resolver: resolver})

    v = fixture("5_6.direct_encryption_using_aes-gcm.json")
    p = jwe_policy(v["input"]["key"], "dir", "A128GCM")

    resolver = fn request ->
      {:ok, entry} = p.key_resolver.(request)
      {:ok, Map.put(entry, :extra, true)}
    end

    assert {:error, %{reason: :key_resolver_failed}} =
             JWE.decrypt(v["output"]["compact"], %{p | key_resolver: resolver})
  end
end

defmodule RequestSeal.JOSEBoundaryTest do
  use ExUnit.Case, async: false
  import RequestSeal.JOSEVectors
  alias RequestSeal.JOSE.{JWE, Header, Support, KeyManagement}

  test "decoder bounds reject before later malformed bytes and direct JSON has its own byte bound" do
    for {n, reason} <- [{16384, :invalid_header}, {16385, :limit}] do
      bytes = ~s({"alg":"RS256","a":") <> String.duplicate("a", n - 22)
      bytes = String.pad_trailing(bytes, n, "a")
      assert {:error, %{reason: ^reason}} = Support.safe(fn -> Header.json(bytes) end)
    end

    array = ~s({"alg":"RS256","a":[) <> Enum.join(List.duplicate("null", 65), ",") <> "]} broken"
    assert {:error, %{reason: :limit}} = Support.safe(fn -> Header.json(array) end)
    members = Enum.map_join(1..64, ",", &~s("x#{&1}":true))
    object = ~s({"alg":"RS256",#{members}} broken)
    assert {:error, %{reason: :limit}} = Support.safe(fn -> Header.json(object) end)
  end

  test "direct encryption cannot emit a nonempty encrypted key" do
    wrapper = fn alg, cek ->
      {:ok, wrapped} = KeyManagement.wrap(alg, cek, %{}, {:cek, cek})
      {:ok, %{wrapped | encrypted_key: :crypto.strong_rand_bytes(1)}}
    end

    assert {:error, %{reason: :decryption_failed}} =
             JWE.encrypt([{"alg", "dir"}, {"enc", "A128GCM"}], "", wrapper)
  end

  test "published GCMKW stage with shortened tag rejects before OTP" do
    v = fixture("5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json")
    h = v["encrypting_content"]["protected"]
    <<short::binary-size(15), _>> = b64(h["tag"])

    assert {:error, %{reason: :invalid_tag}} =
             KeyManagement.unwrap(
               "A256GCMKW",
               b64(v["encrypting_key"]["encrypted_key"]),
               Map.put(h, "tag", enc(short)),
               {:aes, b64(v["input"]["key"]["k"])}
             )
  end

  test "every vendored or extracted fixture hash agrees with the recorded inventory" do
    lines = File.read!("test/fixtures/jose/SHA256SUMS") |> String.split("\n", trim: true)
    assert length(lines) > 20
    assert Enum.any?(lines, &String.ends_with?(&1, "rfc7515.json"))

    for line <- lines do
      [digest, name] = String.split(line, "  ")

      assert :crypto.hash(:sha256, File.read!("test/fixtures/jose/" <> name))
             |> Base.encode16(case: :lower) == digest
    end
  end
end
