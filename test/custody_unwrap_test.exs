defmodule RequestSeal.CustodyUnwrapTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import ExUnit.CaptureIO
  require Logger
  alias RequestSeal.{Custody, PublicKey}
  alias RequestSeal.Custody.Local
  alias RequestSeal.JOSE.{JWE, KeyManagement, Support}

  setup_all do
    {:ok, private: :public_key.generate_key({:rsa, 2048, 65537})}
  end

  test "published RFC OAEP envelopes and Wycheproof SHA256 vectors unwrap through custody" do
    rfc = RequestSeal.JOSEVectors.fixture("rfc7516.json")

    cookbook =
      RequestSeal.JOSEVectors.fixture("5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json")

    for {key, compact, plaintext} <- [
          {rfc["key"], rfc["compact"], rfc["plaintext"]},
          {cookbook["input"]["key"], cookbook["output"]["compact"],
           cookbook["input"]["plaintext"]}
        ] do
      assert {:ok, handle} = Local.import({:jwe, "RSA-OAEP"}, key, :jwk)
      assert {:ok, result} = JWE.decrypt(compact, policy(handle, "RSA-OAEP"))
      assert result.plaintext == plaintext
      assert :ok = Local.release(handle)
    end

    vectors = RequestSeal.JOSEVectors.fixture("rsa_oaep_2048_sha256_mgf1sha256_test.json")

    for group <- vectors["testGroups"] do
      assert {:ok, handle} = Local.import({:jwe, "RSA-OAEP-256"}, group["privateKeyPem"], :pem)

      for v <- group["tests"], v["label"] == "" do
        result = Custody.unwrap(handle, Base.decode16!(v["ct"], case: :mixed))

        if v["result"] == "valid" and v["msg"] != "" do
          assert result == {:ok, Base.decode16!(v["msg"], case: :mixed)}
        else
          assert {:error, _} = result
        end
      end

      assert :ok = Local.release(handle)
    end
  end

  test "RSA-OAEP handles unwrap and round trip both content ciphers", %{private: private} do
    for alg <- ~w(RSA-OAEP RSA-OAEP-256) do
      assert {:ok, handle} = Local.new({:jwe, alg}, {:rsa, private})
      assert handle.capabilities == [:unwrap]
      assert {:ok, public} = Custody.public_key(handle)
      assert {:ok, identity} = Custody.identity(handle)
      assert identity.kind == :public

      for enc <- ~w(A128GCM A256GCM) do
        cek = :crypto.strong_rand_bytes(if enc == "A128GCM", do: 16, else: 32)
        assert {:ok, wrapped} = KeyManagement.wrap(alg, cek, %{}, public_descriptor(public))
        assert Custody.unwrap(handle, wrapped.encrypted_key) == {:ok, cek}
        assert {:ok, compact} = JWE.encrypt([{"alg", alg}, {"enc", enc}], "plaintext", public)
        assert {:ok, result} = JWE.decrypt(compact, policy(handle, alg, enc))
        assert result.plaintext == "plaintext"
      end

      assert_error(Custody.sign(handle, "bytes"), :unsupported_operation)
      assert_error(Custody.verify(handle, "bytes", <<0>>), :unsupported_operation)
      assert :ok = Local.release(handle)
      assert_error(Custody.unwrap(handle, :crypto.strong_rand_bytes(256)), :key_not_found)
    end
  end

  test "private PEM PKCS8 DER and JWK imports preserve OAEP binding", %{private: private} do
    pem = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, private)])

    {:PrivateKeyInfo, der, :not_encrypted} =
      :public_key.pem_entry_encode(:PrivateKeyInfo, private)

    jwk = private_jwk(private)

    for alg <- ~w(RSA-OAEP RSA-OAEP-256),
        {format, input} <- [pem: pem, der: der, jwk: jwk] do
      assert {:ok, handle} = Local.import({:jwe, alg}, input, format)
      assert {:ok, public} = Custody.public_key(handle)
      cek = :crypto.strong_rand_bytes(32)
      assert {:ok, wrapped} = KeyManagement.wrap(alg, cek, %{}, public_descriptor(public))
      assert Custody.unwrap(handle, wrapped.encrypted_key) == {:ok, cek}
      assert :ok = Local.release(handle)
    end

    for alg <- ~w(RSA-OAEP RSA-OAEP-256) do
      allowed = Map.merge(jwk, %{"alg" => alg, "use" => "enc", "key_ops" => ["unwrapKey"]})
      assert {:ok, handle} = Local.import({:jwe, alg}, allowed, :jwk)
      assert handle.capabilities == [:unwrap]
      assert {:ok, public} = Custody.public_key(handle)
      assert public.algorithm == alg and public.use == "enc"
      assert public.operations == ["unwrapKey"]
      assert :ok = Local.release(handle)

      for {field, value, reason} <- [
            {"alg", "RS256", :key_mismatch},
            {"use", "sig", :key_mismatch},
            {"key_ops", ["wrapKey"], :key_mismatch},
            {"key_ops", ["sign", "unwrapKey"], :invalid_key},
            {"key_ops", ["unwrapKey", "unwrapKey"], :invalid_key},
            {"key_ops", nil, :invalid_key},
            {"qi", "AQ", :invalid_key}
          ] do
        assert_error(Local.import({:jwe, alg}, Map.put(allowed, field, value), :jwk), reason)
      end

      assert_error(
        Local.new({:jwe, alg}, {:rsa, private}, equivalence: "identity"),
        :invalid_options
      )

      assert_error(Local.import({:jwe, alg}, Map.delete(jwk, "d"), :jwk), :invalid_key)
      assert_error(Local.import({:jwe, alg}, der <> <<0>>, :der), :invalid_key)

      assert_error(
        Local.import({:jwe, alg}, File.read!("test/fixtures/crypto/rsa_pss_private.pem"), :pem),
        :key_mismatch
      )
    end
  end

  test "invalid keys byte bounds and options reject", %{private: private} do
    assert {:ok, handle} = Local.new({:jwe, "RSA-OAEP-256"}, {:rsa, private})

    for value <- [nil, [], <<>>, :crypto.strong_rand_bytes(1025)] do
      assert_error(Custody.unwrap(handle, value), :invalid_data)
    end

    for opts <- [
          [timeout: 0],
          [timeout: :infinity],
          [timeout: 300_001],
          [timeout: 1, timeout: 2],
          [extra: true]
        ] do
      assert_error(Custody.unwrap(handle, <<0>>, opts), :invalid_options)
    end

    assert_error(Custody.unwrap(handle, :crypto.strong_rand_bytes(255)), :decryption_failed)

    for index <- 4..9 do
      assert_error(
        Local.new({:jwe, "RSA-OAEP"}, {:rsa, put_elem(private, index, elem(private, index) + 2)}),
        :invalid_key
      )
    end

    small = :public_key.generate_key({:rsa, 1024, 65537})
    assert_error(Local.new({:jwe, "RSA-OAEP"}, {:rsa, small}), :invalid_key)
    assert_error(Local.new({:jwe, "A128GCMKW"}, {:rsa, private}), :unsupported_algorithm)

    assert_error(
      Local.new({:jwe, "RSA-OAEP"}, {:hmac, :crypto.strong_rand_bytes(32)}),
      :key_mismatch
    )

    assert :ok = Local.release(handle)
  end

  test "wrong binding forged binding released and signing handles reject", %{private: private} do
    assert {:ok, handle} = Local.new({:jwe, "RSA-OAEP"}, {:rsa, private})
    assert {:ok, signing} = Local.new({:jws, "RS256"}, {:rsa, private})
    assert {:ok, public} = Custody.public_key(handle)

    assert {:ok, compact} =
             JWE.encrypt([{"alg", "RSA-OAEP-256"}, {"enc", "A256GCM"}], "plaintext", public)

    assert {:error, %{reason: :algorithm_mismatch}} =
             JWE.decrypt(compact, policy(handle, "RSA-OAEP-256"))

    assert {:error, %{reason: :algorithm_mismatch}} =
             JWE.decrypt(compact, policy(signing, "RSA-OAEP-256"))

    assert_error(Custody.unwrap(signing, :crypto.strong_rand_bytes(256)), :unsupported_operation)
    forged = %{handle | algorithm: {:jwe, "RSA-OAEP-256"}}
    assert_error(Custody.unwrap(forged, :crypto.strong_rand_bytes(256)), :key_mismatch)
    assert :ok = Local.release(handle)

    assert {:ok, compact} =
             JWE.encrypt([{"alg", "RSA-OAEP"}, {"enc", "A256GCM"}], "plaintext", public)

    assert {:error, %{reason: :decryption_failed}} =
             JWE.decrypt(compact, policy(handle, "RSA-OAEP"))

    assert :ok = Local.release(signing)
  end

  test "Node WebCrypto encrypts to each handle's exported public key", %{private: private} do
    for alg <- ~w(RSA-OAEP RSA-OAEP-256), enc <- ~w(A128GCM A256GCM) do
      assert {:ok, handle} = Local.new({:jwe, alg}, {:rsa, private})
      assert {:ok, public} = Custody.public_key(handle)
      assert {:ok, jwk} = PublicKey.export(public, :jwk)
      plaintext = :crypto.strong_rand_bytes(1024)

      request = %{
        operation: "encrypt",
        algorithm: alg,
        encryption: enc,
        key: jwk,
        plaintext: Support.b64(plaintext)
      }

      input = request |> :json.encode() |> IO.iodata_to_binary()

      compact =
        RequestSeal.JOSEPeer.with_input(input, fn path ->
          {out, status} = RequestSeal.JOSEPeer.run(path)
          assert status == 0, out
          :json.decode(out)["jwe"]
        end)

      assert {:ok, result} = JWE.decrypt(compact, policy(handle, alg, enc))
      assert result.plaintext == plaintext
      assert :ok = Local.release(handle)
    end
  end

  test "suspended holder unwrap honors deadlines and caller cancellation", %{private: private} do
    assert {:ok, handle} = Local.new({:jwe, "RSA-OAEP-256"}, {:rsa, private})
    assert {:ok, public} = Custody.public_key(handle)
    cek = :crypto.strong_rand_bytes(32)

    assert {:ok, wrapped} =
             KeyManagement.wrap("RSA-OAEP-256", cek, %{}, public_descriptor(public))

    assert {:ok, compact} =
             JWE.encrypt([{"alg", "RSA-OAEP-256"}, {"enc", "A256GCM"}], "plaintext", public)

    {holder, _} = handle.ref.()
    parent = self()
    original = handle.ref

    observed = %{
      handle
      | ref: fn ->
          send(parent, {:unwrap_runner, self()})
          receive do: (:continue -> original.())
        end
    }

    for mode <- [:deadline, :cancellation, :jwe_deadline] do
      assert :erlang.suspend_process(holder)

      caller =
        Task.async(fn ->
          if mode == :jwe_deadline,
            do: JWE.decrypt(compact, %{policy(observed, "RSA-OAEP-256") | timeout: 300}),
            else: Custody.unwrap(observed, wrapped.encrypted_key, timeout: 300)
        end)

      try do
        assert_receive {:unwrap_runner, runner}, 1000
        monitor = Process.monitor(runner)
        :erlang.trace(runner, true, [:send])
        send(runner, :continue)

        assert_receive {:trace, ^runner, :send, {:request, _, ^runner, _, _, {:unwrap, _, _}},
                        ^holder},
                       1000

        :erlang.trace(runner, false, [:send])

        if mode == :cancellation do
          Task.shutdown(caller, :brutal_kill)
        else
          assert {:error, %{reason: :deadline_exceeded, retryable: true}} =
                   Task.await(caller, 1000)
        end

        assert_receive {:DOWN, ^monitor, :process, ^runner, _}, 1000
      after
        Task.shutdown(caller, :brutal_kill)
        :erlang.resume_process(holder)
      end

      assert Custody.unwrap(handle, wrapped.encrypted_key) == {:ok, cek}
      refute_receive {_, {:ok, ^cek}}, 20
    end

    assert :ok = Local.release(handle)
  end

  test "RSA unwrap canaries stay out of values Inspect serialization output and crash reports", %{
    private: private
  } do
    <<131, canary::binary>> = :erlang.term_to_binary(elem(private, 5))
    text_canary = Integer.to_string(elem(private, 4))
    assert :erlang.term_to_binary(private) =~ canary
    assert inspect(private, limit: :infinity) =~ text_canary

    assert capture_log(fn -> Logger.warning("unwrap-log-positive-probe") end) =~
             "unwrap-log-positive-probe"

    assert capture_io(fn -> IO.write("unwrap-output-positive-probe") end) ==
             "unwrap-output-positive-probe"

    for alg <- ~w(RSA-OAEP RSA-OAEP-256) do
      assert {:ok, handle} = Local.new({:jwe, alg}, {:rsa, private})
      assert {:ok, public} = Custody.public_key(handle)
      cek = :crypto.strong_rand_bytes(32)
      assert {:ok, wrapped} = KeyManagement.wrap(alg, cek, %{}, public_descriptor(public))
      crashing = %{handle | ref: fn -> raise text_canary end}
      errors = [Custody.unwrap(handle, <<0>>), Custody.unwrap(crashing, wrapped.encrypted_key)]

      values = [
        handle,
        public,
        Custody.identity(handle),
        Custody.unwrap(handle, wrapped.encrypted_key) | errors
      ]

      for value <- values do
        refute :erlang.term_to_binary(value) =~ canary

        for structs <- [true, false],
            do: refute(inspect(value, structs: structs, limit: :infinity) =~ text_canary)
      end

      for {:error, error} <- errors,
          do: refute(Exception.format(:error, error, []) =~ text_canary)

      refute :erlang.term_to_binary(:erlang.fun_info(handle.ref)) =~ canary
      {holder, _} = handle.ref.()
      assert :sys.get_status(holder, 200) == {:error, :unsupported_operation}
      assert :erlang.suspend_process(holder)

      try do
        send(holder, {:secret_probe, private})
        assert Process.info(holder, [:dictionary, :messages]) == [dictionary: [], messages: []]
      after
        :erlang.resume_process(holder)
      end

      output =
        capture_io(fn ->
          log =
            capture_log(fn ->
              assert_error(Custody.unwrap(crashing, wrapped.encrypted_key), :custodian_failure)

              assert_error(
                Custody.unwrap(handle, :crypto.strong_rand_bytes(256)),
                :decryption_failed
              )

              monitor = Process.monitor(holder)
              Process.exit(holder, :kill)
              assert_receive {:DOWN, ^monitor, :process, ^holder, :killed}
              assert_error(Custody.unwrap(handle, wrapped.encrypted_key), :key_not_found)
            end)

          refute log =~ text_canary
          refute log =~ canary
        end)

      refute output =~ text_canary
      refute output =~ canary
    end
  end

  defp policy(handle, alg, enc \\ "A256GCM") do
    %{
      algorithms: [alg],
      encryption: [enc],
      max_plaintext: 2048,
      timeout: 5000,
      key_resolver: fn _ -> {:ok, %{algorithm: alg, key: handle}} end
    }
  end

  defp public_descriptor(%PublicKey{material: {:rsa, n, e}}), do: {:rsa, {:RSAPublicKey, n, e}}

  defp private_jwk(private) do
    values = for i <- 2..9, do: Support.b64(:binary.encode_unsigned(elem(private, i)))
    Map.new(Enum.zip(~w(n e d p q dp dq qi), values)) |> Map.put("kty", "RSA")
  end

  defp assert_error(result, reason) do
    assert {:error, %Custody.Error{reason: ^reason}} = result
  end
end
