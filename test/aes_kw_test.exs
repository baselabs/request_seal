defmodule RequestSeal.AESKWTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Custody
  alias RequestSeal.Custody.Local
  alias RequestSeal.JOSE.{JWE, KeyManagement, Error}
  import RequestSeal.JOSEVectors, only: [hex: 1]

  @k128 "000102030405060708090A0B0C0D0E0F"
  @k256 "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
  @key "00112233445566778899AABBCCDDEEFF"
  @wrapped "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"

  test "RFC 3394 sections 4.1 and 4.3 wrap and unwrap published bytes" do
    for {alg, kek, wrapped} <- [
          {"A128KW", @k128, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
          {"A256KW", @k256, @wrapped}
        ] do
      assert {:ok, %{encrypted_key: actual, header: %{}}} =
               KeyManagement.wrap(alg, hex(@key), %{}, {:aes, hex(kek)})

      assert actual == hex(wrapped)
      assert KeyManagement.unwrap(alg, hex(wrapped), %{}, {:aes, hex(kek)}) == {:ok, hex(@key)}
    end
  end

  test "RFC 7520 section 5.8 decrypts published AES-KW envelope bytes through custody" do
    v = RequestSeal.JOSEVectors.fixture("5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json")
    {:ok, handle} = Local.import({:jwe, "A128KW"}, v["input"]["key"], :jwk)

    try do
      assert {:ok, result} =
               JWE.decrypt(v["output"]["compact"], policy("A128KW", "A128GCM", handle))

      assert result.plaintext == v["input"]["plaintext"]
    after
      Custody.release(handle)
    end
  end

  test "AES-KW round trips through wrap and unwrap capabilities and JWE" do
    for {alg, kek} <- [{"A128KW", @k128}, {"A256KW", @k256}], enc <- ~w(A128GCM A256GCM) do
      {:ok, handle} = Local.new({:jwe, alg}, {:aes, hex(kek)})

      try do
        assert handle.capabilities == [:wrap, :unwrap]
        cek = :crypto.strong_rand_bytes(if enc == "A128GCM", do: 16, else: 32)
        assert {:ok, %{encrypted_key: ek, params: %{}}} = Custody.wrap(handle, cek)
        assert Custody.unwrap(handle, [{ek, %{}, bit_size(cek)}]) == {:ok, [{:ok, cek}]}
        assert {:ok, compact} = JWE.encrypt([{"alg", alg}, {"enc", enc}], "sealed", handle)
        assert {:ok, %{plaintext: "sealed"}} = JWE.decrypt(compact, policy(alg, enc, handle))
        {pid, _} = handle.ref.()
        assert catch_error(:sys.get_state(pid)) == :unsupported_operation
      after
        assert :ok = Custody.release(handle)
        assert :ok = Custody.release(handle)
      end
    end
  end

  test "AES-KW primitive and custodian reject corrupt wrong-key truncated and over-long keys without key bytes" do
    wrong = :binary.copy(<<255>>, 32)

    for {name, wrapped, kek} <- [
          {:corrupt, <<0::192>>, hex(@k256)},
          {:wrong_kek, hex(@wrapped), wrong},
          {:truncated, binary_part(hex(@wrapped), 0, 23), hex(@k256)},
          {:over_long, hex(@wrapped) <> <<0::64>>, hex(@k256)}
        ] do
      assert KeyManagement.unwrap("A256KW", wrapped, %{}, {:aes, kek}) ==
               {:error, Error.new(:decryption_failed, :crypto)},
             inspect(name)

      {:ok, handle} = Local.new({:jwe, "A256KW"}, {:aes, kek})

      try do
        assert Custody.unwrap(handle, [{wrapped, %{}, 128}]) ==
                 {:ok, [{:error, :decryption_failed}]},
               inspect(name)
      after
        Custody.release(handle)
      end
    end
  end

  test "released and forged handles settle one closed unwrap failure" do
    {:ok, handle} = Local.new({:jwe, "A256KW"}, {:aes, hex(@k256)})
    forged = %{handle | algorithm: {:jwe, "A128KW"}}

    assert Custody.unwrap(forged, [{hex(@wrapped), %{}, 128}]) ==
             {:ok, [{:error, :decryption_failed}]}

    assert :ok = Custody.release(handle)

    assert Custody.unwrap(handle, [{hex(@wrapped), %{}, 128}]) ==
             {:ok, [{:error, :decryption_failed}]}
  end

  test "exact KEK sizes and RFC 5649 padding are refused" do
    for alg <- ~w(A128KW A256KW), length <- [0, 15, 17, 24, 31, 33] do
      kek = :binary.copy(<<0>>, length)

      assert {:error, %{reason: :algorithm_mismatch, layer: :key}} =
               KeyManagement.wrap(alg, hex(@key), %{}, {:aes, kek})

      assert {:error, %{reason: :algorithm_mismatch, layer: :key}} =
               KeyManagement.unwrap(alg, hex(@wrapped), %{}, {:aes, kek})
    end

    for length <- [0, 1, 8, 15, 17, 23] do
      assert {:error, %{reason: :algorithm_mismatch}} =
               KeyManagement.wrap("A128KW", :binary.copy(<<0>>, length), %{}, {:aes, hex(@k128)})
    end
  end

  test "closed params reject headers extra fields and malformed GCMKW parameters" do
    for params <- [%{"alg" => "A256KW"}, %{iv: <<0::96>>}, nil] do
      assert {:error, %{reason: :invalid_header}} =
               KeyManagement.unwrap("A256KW", hex(@wrapped), params, {:aes, hex(@k256)})
    end

    for params <- [
          %{},
          %{"iv" => "", "tag" => ""},
          %{iv: <<0::96>>, tag: <<0::128>>, extra: true}
        ] do
      assert {:error, %{reason: :invalid_header}} =
               KeyManagement.unwrap("A256GCMKW", <<0::128>>, params, {:aes, hex(@k256)})
    end

    assert {:error, %{reason: :invalid_iv}} =
             KeyManagement.unwrap(
               "A256GCMKW",
               <<0::128>>,
               %{iv: <<0>>, tag: <<0::128>>},
               {:aes, hex(@k256)}
             )

    assert {:error, %{reason: :invalid_tag}} =
             KeyManagement.unwrap(
               "A256GCMKW",
               <<0::128>>,
               %{iv: <<0::96>>, tag: <<0>>},
               {:aes, hex(@k256)}
             )
  end

  test "unwrap list item count key width content bits and params are bounded" do
    {:ok, handle} = Local.new({:jwe, "A256KW"}, {:aes, hex(@k256)})

    try do
      for items <- [
            nil,
            [],
            List.duplicate({"", %{}, 128}, 10_001),
            [{<<0::8200>>, %{}, 128}],
            [{"", %{}, 192}],
            [{"", %{extra: true}, 128}],
            ["bad"]
          ] do
        assert {:error, %{reason: :invalid_data}} = Custody.unwrap(handle, items)
      end

      assert {:ok, [{:error, :decryption_failed}]} = Custody.unwrap(handle, [{"", %{}, 128}])
    after
      Custody.release(handle)
    end
  end

  test "capabilities are nonempty unique subsets and unwrap-only families refuse wrap at construction" do
    for {alg, material} <- [
          {"A128GCMKW", {:aes, hex(@k128)}},
          {"A256GCMKW", {:aes, hex(@k256)}},
          {"dir", {:cek, hex(@key)}}
        ] do
      assert {:error, %{reason: :invalid_options}} =
               Local.new({:jwe, alg}, material, capabilities: [:wrap])
    end

    for caps <- [[], [:wrap, :wrap], [:sign], [:unwrap, :sign]] do
      assert {:error, %{reason: :invalid_options}} =
               Local.new({:jwe, "A256KW"}, {:aes, hex(@k256)}, capabilities: caps)
    end

    for caps <- [[:wrap], [:unwrap], [:wrap, :unwrap]] do
      assert {:ok, handle} = Local.new({:jwe, "A256KW"}, {:aes, hex(@k256)}, capabilities: caps)
      assert handle.capabilities == caps
      Custody.release(handle)
    end
  end

  test "GCMKW and dir encrypt and primitive wrap refusals precede every recipient and key validation" do
    observer = self()
    cek = hex(@key)

    for alg <- ~w(A128GCMKW A256GCMKW dir) do
      kek = hex(if alg == "A128GCMKW", do: @k128, else: @k256)
      # This is a real 1.x recipient callback, with actual cryptography. It
      # must never be invoked after admission removes its algorithm.
      valid_recipient = fn selected, generated_cek ->
        send(observer, :recipient_invoked)

        if selected == "dir" do
          {:ok, %{encrypted_key: "", header: %{}}}
        else
          iv = :crypto.strong_rand_bytes(12)
          {ek, tag} = :crypto.crypto_one_time_aead(:aes_gcm, kek, iv, generated_cek, "", 16, true)

          {:ok,
           %{
             encrypted_key: ek,
             header: %{
               "iv" => Base.url_encode64(iv, padding: false),
               "tag" => Base.url_encode64(tag, padding: false)
             }
           }}
        end
      end

      for recipient <- [valid_recipient, :invalid, nil] do
        assert JWE.encrypt([{"alg", alg}, {"enc", "A256GCM"}], "payload", recipient) ==
                 {:error, Error.new(:algorithm_not_permitted, :input)}
      end

      material = if alg == "dir", do: {:cek, cek}, else: {:aes, kek}

      for descriptor <- [material, :invalid, nil] do
        assert KeyManagement.wrap(alg, cek, %{}, descriptor) ==
                 {:error, Error.new(:algorithm_not_permitted, :input)}
      end

      assert KeyManagement.wrap(alg, :invalid, :invalid, :invalid) ==
               {:error, Error.new(:algorithm_not_permitted, :input)}
    end

    refute_receive :recipient_invoked

    assert KeyManagement.unwrap("unknown", :invalid, :invalid, :invalid) ==
             {:error, Error.new(:algorithm_not_permitted, :input)}
  end

  test "key-agreement family uses agree and remains refused by primitive wrap" do
    for alg <- ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW) do
      assert KeyManagement.wrap(alg, hex(@key), %{}, {:aes, hex(@k256)}) ==
               {:error, Error.new(:algorithm_not_permitted, :input)}
    end
  end

  test "wrap telemetry has only an outcome and unwrap exposes no item outcome" do
    id = make_ref()
    observer = self()

    :telemetry.attach_many(
      id,
      [[:request_seal, :custody, :wrap], [:request_seal, :custody, :unwrap]],
      fn event, _, metadata, _ -> send(observer, {:event, event, metadata}) end,
      nil
    )

    {:ok, handle} = Local.new({:jwe, "A256KW"}, {:aes, hex(@k256)})

    try do
      assert {:ok, %{encrypted_key: ek}} = Custody.wrap(handle, hex(@key))
      assert_receive {:event, [:request_seal, :custody, :wrap], %{outcome: :ok} = meta}
      assert map_size(meta) == 1
      assert {:error, _} = Custody.wrap(%{handle | capabilities: [:unwrap]}, hex(@key))
      assert_receive {:event, [:request_seal, :custody, :wrap], %{outcome: :failed} = meta}
      assert map_size(meta) == 1
      Custody.unwrap(handle, [{ek, %{}, 128}, {<<0>>, %{}, 128}])
      assert_receive {:event, [:request_seal, :custody, :unwrap], unwrap_meta}
      assert unwrap_meta == %{}
      refute_receive {:event, [:request_seal, :custody, :unwrap], %{outcome: _}}
    after
      :telemetry.detach(id)
      Custody.release(handle)
    end
  end

  test "symmetric JWK import binds the key-management family and narrows capabilities" do
    for {alg, key} <- [
          {"A128KW", hex(@k128)},
          {"A256KW", hex(@k256)},
          {"A128GCMKW", hex(@k128)},
          {"A256GCMKW", hex(@k256)},
          {"dir", hex(@key)}
        ] do
      jwk = %{
        "kty" => "oct",
        "k" => Base.url_encode64(key, padding: false),
        "alg" => alg,
        "use" => "enc"
      }

      assert {:ok, handle} = Local.import({:jwe, alg}, jwk, :jwk)
      assert :ok = Custody.release(handle)
      ops = if alg in ~w(A128KW A256KW), do: ["wrapKey"], else: ["unwrapKey"]
      assert {:ok, handle} = Local.import({:jwe, alg}, Map.put(jwk, "key_ops", ops), :jwk)
      assert handle.capabilities == if(ops == ["wrapKey"], do: [:wrap], else: [:unwrap])
      assert :ok = Custody.release(handle)

      assert {:error, %{reason: :key_mismatch}} =
               Local.import({:jwe, alg}, Map.put(jwk, "use", "sig"), :jwk)
    end
  end

  defp policy(alg, enc, handle),
    do: %{
      algorithms: [alg],
      encryption: [enc],
      max_plaintext: 1024,
      timeout: 5000,
      key_resolver: fn _ -> {:ok, %{algorithm: alg, key: handle}} end
    }
end
