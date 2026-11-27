defmodule RequestSeal.FramedCryptoTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Conformance, Custody, Fingerprint}
  alias RequestSeal.Custody.Local

  doctest Fingerprint

  test "framing preserves split points and returns unread bytes" do
    assert Fingerprint.prefixed("abc") == <<3::32, "abc">>
    assert {:ok, "abc", "rest"} = Fingerprint.read_prefixed(<<3::32, "abc", "rest">>)
    assert {:ok, "", "rest"} = Fingerprint.read_prefixed(<<0::32, "rest">>, 0)
    assert :error = Fingerprint.read_prefixed(<<3::32, "abc">>, 2)
    assert :error = Fingerprint.read_prefixed(<<3::32, "ab">>)
    assert :error = Fingerprint.read_prefixed(<<1, 2, 3>>)

    assert {:ok, first} = Fingerprint.digest("frame v1", ["ab", "c"])
    assert {:ok, second} = Fingerprint.digest("frame v1", ["a", "bc"])
    refute first == second
    refute Fingerprint.digest("frame v2", ["ab", "c"]) == {:ok, first}
  end

  test "digest bounds reject improper lists, byte overflow and invalid domains" do
    for {domain, fields} <- [
          {"", ["a"]},
          {String.duplicate("A", 65), ["a"]},
          {<<0>>, ["a"]},
          {"frame v1", []},
          {"frame v1", ["a" | :invalid]},
          {"frame v1", [1]},
          {"frame v1", List.duplicate("", 257)},
          {"frame v1", [:binary.copy(<<0>>, 1_048_577)]}
        ] do
      assert {:error, :invalid_input} = Fingerprint.digest(domain, fields)
    end

    assert {:ok, <<_::256>>} =
             Fingerprint.digest(String.duplicate("A", 64), List.duplicate("", 256))
  end

  test "dedicated custody MAC matches a published project vector" do
    manifest =
      Conformance.json(File.read!("corpus/cases/custody/framed-mac-sha256.json"))

    assert {:ok, actual} = Conformance.Surfaces.framed_mac("corpus", manifest)
    assert actual == manifest["expected"]
  end

  test "MAC-only handles refuse signing and legacy handles refuse MAC" do
    for algorithm <- ["hmac-sha256", {:jws, "HS256"}] do
      {:ok, mac} = Local.generate(algorithm, capabilities: [:mac])
      {:ok, signing} = Local.generate(algorithm, [])
      assert {:ok, <<_::256>>} = Custody.mac(mac, "application v1", [<<0, 255>>])
      assert {:error, %{reason: :unsupported_operation}} = Custody.sign(mac, "bytes")
      assert {:error, %{reason: :unsupported_operation}} = Custody.verify(mac, "bytes", <<>>)

      assert {:error, %{reason: :unsupported_operation}} =
               Custody.mac(signing, "application v1", ["bytes"])

      assert :ok = Local.release(signing)
      assert :ok = Local.release(mac)
      assert {:error, %{reason: :key_not_found}} = Custody.mac(mac, "application v1", ["bytes"])
    end
  end

  test "MAC validates label, fields, timeout and requested capabilities" do
    {:ok, handle} = Local.generate("hmac-sha256", capabilities: [:mac])

    for label <- ["", "single", <<0, 32>>, ~s["field"], "request-seal reserved"] do
      assert {:error, %{reason: :invalid_options}} = Custody.mac(handle, label, ["a"])
    end

    for fields <- [
          [],
          ["a" | :bad],
          [1],
          List.duplicate("", 257),
          [:binary.copy(<<0>>, 1_048_576), "a"]
        ] do
      assert {:error, %{reason: :invalid_data}} = Custody.mac(handle, "frame v1", fields)
    end

    assert {:ok, <<_::256>>} =
             Custody.mac(handle, "frame v1", [:binary.copy(<<0>>, 1_048_576)])

    assert {:error, %{reason: :invalid_options}} =
             Custody.mac(handle, "frame v1", ["a"], timeout: 0)

    assert :ok = Local.release(handle)

    assert {:error, %{reason: :invalid_options}} =
             Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)}, [
               {:capabilities, [:mac]} | :invalid_tail
             ])

    assert {:error, %{reason: :invalid_options}} = Local.generate("ed25519", capabilities: [:mac])

    assert {:error, %{reason: :invalid_options}} =
             Local.generate("hmac-sha256", capabilities: [:sign, :mac])
  end

  test "HS256 JWK import honors MAC-only custody and preserves signing restrictions" do
    key = :binary.copy(<<37>>, 32)

    jwk = %{
      "kty" => "oct",
      "alg" => "HS256",
      "use" => "sig",
      "key_ops" => ["sign"],
      "k" => Base.url_encode64(key, padding: false)
    }

    for algorithm <- ["hmac-sha256", {:jws, "HS256"}] do
      assert {:ok, raw} = Local.new(algorithm, {:hmac, key}, capabilities: [:mac])

      assert {:ok, %{capabilities: [:mac]} = imported} =
               Local.import(algorithm, jwk, :jwk, capabilities: [:mac])

      try do
        assert {:ok, tag} = Custody.mac(raw, "frame v1", ["one", "two"])
        assert {:ok, ^tag} = Custody.mac(imported, "frame v1", ["one", "two"])
        assert {:error, %{reason: :unsupported_operation}} = Custody.sign(imported, "bytes")
      after
        :ok = Local.release(raw)
        :ok = Local.release(imported)
      end

      for {changed, reason} <- [
            {%{jwk | "key_ops" => ["verify"]}, :key_mismatch},
            {%{jwk | "key_ops" => ["sign", "sign"]}, :invalid_key},
            {%{jwk | "use" => "enc"}, :key_mismatch},
            {%{jwk | "alg" => "HS512"}, :key_mismatch},
            {%{jwk | "k" => Base.url_encode64(binary_part(key, 0, 31), padding: false)},
             :invalid_key}
          ] do
        assert {:error, %{reason: ^reason}} =
                 Local.import(algorithm, changed, :jwk, capabilities: [:mac])
      end

      assert {:error, %{reason: :invalid_options}} =
               Local.import(algorithm, jwk, :jwk, capabilities: [:mac, :sign])
    end
  end
end
