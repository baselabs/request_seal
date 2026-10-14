defmodule RequestSeal.ReasonAlignmentTest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.{JWE, JWS}

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, jws} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
    {:ok, http} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})

    on_exit(fn ->
      RequestSeal.Custody.Local.release(jws)
      RequestSeal.Custody.Local.release(http)
    end)

    %{jws: jws, http: http}
  end

  test "a header that is not a list of pairs is an invalid header, not a limit", c do
    kek = {:aes, :crypto.strong_rand_bytes(32)}
    wrap = fn alg, cek -> RequestSeal.JOSE.KeyManagement.wrap(alg, cek, %{}, kek) end

    for header <- [%{"alg" => "EdDSA"}, nil, "alg", {"alg", "EdDSA"}] do
      assert {:error, %RequestSeal.JOSE.Error{reason: :invalid_header}} =
               JWS.sign(header, "sensor reading", c.jws)

      assert {:error, %RequestSeal.JOSE.Error{reason: :invalid_header}} =
               JWE.encrypt(header, "sensor reading", wrap)
    end

    too_many = [{"alg", "EdDSA"} | for(i <- 1..64, do: {"x#{i}", i})]
    assert {:error, %RequestSeal.JOSE.Error{reason: :limit}} = JWS.sign(too_many, "r", c.jws)
  end

  test "unwrap reports every failure to recover a CEK as decryption failure; wrap reports mismatches" do
    alias RequestSeal.JOSE.KeyManagement
    cek = :crypto.strong_rand_bytes(32)
    kek = {:aes, :crypto.strong_rand_bytes(32)}

    {:ok, %{encrypted_key: wrapped, header: header}} =
      KeyManagement.wrap("A256GCMKW", cek, %{}, kek)

    for material <- [{:aes, :crypto.strong_rand_bytes(16)}, {:cek, cek}, {:rsa, :none}, :none] do
      assert {:error, %RequestSeal.JOSE.Error{reason: :decryption_failed}} =
               KeyManagement.unwrap("A256GCMKW", wrapped, header, material)

      assert {:error, %RequestSeal.JOSE.Error{reason: :algorithm_mismatch}} =
               KeyManagement.wrap("A256GCMKW", cek, %{}, material)
    end
  end
end
