defmodule RequestSeal.JOSE.KeyManagement do
  @moduledoc """
  Custodian-side RFC 7518 key wrapping primitives over OTP.

  `wrap/4` returns `{:ok, %{encrypted_key: bytes, header: map}}`;
  `unwrap/4` returns `{:ok, bytes}`. Both return `{:error, JOSE.Error}` on
  failure. These functions consume operation-local descriptors only:
  `{:rsa, otp_key}`, `{:aes, kek}`, `{:cek, bytes}`. RSA wrapping takes
  an OTP public key; unwrapping takes an OTP private key.
  Private keys and symmetric material remain the caller custodian's responsibility.

  RSA-OAEP uses SHA-1/MGF1 SHA-1; RSA-OAEP-256 uses SHA-256/MGF1 SHA-256,
  both with an empty label. RSA encrypted keys must equal the modulus width,
  and private RSA CRT components are checked. RSA keys are 2048–8192 bits.
  A128GCMKW/A256GCMKW use 16/32-byte KEKs, fresh 12-byte IVs, empty AAD,
  and 16-byte tags. The returned `iv`/`tag` header additions must be protected.
  Received widths reject before OTP. `dir` produces an empty encrypted key and
  requires the supplied CEK to equal the direct key. JOSE envelopes enforce the
  content cipher's CEK width; primitives also support published unwrap stages
  belonging to other content algorithms without enabling those algorithms.
  """
  import RequestSeal.JOSE.Support
  alias RequestSeal.{Crypto, PublicKey}

  @spec wrap(binary(), binary(), map(), tuple()) ::
          {:ok, map()} | {:error, RequestSeal.JOSE.Error.t()}
  def wrap(alg, bytes, header, material) do
    safe(
      fn ->
        ensure(alg in algorithms(:jwe), :algorithm_not_permitted)
        ensure(is_map(header), :invalid_header)
        bytes(bytes)
        {encrypted, additions} = wrap_bytes(alg, bytes, material)
        {:ok, %{encrypted_key: encrypted, header: additions}}
      end,
      :signer_failed,
      :crypto
    )
  end

  @spec unwrap(binary(), binary(), map(), tuple()) ::
          {:ok, binary()} | {:error, RequestSeal.JOSE.Error.t()}
  def unwrap(alg, bytes, header, material) do
    safe(
      fn ->
        ensure(alg in algorithms(:jwe), :algorithm_not_permitted)
        ensure(is_map(header), :invalid_header)
        bytes(bytes)
        {:ok, unwrap_bytes(alg, bytes, header, material)}
      end,
      :decryption_failed,
      :crypto
    )
  end

  defp wrap_bytes(alg, bytes, {:rsa, key}) when alg in ["RSA-OAEP", "RSA-OAEP-256"] do
    {:RSAPublicKey, n, e} = key
    {:ok, _} = PublicKey.import({:rsa, n, e}, :raw)
    encrypted = :public_key.encrypt_public(bytes, key, oaep(alg))
    ensure(byte_size(encrypted) == byte_size(:binary.encode_unsigned(n)), :signer_failed, :crypto)
    {encrypted, %{}}
  end

  defp wrap_bytes(alg, bytes, {:aes, kek}) when alg in ["A128GCMKW", "A256GCMKW"] do
    kek!(alg, kek)
    iv = random(12)
    {encrypted, tag} = :crypto.crypto_one_time_aead(:aes_gcm, kek, iv, bytes, "", 16, true)
    {encrypted, %{"iv" => b64(iv), "tag" => b64(tag)}}
  end

  defp wrap_bytes("dir", bytes, {:cek, key}) do
    ensure(
      is_binary(key) and byte_size(key) == byte_size(bytes) and :crypto.hash_equals(key, bytes),
      :algorithm_mismatch,
      :key
    )

    {"", %{}}
  end

  defp wrap_bytes(_, _, _), do: fail(:algorithm_mismatch, :key)

  defp unwrap_bytes(alg, bytes, _, {:rsa, key}) when alg in ["RSA-OAEP", "RSA-OAEP-256"] do
    Crypto.validate_rsa_private!(key)
    n = elem(key, 2)
    ensure(byte_size(bytes) == byte_size(:binary.encode_unsigned(n)), :decryption_failed, :crypto)
    :public_key.decrypt_private(bytes, key, oaep(alg))
  end

  defp unwrap_bytes(alg, bytes, h, {:aes, kek}) when alg in ["A128GCMKW", "A256GCMKW"] do
    kek!(alg, kek)
    iv = decode(h["iv"])
    ensure(byte_size(iv) == 12, :invalid_iv)
    tag = decode(h["tag"])
    ensure(byte_size(tag) == 16, :invalid_tag)
    plaintext = :crypto.crypto_one_time_aead(:aes_gcm, kek, iv, bytes, "", tag, false)
    ensure(is_binary(plaintext), :decryption_failed, :crypto)
    plaintext
  end

  defp unwrap_bytes("dir", bytes, _, {:cek, key}) do
    ensure(
      bytes == "" and is_binary(key) and byte_size(key) in [16, 32],
      :decryption_failed,
      :crypto
    )

    key
  end

  defp unwrap_bytes(_, _, _, _), do: fail(:decryption_failed, :crypto)

  defp kek!(alg, kek),
    do:
      ensure(
        is_binary(kek) and byte_size(kek) == if(alg == "A128GCMKW", do: 16, else: 32),
        :algorithm_mismatch,
        :key
      )

  defp oaep(alg) do
    digest = if alg == "RSA-OAEP-256", do: :sha256, else: :sha

    [
      rsa_padding: :rsa_pkcs1_oaep_padding,
      rsa_oaep_md: digest,
      rsa_mgf1_md: digest,
      rsa_oaep_label: ""
    ]
  end
end
