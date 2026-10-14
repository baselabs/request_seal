defmodule RequestSeal.JOSE.KeyManagement do
  @moduledoc """
  Custodian-side RFC 7518 key wrapping primitives over OTP.

  `wrap/4` and `unwrap/4` consume operation-local descriptors only:
  `{:rsa, otp_key}`, `{:aes, kek}`, `{:cek, bytes}`. RSA wrapping takes
  an OTP public key; unwrapping takes an OTP private key.
  Private keys and symmetric material remain the caller custodian's responsibility.

  RSA-OAEP uses SHA-1/MGF1 SHA-1; RSA-OAEP-256 uses SHA-256/MGF1 SHA-256,
  both with an empty label. A128GCMKW/A256GCMKW use AES GCM with empty AAD.
  JOSE envelopes enforce the content cipher's CEK width; primitives also support
  published unwrap stages belonging to other content algorithms without enabling
  those algorithms.

  `wrap/4` reports a descriptor or KEK that does not fit the algorithm as
  `:algorithm_mismatch`. `unwrap/4` reports a KEK of the wrong size as
  `:algorithm_mismatch` (rule `jose/key.algorithm_mismatch` in the
  cross-language conformance corpus) and every other failure to recover a CEK,
  including a descriptor of the wrong kind, as `:decryption_failed`. These
  primitive reasons never reach a decrypting peer: `RequestSeal.JOSE.JWE.decrypt/2`
  replaces any unwrap failure with a random CEK and returns the same
  `:decryption_failed` as an authentication failure.
  """
  import RequestSeal.JOSE.Support
  alias RequestSeal.{Crypto, PublicKey}

  @doc """
  Wrap a content-encryption key (CEK) for one recipient (RFC 7518).

  The result is the shape a `RequestSeal.JOSE.JWE.encrypt/4` wrapper returns.

  ## Parameters

    * `alg` - `"RSA-OAEP-256"`, `"RSA-OAEP"`, `"A128GCMKW"`, `"A256GCMKW"`, or
      `"dir"`.
    * `bytes` - the CEK, a binary of at most 1,048,576 bytes. RSA-OAEP limits it
      further by the modulus size.
    * `header` - a map; not read when wrapping (pass `%{}`).
    * `material` - the descriptor matching `alg`:
      * `{:rsa, {:RSAPublicKey, n, e}}` - OTP RSA public key, 2048 to 8192 bits,
        for `"RSA-OAEP"` and `"RSA-OAEP-256"`.
      * `{:aes, kek}` - 16-byte KEK for `"A128GCMKW"`, 32-byte KEK for
        `"A256GCMKW"`.
      * `{:cek, key}` - for `"dir"`; `key` must equal `bytes`.

  ## Returns

    * `{:ok, %{encrypted_key: bytes, header: additions}}` - RSA returns a
      modulus-width encrypted key and `%{}`; GCM key wrapping returns the wrapped
      key and `%{"iv" => b64, "tag" => b64}` (fresh 12-byte IV, 16-byte tag, which
      must be protected); `"dir"` returns `""` and `%{}`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:algorithm_not_permitted`, `:invalid_header` (non-map header),
      `:invalid_serialization` (non-binary CEK), `:limit`, `:algorithm_mismatch`
      (descriptor does not fit `alg`, wrong KEK size, or `"dir"` key differs),
      `:entropy_failure`, and `:signer_failed` (invalid RSA key or OTP failure).
      Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

      iex> kek = :crypto.strong_rand_bytes(16)
      iex> cek = :crypto.strong_rand_bytes(16)
      iex> {:ok, %{encrypted_key: wrapped, header: header}} = RequestSeal.JOSE.KeyManagement.wrap("A128GCMKW", cek, %{}, {:aes, kek})
      iex> {byte_size(wrapped), Enum.sort(Map.keys(header))}
      {16, ["iv", "tag"]}
      iex> {:error, error} = RequestSeal.JOSE.KeyManagement.wrap("A256GCMKW", cek, %{}, {:aes, kek})
      iex> error.reason
      :algorithm_mismatch
  """
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

  @doc """
  Recover a content-encryption key (CEK) from its wrapped form (RFC 7518).

  Received widths reject before OTP is called. Use it inside a
  `RequestSeal.JOSE.JWE.decrypt/2` `unwrap:` callback, which supplies the
  encrypted key and decoded protected header.

  ## Parameters

    * `alg` - `"RSA-OAEP-256"`, `"RSA-OAEP"`, `"A128GCMKW"`, `"A256GCMKW"`, or
      `"dir"`.
    * `bytes` - the encrypted key, a binary of at most 1,048,576 bytes. RSA
      requires exactly the modulus width; `"dir"` requires `""`.
    * `header` - the decoded protected header map. GCM key wrapping reads its
      `"iv"` (12 bytes) and `"tag"` (16 bytes), canonical unpadded Base64url.
    * `material` - the descriptor matching `alg`:
      * `{:rsa, rsa_private_key}` - OTP `:RSAPrivateKey` record, two-prime,
        2048 to 8192 bits, CRT components checked.
      * `{:aes, kek}` - 16-byte KEK for `"A128GCMKW"`, 32-byte KEK for
        `"A256GCMKW"`.
      * `{:cek, key}` - for `"dir"`; a 16- or 32-byte key, returned as the CEK.

  ## Returns

    * `{:ok, cek}` - the unwrapped bytes. This function does not check the width
      against a content cipher; `RequestSeal.JOSE.JWE.decrypt/2` does.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:algorithm_not_permitted`, `:invalid_header` (non-map header),
      `:invalid_serialization` (non-binary input), `:limit`, `:algorithm_mismatch`
      (KEK of the wrong size), `:invalid_base64`, `:invalid_iv`, `:invalid_tag`,
      and `:decryption_failed` (descriptor does not fit `alg`, invalid private
      key, wrong encrypted-key width, or authentication failure). Meanings:
      `RequestSeal.JOSE.Error`.

  ## Examples

      iex> kek = :crypto.strong_rand_bytes(32)
      iex> cek = :crypto.strong_rand_bytes(32)
      iex> {:ok, %{encrypted_key: wrapped, header: header}} = RequestSeal.JOSE.KeyManagement.wrap("A256GCMKW", cek, %{}, {:aes, kek})
      iex> RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", wrapped, header, {:aes, kek}) == {:ok, cek}
      true
      iex> {:error, error} = RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", wrapped, header, {:aes, :crypto.strong_rand_bytes(32)})
      iex> error.reason
      :decryption_failed
      iex> {:error, error} = RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", wrapped, %{}, {:aes, kek})
      iex> error.reason
      :invalid_base64
  """
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
