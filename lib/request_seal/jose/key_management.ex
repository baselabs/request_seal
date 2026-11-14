defmodule RequestSeal.JOSE.KeyManagement do
  @moduledoc """
  Custodian-side RFC 7518 key wrapping primitives over OTP.

  `wrap/4` and `unwrap/4` consume operation-local descriptors only:
  `{:rsa, otp_key}`, `{:aes, kek}`, `{:cek, bytes}`. RSA wrapping takes
  an OTP public key; unwrapping takes an OTP private key.
  Private keys and symmetric material remain the caller custodian's responsibility.

  RSA-OAEP uses SHA-1/MGF1 SHA-1; RSA-OAEP-256 uses SHA-256/MGF1 SHA-256,
  both with an empty label. AES-KW uses RFC 3394; decrypt-only
  A128GCMKW/A256GCMKW use AES GCM with empty AAD.
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
  Wrap a CEK with RSA-OAEP or RFC 3394 AES-KW.

  `alg` is admitted before the header, CEK, or descriptor is inspected. Only
  `RSA-OAEP`, `RSA-OAEP-256`, `A128KW`, and `A256KW` are permitted; GCMKW and
  `dir` return `:algorithm_not_permitted`, layer `:input`.
  Pass a map for the unused `header`. `material` is `{:rsa, otp_public_key}` or
  `{:aes, kek}` with exactly 16 bytes for A128KW or 32 for A256KW. Key data is
  bounded to 1,048,576 bytes; AES-KW requires at least 16 bytes, divisible by 8.
  No RFC 5649 padding or alternate ICV is supported.

  Returns `{:ok, %{encrypted_key: bytes, header: %{}}}`. Validation failures are
  bounded JOSE errors: `:invalid_header`, `:invalid_serialization`, `:limit`,
  `:algorithm_mismatch` (key layer); OTP failures are `:signer_failed` (crypto).

      iex> kek = :binary.copy(<<0>>, 16)
      iex> {:ok, wrapped} = RequestSeal.JOSE.KeyManagement.wrap("A128KW", <<0::128>>, %{}, {:aes, kek})
      iex> byte_size(wrapped.encrypted_key)
      24
  """
  @spec wrap(binary(), binary(), map(), tuple()) ::
          {:ok, map()} | {:error, RequestSeal.JOSE.Error.t()}
  def wrap(alg, bytes, header, material) do
    safe(
      fn ->
        ensure(alg in algorithms(:jwe_wrap), :algorithm_not_permitted)
        ensure(is_map(header) and not is_struct(header), :invalid_header)
        bytes(bytes)
        {encrypted, additions} = wrap_bytes(alg, bytes, material)
        {:ok, %{encrypted_key: encrypted, header: additions}}
      end,
      :signer_failed,
      :crypto
    )
  end

  @doc """
  Recover key data using the selected algorithm and closed, decoded params.

  Admission of `alg` precedes params and key validation. Params are exactly
  `%{}` for RSA-OAEP, AES-KW, and `dir`, or exactly
  `%{iv: twelve_bytes, tag: sixteen_bytes}` for AES-GCMKW. Headers and extra
  members reject as `:invalid_header`; invalid GCM widths as `:invalid_iv` or
  `:invalid_tag`, all at layer `:input`.

  `material` is `{:rsa, otp_private_key}`, `{:aes, kek}`, or `{:cek, bytes}`.
  KEKs are exactly 16 or 32 bytes for the corresponding AES algorithm; a wrong
  size is `:algorithm_mismatch`, layer `:key`. Input is bounded to 1,048,576
  bytes. RFC 3394 requires at least 24 wrapped bytes, divisible by 8: all 6n
  ECB rounds run before the complete eight-byte ICV is compared using
  `:crypto.hash_equals/2`. No recovered byte is returned before that check.

  Returns `{:ok, key_data}` or a bounded JOSE error. Unsupported algorithms
  return `:algorithm_not_permitted`, layer `:input`; nonbinary or excessive
  input returns `:invalid_serialization` or `:limit`. All other recovery
  failures return `:decryption_failed`, layer `:crypto`. The primitive admits
  published key-data widths beyond JWE's 128/256-bit CEKs; JWE checks its width.

      iex> kek = :binary.copy(<<0>>, 32)
      iex> cek = <<0::256>>
      iex> {:ok, wrapped} = RequestSeal.JOSE.KeyManagement.wrap("A256KW", cek, %{}, {:aes, kek})
      iex> RequestSeal.JOSE.KeyManagement.unwrap("A256KW", wrapped.encrypted_key, %{}, {:aes, kek}) == {:ok, cek}
      true
  """
  @spec unwrap(binary(), binary(), RequestSeal.Custody.params(), tuple()) ::
          {:ok, binary()} | {:error, RequestSeal.JOSE.Error.t()}
  def unwrap(alg, bytes, params, material) do
    safe(
      fn ->
        ensure(alg in algorithms(:jwe), :algorithm_not_permitted)
        params_shape!(alg, params)
        bytes(bytes)
        {:ok, unwrap_bytes(alg, bytes, params, material)}
      end,
      :decryption_failed,
      :crypto
    )
  end

  @doc false
  def validate_params!(alg, params) when alg in ~w(A128GCMKW A256GCMKW) do
    params_shape!(alg, params)
    ensure(is_binary(params.iv) and byte_size(params.iv) == 12, :invalid_iv)
    ensure(is_binary(params.tag) and byte_size(params.tag) == 16, :invalid_tag)
    :ok
  end

  def validate_params!(_alg, params), do: ensure(params == %{}, :invalid_header)

  defp params_shape!(alg, params) when alg in ~w(A128GCMKW A256GCMKW),
    do:
      ensure(
        is_map(params) and not is_struct(params) and Enum.sort(Map.keys(params)) == [:iv, :tag],
        :invalid_header
      )

  defp params_shape!(_alg, params), do: ensure(params == %{}, :invalid_header)

  defp wrap_bytes(alg, bytes, {:rsa, key}) when alg in ["RSA-OAEP", "RSA-OAEP-256"] do
    {:RSAPublicKey, n, e} = key
    {:ok, _} = PublicKey.import({:rsa, n, e}, :raw)
    encrypted = :public_key.encrypt_public(bytes, key, oaep(alg))
    ensure(byte_size(encrypted) == byte_size(:binary.encode_unsigned(n)), :signer_failed, :crypto)
    {encrypted, %{}}
  end

  defp wrap_bytes(alg, bytes, {:aes, kek}) when alg in ["A128KW", "A256KW"] do
    kek!(alg, kek)
    ensure(byte_size(bytes) >= 16 and rem(byte_size(bytes), 8) == 0, :algorithm_mismatch, :key)
    {kw(alg, kek, bytes, true), %{}}
  end

  defp wrap_bytes(_, _, _), do: fail(:algorithm_mismatch, :key)

  defp unwrap_bytes(alg, bytes, _, {:rsa, key}) when alg in ["RSA-OAEP", "RSA-OAEP-256"] do
    Crypto.validate_rsa_private!(key)
    n = elem(key, 2)
    ensure(byte_size(bytes) == byte_size(:binary.encode_unsigned(n)), :decryption_failed, :crypto)
    :public_key.decrypt_private(bytes, key, oaep(alg))
  end

  defp unwrap_bytes(alg, bytes, _, {:aes, kek}) when alg in ["A128KW", "A256KW"] do
    kek!(alg, kek)
    ensure(byte_size(bytes) >= 24 and rem(byte_size(bytes), 8) == 0, :decryption_failed, :crypto)
    kw(alg, kek, bytes, false)
  end

  defp unwrap_bytes(alg, bytes, params, {:aes, kek}) when alg in ["A128GCMKW", "A256GCMKW"] do
    kek!(alg, kek)
    validate_params!(alg, params)

    plaintext =
      :crypto.crypto_one_time_aead(:aes_gcm, kek, params.iv, bytes, "", params.tag, false)

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
        is_binary(kek) and byte_size(kek) == if(alg in ["A128KW", "A128GCMKW"], do: 16, else: 32),
        :algorithm_mismatch,
        :key
      )

  @icv <<0xA6A6A6A6A6A6A6A6::64>>
  defp kw(alg, kek, bytes, encrypt?) do
    cipher = if alg == "A128KW", do: :aes_128_ecb, else: :aes_256_ecb
    {a, data} = if encrypt?, do: {@icv, bytes}, else: :erlang.split_binary(bytes, 8)
    blocks = for <<block::binary-size(8) <- data>>, do: block
    n = length(blocks)
    rounds = if encrypt?, do: 0..5, else: 5..0//-1
    indices = if encrypt?, do: 1..n, else: n..1//-1

    {a, blocks} =
      Enum.reduce(rounds, {a, List.to_tuple(blocks)}, fn j, state ->
        Enum.reduce(indices, state, fn i, {a, r} ->
          <<counter::64>> = a
          t = n * j + i
          input_a = if encrypt?, do: a, else: <<Bitwise.bxor(counter, t)::64>>

          <<next_a::64, next_r::binary-size(8)>> =
            :crypto.crypto_one_time(cipher, kek, input_a <> elem(r, i - 1), encrypt?)

          next_a = if encrypt?, do: Bitwise.bxor(next_a, t), else: next_a
          {<<next_a::64>>, put_elem(r, i - 1, next_r)}
        end)
      end)

    recovered = blocks |> Tuple.to_list() |> IO.iodata_to_binary()

    if encrypt? do
      a <> recovered
    else
      ensure(:crypto.hash_equals(a, @icv), :decryption_failed, :crypto)
      recovered
    end
  end

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
