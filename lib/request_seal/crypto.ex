defmodule RequestSeal.Crypto do
  @moduledoc """
  OTP cryptographic primitives over exact signature-base bytes, for custodians.

  Algorithms and encodings follow
  [RFC 9421 Section 3.3](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3),
  [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), and
  [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).

  This low-level boundary returns only signature bytes or mathematical validity.
  It does not establish trust, identity, policy, or authorization. A custodian calls
  it inside its secret boundary; private material is never stored in a public key,
  message, or result. Caller-owned signing functions connect these primitives
  to `RequestSeal.sign/4`.

  Select an exact identifier from `algorithms/0`, or explicitly select a supported
  RFC 9421 Section 3.3.7 extension as `{:jws, name}`. Extensions are `RS256`,
  `PS256`, `PS384`, `PS512`, `HS256`, `ES256`, `ES384`, and Ed25519-only `EdDSA`.
  Unknown, case-altered, `none`, and encryption identifiers reject. JWS names never
  alias HTTP `alg` parameters: callers using JWS must omit the HTTP `alg` parameter
  and select the extension through trusted configuration/key metadata. These
  primitives consume the entire base directly, with no JOSE header or Base64 step.

  `sign/4` takes operation-local signing material and `verify/5` a
  `RequestSeal.PublicKey`; their documentation lists the descriptors. HMAC secrets must be
  32–16,384 bytes for both `"hmac-sha256"` and `{:jws, "HS256"}`; there is no
  key-equivalence derivation. HMAC compares
  with OTP `:crypto.hash_equals/2`. HMAC proves shared-secret possession only.

  The per-call `max_bytes:` bound of `sign/4` and `verify/5` does not change
  `RequestSeal.SignatureBase`'s separate 1,048,576-byte ceiling. ECDSA uses fixed-width r || s
  (64/96 bytes), never DER on the wire. RSA-PSS fixes MGF1 to the selected digest
  and salt length to its digest width (64 for HTTP SHA-512). Ed25519 has no prehash
  and rejects noncanonical S. RSA signatures have the exact modulus width.
  Errors are bounded `RequestSeal.Crypto.Error` values and contain no input bytes.
  """
  alias RequestSeal.PublicKey
  alias RequestSeal.Crypto.{Algorithm, Error, Support}
  import Support, only: [ensure: 2, bounded_binary?: 3]
  @type algorithm :: binary() | {:jws, binary()}
  @doc """
  The six registered, case-sensitive HTTP signature algorithm identifiers.

  ## Returns

    * a list of six binaries, in registry order.

  ## Examples

      iex> RequestSeal.Crypto.algorithms()
      ["rsa-pss-sha512", "rsa-v1_5-sha256", "hmac-sha256", "ecdsa-p256-sha256", "ecdsa-p384-sha384", "ed25519"]
  """
  @spec algorithms() :: [binary()]
  def algorithms, do: Algorithm.http()

  @doc """
  The inclusive byte ceiling shared by cryptographic and custody operations.

  It is the largest `max_bytes:` value accepted by `sign/4`, `verify/5`,
  `RequestSeal.Custody.sign/3`, and `RequestSeal.Custody.verify/4`.

  ## Returns

    * `16_777_216`.

  ## Examples

      iex> RequestSeal.Crypto.max_bytes_ceiling()
      16_777_216
  """
  @spec max_bytes_ceiling() :: pos_integer()
  def max_bytes_ceiling, do: 16_777_216

  @doc """
  Sign exact bytes using operation-local material within the caller's custodian.

  Checks run in this order: options, algorithm, `bytes`, then material, so
  invalid options take precedence over an unsupported algorithm.

  ## Parameters

    * `algorithm` - an identifier from `algorithms/0` or `{:jws, name}` for a JWS
      extension listed in the module documentation.
    * `bytes` - the entire signature base as a binary, at most `:max_bytes` bytes.
    * `material` - an operation-local descriptor that fits `algorithm`:
      * `{:rsa, otp_private_key}` - a two-prime `:RSAPrivateKey` record with a
        valid 2048–8192-bit public part and consistent CRT components.
      * `{:ec, "P-256" | "P-384", scalar_bytes}` - a 32- or 48-byte scalar in
        `1..order-1` on the algorithm's curve.
      * `{:ed25519, seed_bytes}` - a 32-byte seed.
      * `{:hmac, secret_bytes}` - a 32–16,384-byte secret.
    * `opts` - keyword list; see Options.

  ## Options

    * `:max_bytes` - largest accepted `bytes` size, integer 1–16,777,216
      (`max_bytes_ceiling/0`). Default `1_048_576`. It is the only option; any
      other key, a duplicate, or an out-of-range or non-integer value returns
      `:invalid_options`.

  ## Returns

    * `{:ok, signature}` - RSA signatures have the modulus width, ECDSA
      signatures are fixed-width r || s (64 or 96 bytes), Ed25519 signatures are
      64 bytes, and HMAC-SHA256 tags are 32 bytes.
    * `{:error, %RequestSeal.Crypto.Error{}}` - reasons this function can return:
      `:invalid_options`, `:unsupported_algorithm`, `:invalid_data` (`bytes` is
      not a binary or exceeds `:max_bytes`), `:invalid_key` (malformed,
      out-of-range, or inconsistent material), `:key_mismatch` (material of a
      type or curve that does not fit `algorithm`), and `:invalid_signature` (OTP
      produced an ECDSA r or s outside the curve order). Meanings:
      `RequestSeal.Crypto.Error`.

  ## Examples

  RFC 8032 Section 7.1, TEST 1 (Ed25519, empty message):

      iex> seed = Base.decode16!("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
      iex> {:ok, signature} = RequestSeal.Crypto.sign("ed25519", "", {:ed25519, seed})
      iex> Base.encode16(signature, case: :lower)
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
      iex> RequestSeal.Crypto.sign("ed25519", "", {:ed25519, seed}, timeout: 1_000)
      {:error, %RequestSeal.Crypto.Error{reason: :invalid_options}}
      iex> RequestSeal.Crypto.sign({:jws, "ES256"}, "", {:ed25519, seed})
      {:error, %RequestSeal.Crypto.Error{reason: :key_mismatch}}
      iex> RequestSeal.Crypto.sign("hmac-sha256", "message 41 delivered", {:hmac, "short secret"})
      {:error, %RequestSeal.Crypto.Error{reason: :invalid_key}}
  """
  @spec sign(algorithm(), binary(), tuple(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(algorithm, bytes, material, opts \\ []) do
    Support.safe(:invalid_key, fn ->
      max = max_bytes(opts)
      {_, spec} = Algorithm.resolve(algorithm)
      ensure(bounded_binary?(bytes, 0, max), :invalid_data)
      {:ok, sign_bytes(spec, bytes, material)}
    end)
  end

  @doc """
  Verify exact bytes; `:ok` establishes cryptographic validity only.

  Checks run in this order: options, algorithm, `bytes`, key, then signature,
  so invalid options take precedence over an unsupported algorithm.

  ## Parameters

    * `algorithm` - an identifier from `algorithms/0` or `{:jws, name}` for a JWS
      extension listed in the module documentation.
    * `bytes` - the entire signature base as a binary, at most `:max_bytes` bytes.
    * `signature` - the signature binary in the format `sign/4` returns.
    * `key` - a `t:RequestSeal.PublicKey.t/0` that fits `algorithm`: its type and
      curve must match, its JWK `alg` must be absent or equal the JOSE name, its
      `use` absent or `"sig"`, and its `key_ops` absent or include `"verify"`.
      Only inside the HMAC custodian, `{:hmac, secret_bytes}` (32–16,384 bytes)
      for an HMAC algorithm.
    * `opts` - keyword list; see Options.

  ## Options

    * `:max_bytes` - largest accepted `bytes` size, integer 1–16,777,216
      (`max_bytes_ceiling/0`). Default `1_048_576`. It is the only option; any
      other key, a duplicate, or an out-of-range or non-integer value returns
      `:invalid_options`.

  ## Returns

    * `:ok` - the signature is mathematically valid for `bytes` under `key`.
    * `{:error, %RequestSeal.Crypto.Error{}}` - reasons this function can return:
      `:invalid_options`, `:unsupported_algorithm`, `:invalid_data` (`bytes` is
      not a binary or exceeds `:max_bytes`), `:invalid_key` (`key` is malformed,
      is neither a public key nor an HMAC descriptor, or holds an HMAC secret
      outside 32–16,384 bytes), `:key_mismatch` (`key` does not fit `algorithm`
      or its restrictions forbid verification), and `:invalid_signature` (not a
      binary, wrong width, ECDSA r or s outside the curve order, noncanonical
      Ed25519 S, or failed verification). Meanings: `RequestSeal.Crypto.Error`.

  ## Examples

  RFC 8032 Section 7.1, TEST 1 (Ed25519, empty message):

      iex> public = Base.decode16!("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")
      iex> {:ok, key} = RequestSeal.PublicKey.import({:ed25519, public}, :raw)
      iex> signature = Base.decode16!("E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B")
      iex> RequestSeal.Crypto.verify("ed25519", "", signature, key)
      :ok
      iex> RequestSeal.Crypto.verify("ed25519", "x", signature, key)
      {:error, %RequestSeal.Crypto.Error{reason: :invalid_signature}}
      iex> RequestSeal.Crypto.verify("ecdsa-p256-sha256", "", signature, key)
      {:error, %RequestSeal.Crypto.Error{reason: :key_mismatch}}
      iex> RequestSeal.Crypto.verify("ed25519", "", signature, %{key | operations: ["sign"]})
      {:error, %RequestSeal.Crypto.Error{reason: :key_mismatch}}
      iex> RequestSeal.Crypto.verify("ed25519", "", signature, key, max_bytes: 0)
      {:error, %RequestSeal.Crypto.Error{reason: :invalid_options}}
  """
  @spec verify(algorithm(), binary(), binary(), PublicKey.t() | tuple(), keyword()) ::
          :ok | {:error, Error.t()}
  def verify(algorithm, bytes, signature, key, opts \\ []) do
    Support.safe(:invalid_key, fn ->
      max = max_bytes(opts)
      resolved = {_, spec} = Algorithm.resolve(algorithm)
      ensure(bounded_binary?(bytes, 0, max), :invalid_data)

      material =
        case key do
          {:hmac, _} ->
            ensure(elem(spec, 0) == :hmac, :key_mismatch)
            key

          %PublicKey{} ->
            PublicKey.bind!(key, resolved)

          _ ->
            ensure(false, :invalid_key)
        end

      ensure(is_binary(signature), :invalid_signature)
      ensure(verify_bytes(spec, bytes, signature, material), :invalid_signature)
      :ok
    end)
  end

  defp max_bytes([]), do: 1_048_576

  defp max_bytes(max_bytes: value) do
    ensure(is_integer(value) and value in 1..max_bytes_ceiling(), :invalid_options)
    value
  end

  defp max_bytes(_), do: ensure(false, :invalid_options)

  defp sign_bytes({:rsa, digest, padding, salt}, bytes, {:rsa, key}) do
    validate_rsa_private!(key)

    :public_key.sign(bytes, digest, key, rsa_options(padding, digest, salt))
  end

  defp sign_bytes({:ec, digest, crv, size}, bytes, {:ec, key_curve, scalar}) do
    ensure(crv == key_curve, :key_mismatch)
    {curve, _, order} = Algorithm.curve(crv)
    ensure(bounded_binary?(scalar, size, size), :invalid_key)
    value = :binary.decode_unsigned(scalar)
    ensure(value > 0 and value < order, :invalid_key)
    der = :crypto.sign(:ecdsa, digest, bytes, [scalar, curve])
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    ensure(r > 0 and r < order and s > 0 and s < order, :invalid_signature)
    <<r::unsigned-big-size(size * 8), s::unsigned-big-size(size * 8)>>
  end

  defp sign_bytes({:ed25519, :none, _, _}, bytes, {:ed25519, seed}) do
    ensure(bounded_binary?(seed, 32, 32), :invalid_key)
    :crypto.sign(:eddsa, :none, bytes, [seed, :ed25519])
  end

  defp sign_bytes({:hmac, :sha256, _, _}, bytes, {:hmac, secret}) do
    ensure(bounded_binary?(secret, 32, 16_384), :invalid_key)
    :crypto.mac(:hmac, :sha256, secret, bytes)
  end

  defp sign_bytes(_, _, _), do: ensure(false, :key_mismatch)

  defp verify_bytes({:rsa, digest, padding, salt}, bytes, signature, {type, n, e})
       when type in [:rsa, :rsa_pss] do
    ensure(byte_size(signature) == byte_size(:binary.encode_unsigned(n)), :invalid_signature)

    :public_key.verify(
      bytes,
      digest,
      signature,
      {:RSAPublicKey, n, e},
      rsa_options(padding, digest, salt)
    )
  end

  defp verify_bytes({:ec, digest, crv, size}, bytes, signature, {:ec, crv, point}) do
    ensure(byte_size(signature) == size * 2, :invalid_signature)
    <<r::unsigned-big-size(^size * 8), s::unsigned-big-size(^size * 8)>> = signature
    {curve, _, order} = Algorithm.curve(crv)
    ensure(r > 0 and r < order and s > 0 and s < order, :invalid_signature)
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
    :crypto.verify(:ecdsa, digest, bytes, der, [point, curve])
  end

  defp verify_bytes({:ed25519, :none, _, _}, bytes, signature, {:ed25519, key}) do
    ensure(byte_size(signature) == 64, :invalid_signature)
    <<_::binary-size(32), s::little-unsigned-256>> = signature

    ensure(
      s < 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
      :invalid_signature
    )

    :crypto.verify(:eddsa, :none, bytes, signature, [key, :ed25519])
  end

  defp verify_bytes({:hmac, :sha256, _, _} = spec, bytes, signature, material) do
    ensure(byte_size(signature) == 32, :invalid_signature)
    :crypto.hash_equals(sign_bytes(spec, bytes, material), signature)
  end

  @doc false
  def validate_rsa_private!(key) do
    ensure(
      is_tuple(key) and tuple_size(key) == 11 and elem(key, 0) == :RSAPrivateKey,
      :invalid_key
    )

    {:RSAPrivateKey, version, n, e, d, p, q, dp, dq, qi, extra} = key
    {:ok, _} = PublicKey.import({:rsa, n, e}, :raw)

    ensure(
      Enum.all?([d, p, q, dp, dq, qi], &(is_integer(&1) and &1 > 0 and &1 < n)),
      :invalid_key
    )

    ensure(
      version == :"two-prime" and extra == :asn1_NOVALUE and p > 1 and q > 1,
      :invalid_key
    )

    ensure(
      n == p * q and rem(d, p - 1) == dp and rem(d, q - 1) == dq and
        rem(q * qi, p) == 1 and rem(e * d, div((p - 1) * (q - 1), Integer.gcd(p - 1, q - 1))) == 1,
      :invalid_key
    )

    key
  end

  defp rsa_options(:pkcs1, _, _), do: [rsa_padding: :rsa_pkcs1_padding]

  defp rsa_options(:pss, digest, salt),
    do: [rsa_padding: :rsa_pkcs1_pss_padding, rsa_mgf1_md: digest, rsa_pss_saltlen: salt]
end
