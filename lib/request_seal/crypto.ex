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

  Signing material is an operation-local descriptor: `{:rsa, otp_private_key}`,
  `{:ec, "P-256" | "P-384", scalar_bytes}`, `{:ed25519, seed_bytes}` (32 bytes),
  or `{:hmac, secret_bytes}`. Verification accepts `RequestSeal.PublicKey` or,
  only inside the HMAC custodian, `{:hmac, secret_bytes}`. HMAC secrets must be
  32–16,384 bytes for both `"hmac-sha256"` and `{:jws, "HS256"}`; there is no
  key-equivalence derivation. HMAC compares
  with OTP `:crypto.hash_equals/2`. HMAC proves shared-secret possession only.

  Bases are binaries of at most 1,048,576 bytes by default. `sign/4` and `verify/5`
  accept per-call `max_bytes:` (integer 1–16,777,216). Bytes exceeding the selected
  value return `:invalid_data`; out-of-range, non-integer, unknown, and duplicate
  options return `:invalid_options`. This does not change `RequestSeal.SignatureBase`'s
  separate 1,048,576-byte ceiling. ECDSA uses fixed-width r || s
  (64/96 bytes), never DER on the wire. RSA-PSS fixes MGF1 to the selected digest
  and salt length to its digest width (64 for HTTP SHA-512). Ed25519 has no prehash
  and rejects noncanonical S. RSA signatures have the exact modulus width.
  Errors are bounded `RequestSeal.Crypto.Error` values and contain no input bytes.
  """
  alias RequestSeal.PublicKey
  alias RequestSeal.Crypto.{Algorithm, Error, Support}
  import Support, only: [ensure: 2, bounded_binary?: 3]
  @type algorithm :: binary() | {:jws, binary()}
  @doc "The six registered, case-sensitive HTTP signature algorithm identifiers."
  @spec algorithms() :: [binary()]
  def algorithms, do: Algorithm.http()

  @doc "Sign exact bytes using operation-local material within the caller's custodian."
  @spec sign(algorithm(), binary(), tuple(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(algorithm, bytes, material, opts \\ []) do
    Support.safe(:invalid_key, fn ->
      max = max_bytes(opts)
      {_, spec} = Algorithm.resolve(algorithm)
      ensure(bounded_binary?(bytes, 0, max), :invalid_data)
      {:ok, sign_bytes(spec, bytes, material)}
    end)
  end

  @doc "Verify exact bytes; :ok establishes cryptographic validity only."
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
    ensure(is_integer(value) and value in 1..16_777_216, :invalid_options)
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
