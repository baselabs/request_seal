defmodule RequestSeal.Custody.Local do
  @moduledoc """
  Caller-owned OTP private keys and symmetric secrets, held in sensitive processes.

  `generate/2` draws fresh keys inside a sensitive holder. HKDF-SHA256 parents
  imported as `{:ikm, bytes}` support `RequestSeal.Custody.derive/4`; derived
  material travels holder to holder and never through a runner or caller.
  Uncommitted children refuse use, expire at the commit deadline, and monitor
  the caller from creation. Only acknowledged atomic commitment returns a child.

  `new/3` builds a handle from OTP key material and `import/4` from one private
  PEM, PKCS #8 DER, or private JWK. All six HTTP algorithms and the eight
  explicit JWS extensions in `RequestSeal.Crypto` are supported for signing, and
  RSA-OAEP, AES-KW, AES-GCMKW, ECDH-ES (P-256, P-384, X25519), and `dir` JWE custody. AES-KW handles grant
  `:wrap` and/or `:unwrap`; GCMKW, `dir`, and RSA handles grant `:unwrap` only. Each
  handle binds exactly one algorithm; an unwrap handle cannot sign or verify.
  Construction derives a public key and performs an actual sign/verify
  before returning a signing handle. RSA-OAEP construction validates CRT
  components and performs an actual OAEP wrap/unwrap; AES-KW construction
  performs a real wrap/unwrap. ECDH construction performs real agreement and recovery. Decrypt-only symmetric handles validate key widths. Only `equivalence: nonsecret_binary` is accepted, and
  only for HMAC (1–256 bytes). Absent HMAC equivalence remains `:unknown`; no value
  is derived from the secret. HMAC verification stays inside the custodian.
  No private key export, global store, or server is provided. The custody facade
  emits bounded wrap and unwrap telemetry without key identity.

  Each successful construction starts one unsupervised holder process. It marks
  itself sensitive before receiving key material; the handle references only its
  PID and a random 32-byte token. The holder performs OTP cryptography and returns
  signature bytes, unwrapped key bytes, verification results, or public metadata,
  never private state. `RequestSeal.Custody.unwrap/3` shares signing deadlines,
  cancellation, and safe errors. RSA-OAEP uses SHA-1/MGF1 SHA-1 and RSA-OAEP-256
  uses SHA-256/MGF1 SHA-256, both with an empty label, as defined by
  [RFC 7518 Section 4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3).
  Process and system introspection do not export that state.

  Holders live until `release/1` or the creating process exits, including after a
  handle is transferred. Dropping a handle does not stop its holder. A long-lived
  owner such as a GenServer must call `release/1` for handles it no longer needs,
  or create handles once at startup and reuse them for its lifetime.
  Operations against a stopped holder return `:key_not_found`. No supervisor,
  registry, application callback, or process starts when the library is loaded.
  For Ed25519 seeds from explicitly encoded environment or file sources, add
  `RequestSeal.Custody.Local.Owner` to the consumer's supervision tree.

  ## Decryption custody

  Import a recipient key once in its long-lived owner's process, then return the
  handle from the JWE policy resolver:

      {:ok, handle} = RequestSeal.Custody.Local.import({:jwe, "RSA-OAEP-256"}, private_pem, :pem)
      policy = %{
        algorithms: ["RSA-OAEP-256"],
        encryption: ["A256GCM"],
        max_plaintext: 1_048_576,
        timeout: 5_000,
        resolve_timeout: 1000,
        unwrap_timeout: 1000,
        protected: %{expected: %{}, permitted: ~w(kid typ cty)},
        key_resolver: fn _ -> {:ok, %{algorithm: "RSA-OAEP-256", key: handle}} end
      }
      RequestSeal.JOSE.JWE.decrypt(compact, policy)

  The resolver's work and the holder request share the JWE deadline. Private RSA
  material stays in the holder. Each CEK is delivered straight to JWE's
  sensitive worker through its owner-created sink; the custody runner and
  middle process receive only a summary. OAEP padding and GCM tag failures return the same complete
  `RequestSeal.JOSE.Error`. A released or unavailable handle produces that same
  error as a forged message, by design; use
  `RequestSeal.Custody.public_key(handle)` as a startup health check to expose
  custody availability independently. Deadline expiration remains distinct.
  Release the handle with `release/1` when its owner no longer needs it.
  """
  @behaviour RequestSeal.Custody
  alias RequestSeal.{Crypto, KeyHandle, KeyIdentity, PublicKey}
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.Custody.{Context, Derivation, DeriveRequest, Gate, Sink, Support}
  import Support, only: [fail: 1, ensure: 2, unwrap: 1]
  @rsa {1, 2, 840, 113_549, 1, 1, 1}
  @pss {1, 2, 840, 113_549, 1, 1, 10}
  @ec {1, 2, 840, 10045, 2, 1}
  @ed {1, 3, 101, 112}
  @ecdh ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)
  @max_bytes_ceiling Crypto.max_bytes_ceiling()

  @doc """
  Construct an algorithm-bound signing or key-management capability from OTP material.

  Construction validates material and derives its public key (none for symmetric
  material). Signing, OAEP, AES-KW, and ECDH perform actual round trips; decrypt-only
  symmetric families validate their exact key widths. It then starts one holder
  process owned by the caller. Release the handle with `release/1`.

  ## Parameters

    * `algorithm` - an HTTP identifier from `RequestSeal.Crypto.algorithms/0`,
      `{:jws, name}` for a JWS extension listed in `RequestSeal.Crypto`, or
      `{:jwe, name}` for RSA-OAEP, RSA-OAEP-256, A128KW, A256KW,
      A128GCMKW, A256GCMKW, dir, ECDH-ES, ECDH-ES+A128KW, or ECDH-ES+A256KW;
      or `{:derive, "hkdf-sha256"}` for an HKDF parent.
    * `material` - an operation-local OTP descriptor that fits `algorithm`:
      * `{:rsa, otp_private_key}` - a two-prime `:RSAPrivateKey` record with a
        2048–8192-bit modulus and consistent CRT components; RSA signing
        algorithms and both OAEP algorithms.
      * `{:ec, "P-256" | "P-384", scalar_bytes}` - a 32- or 48-byte scalar on the
        algorithm's curve.
      * `{:x25519, scalar_bytes}` - a 32-byte ECDH scalar, for ECDH-ES only.
      * `{:ed25519, seed_bytes}` - a 32-byte seed.
      * `{:hmac, secret_bytes}` - a 32–16,384-byte secret.
      * `{:aes, kek}` - exactly 16 bytes for A128KW/A128GCMKW or 32 for
        A256KW/A256GCMKW.
      * `{:cek, key}` - exactly 16 or 32 bytes for `dir`.
      * `{:ikm, bytes}` - 32–64 bytes for `{:derive, "hkdf-sha256"}`, granting
        only `:derive`, with unknown identity and no public export.
    * `opts` - keyword list; see Options.

  ## Options

    * `:issued_for` - caller-assigned purpose atom or nil.
    * `:admission` - a `RequestSeal.Custody.Gate` configuration for HTTP signing.
    * `:capabilities` - for JWE and derivation parents, a nonempty unique subset of the family's
      capabilities. AES-KW defaults to `[:wrap, :unwrap]`; other JWE families
      default to `[:unwrap]` and refuse `:wrap`.
    * `:equivalence` - a nonsecret binary of 1–256 bytes, accepted only for HMAC
      algorithms; it becomes the handle's `:symmetric` `RequestSeal.KeyIdentity`.
      When absent, an HMAC handle's identity is `:unknown`. No default.

  ## Returns

    * `{:ok, %RequestSeal.KeyHandle{}}` - capabilities `[:sign, :verify]` for a
      signing algorithm, `[:wrap, :unwrap]` (or the selected subset) for AES-KW,
      `[:unwrap]` for other JWE algorithms, or `[:derive]` for an HKDF parent.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:unsupported_algorithm`, `:invalid_options` (unknown, duplicate or
      invalid options), `:invalid_key` (malformed, out-of-range, or inconsistent
      material), and `:key_mismatch` (material of a type or curve that does not
      fit `algorithm`). Holder startup can also return `:custodian_failure` or
      `:deadline_exceeded`. Other reasons: see `RequestSeal.Custody.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> handle.capabilities
      [:sign, :verify]
      iex> {:ok, _signature} = RequestSeal.Custody.sign(handle, "release manifest for build 7781")
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
      iex> RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed}, timeout: 1_000)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_options, retryable: false}}
      iex> RequestSeal.Custody.Local.new("hmac-sha256", {:hmac, "too short"})
      {:error, %RequestSeal.Custody.Error{reason: :invalid_key, retryable: false}}
      iex> RequestSeal.Custody.Local.new({:jwe, "RSA-OAEP-256"}, {:ed25519, seed})
      {:error, %RequestSeal.Custody.Error{reason: :key_mismatch, retryable: false}}
  """
  @spec new(RequestSeal.Custody.algorithm(), tuple(), keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def new(algorithm, material, opts \\ []) do
    Support.safe(fn ->
      {_, _, capabilities} = selection(algorithm)
      construct(algorithm, material, opts, nil, nil, capabilities)
    end)
  end

  @doc """
  Generate a key inside a new sensitive holder owned by the caller.

  Only the handle leaves custody. RSA signing and RSA-OAEP algorithms require
  `bits: 2048 | 3072 | 4096` and use public exponent 65,537. ECDH-ES,
  ECDH-ES+A128KW, and ECDH-ES+A256KW require
  `curve: "P-256" | "P-384" | "X25519"`. ECDSA and Ed25519 signing algorithms
  fix their own curve; HMAC-SHA256 uses 32 bytes; A128KW/A256KW use 16/32 bytes.
  Both HTTP and explicit JWS signing identifiers are accepted.

  Options are exactly the required `:bits` or `:curve` for that family, plus
  optional `:issued_for` and HTTP `:admission` as in `new/3`,
  optional `:capabilities` narrowing its defaults (sign/verify, wrap/unwrap, or
  unwrap) and optional `:timeout` (1..300,000 ms, default 5,000) bounding holder
  startup and generation. RSA-4096 generation can take several seconds on a
  loaded machine; pass a longer `:timeout` for it. Unknown, duplicate, misplaced, missing, or invalid options return
  `:invalid_options`. GCMKW, `dir`, derivation parents, and unknown algorithms
  return `:unsupported_algorithm`; HKDF IKM is imported with `new/3`.

  Returns `{:ok, KeyHandle.t()}` after actual cryptographic validation, or
  `{:error, Custody.Error.t()}` with the reasons above, `:invalid_key`,
  `:key_mismatch`, `:custodian_failure`, or `:deadline_exceeded` when startup and
  generation exceed `:timeout`. Release with `RequestSeal.Custody.release/1`. Symmetric keys have
  unknown equivalence and no public key. Generation emits no telemetry.

      iex> {:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", capabilities: [:sign])
      iex> {:ok, _signature} = RequestSeal.Custody.sign(handle, "release manifest")
      iex> RequestSeal.Custody.release(handle)
      :ok
  """
  @spec generate(RequestSeal.Custody.algorithm(), keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def generate(algorithm, opts) do
    Support.safe(fn ->
      {family, capabilities, timeout} = generation_options(algorithm, opts)
      deadline = System.monotonic_time(:millisecond) + timeout

      {holder, token} =
        start_holder({:generate, algorithm, family, opts, capabilities}, self(), deadline)

      KeyHandle.new(
        __MODULE__,
        algorithm,
        capabilities,
        fn -> {holder, token} end,
        Keyword.get(opts, :issued_for)
      )
    end)
  end

  defp generation_options(algorithm, opts) do
    ensure(
      not match?({:derive, _}, algorithm) and
        algorithm not in [{:jwe, "dir"}, {:jwe, "A128GCMKW"}, {:jwe, "A256GCMKW"}],
      :unsupported_algorithm
    )

    {_, family, defaults} = selection(algorithm)

    required =
      case family do
        :rsa -> [:bits]
        :ecdh -> [:curve]
        _ -> []
      end

    timeout = Support.timeout(opts, [:capabilities, :timeout, :issued_for, :admission | required])
    binding_options(algorithm, opts)

    case family do
      :rsa ->
        ensure(Keyword.get(opts, :bits) in [2048, 3072, 4096], :invalid_options)

      :ecdh ->
        ensure(Keyword.get(opts, :curve) in ["P-256", "P-384", "X25519"], :invalid_options)

      _ ->
        :ok
    end

    {family, Derivation.capabilities(opts, defaults), timeout}
  end

  defp generated_material(_, :rsa, opts),
    do: {:rsa, :public_key.generate_key({:rsa, Keyword.fetch!(opts, :bits), 65_537})}

  defp generated_material(_, :ecdh, opts), do: generated_ec(Keyword.fetch!(opts, :curve))
  defp generated_material({:jwe, "A128KW"}, :aes, _), do: {:aes, :crypto.strong_rand_bytes(16)}
  defp generated_material({:jwe, "A256KW"}, :aes, _), do: {:aes, :crypto.strong_rand_bytes(32)}
  defp generated_material(_, :hmac, _), do: {:hmac, :crypto.strong_rand_bytes(32)}
  defp generated_material(_, :ed25519, _), do: {:ed25519, :crypto.strong_rand_bytes(32)}

  defp generated_material(algorithm, :ec, _) do
    {_, {:ec, _, curve, _}} = Algorithm.resolve(algorithm)
    generated_ec(curve)
  end

  defp generated_ec("X25519") do
    {_, scalar} = :crypto.generate_key(:ecdh, :x25519)
    {:x25519, scalar}
  end

  defp generated_ec(curve) do
    {otp, _, _} = Algorithm.curve(curve)
    {_, scalar} = :crypto.generate_key(:ecdh, otp)
    {:ec, curve, scalar}
  end

  @doc """
  Import one unencrypted private PEM, PKCS #8 DER, or private JWK with an explicit algorithm.

  The decoded key goes through the same validation and round trip as `new/3`.
  Public-only material, inconsistent private components, algorithm/type/curve
  mismatches, and encrypted containers reject.

  ## Parameters

    * `algorithm` - as in `new/3`.
    * `value` - the encoded private key, matching `format`:
      * PEM: a binary of 1–16,384 bytes holding exactly one unencrypted entry,
        PKCS #1 RSA, SEC1 EC (P-256 or P-384), or PKCS #8 RSA, RSASSA-PSS, EC, or
        Ed25519. DER inside the entry must be canonical.
      * DER: a canonical PKCS #8 binary of 1–16,384 bytes with the same key types.
      * JWK: a private JWK map of at most 32 fields: `"RSA"` with all two-prime
        CRT members, `"EC"` (P-256 or P-384), `"OKP"` Ed25519/X25519, or `"oct"`. ECDH permits `deriveKey` or
        `deriveBits` (also `decrypt`/`unwrapKey`) and yields `[:unwrap]` only.
        Components must be canonical unpadded Base64url; `"oth"` and explicit
        `null` `alg`, `use`, or `key_ops` reject.
    * `format` - `:pem`, `:der`, or `:jwk`.
    * `opts` - keyword list; see Options.

  A PSS-only private key never becomes a PKCS #1 signing key: it binds only
  `PS256`, `PS384`, or `PS512`. Parameter-constrained PSS containers reject rather
  than dropping restrictions. Imported EC/OKP public components must agree with
  the derived private key. PKCS #8 v2 (OneAsymmetricKey) containers reject with
  `:unsupported_format`.

  JWK `alg`, `use`, and `key_ops` restrictions must permit the selected
  operation. `alg` must be absent or equal the selected JOSE name (for example
  `"EdDSA"` for `"ed25519"`). For signing, `use` must be absent or `"sig"` and
  `key_ops` must be absent or a duplicate-free subset of `"sign"` and `"verify"`
  that includes `"sign"`. For OAEP, `use` must be absent or `"enc"`, and `key_ops`
  must be absent or a duplicate-free subset of `"encrypt"`, `"decrypt"`,
  `"wrapKey"`, and `"unwrapKey"` that includes `"decrypt"` or `"unwrapKey"`;
  signing operations reject. Public metadata retains these restrictions, and the
  handle's capabilities are limited to the permitted operations: `[:unwrap]` for
  OAEP, `[:sign, :verify]` when `key_ops` is absent or includes `"verify"`, and
  `[:sign]` otherwise. Symmetric JWE `oct` imports use the AES or direct
  descriptor from `new/3`. AES-KW grants only operations allowed by `key_ops`;
  GCMKW and `dir` require a decrypt/unwrap operation and grant only `:unwrap`.

  ## Options

    * `:capabilities` - as in `new/3`, additionally narrowed by JWK `key_ops`.
    * `:equivalence` - as in `new/3`: a nonsecret binary of 1–256 bytes, accepted
      only for HMAC algorithms. No default.

  ## Returns

    * `{:ok, %RequestSeal.KeyHandle{}}` - a handle whose capabilities follow the
      rules above.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:unsupported_algorithm`, `:unsupported_format` (unknown `format`, encrypted
      PEM, constrained PSS parameters, PKCS #8 v2, or an unrecognized PKCS #8
      algorithm), `:invalid_key` (malformed, oversized, noncanonical, public-only,
      or inconsistent input, or a JWK `key_ops` value outside the allowed set),
      `:key_mismatch` (JWK `alg` or `use` that does not fit, `key_ops` without the
      required operation, a PSS-only key for a non-PSS algorithm, or material that
      does not fit `algorithm`), and `:invalid_options`. Holder startup can also
      return `:custodian_failure` or `:deadline_exceeded`. Other reasons: see
      `RequestSeal.Custody.Error`.

  ## Examples

  A crawler's signing key arrives as a private JWK restricted to signing.

      iex> {public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> jwk = %{
      ...>   "kty" => "OKP",
      ...>   "crv" => "Ed25519",
      ...>   "x" => Base.url_encode64(public, padding: false),
      ...>   "d" => Base.url_encode64(seed, padding: false),
      ...>   "key_ops" => ["sign"]
      ...> }
      iex> {:ok, handle} = RequestSeal.Custody.Local.import({:jws, "EdDSA"}, jwk, :jwk)
      iex> handle.capabilities
      [:sign]
      iex> {:ok, %RequestSeal.PublicKey{operations: ["sign"]}} = RequestSeal.Custody.public_key(handle)
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
      iex> RequestSeal.Custody.Local.import("ed25519", Map.put(jwk, "alg", "ES256"), :jwk)
      {:error, %RequestSeal.Custody.Error{reason: :key_mismatch, retryable: false}}
      iex> RequestSeal.Custody.Local.import("ed25519", Map.delete(jwk, "d"), :jwk)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_key, retryable: false}}
      iex> RequestSeal.Custody.Local.import("ed25519", jwk, :yaml)
      {:error, %RequestSeal.Custody.Error{reason: :unsupported_format, retryable: false}}
  """
  @spec import(RequestSeal.Custody.algorithm(), term(), :pem | :der | :jwk, keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def import(algorithm, value, format, opts \\ []) do
    Support.safe(fn ->
      {jose, _, _} = selection(algorithm)
      {material, type, expected, capabilities} = decode(value, format, jose)
      construct(algorithm, material, opts, type, expected, capabilities)
    end)
  end

  defp construct(algorithm, material, opts, type, expected, capabilities) do
    state = prepare_state(algorithm, material, opts, type, expected, capabilities)
    {holder, token} = start_holder(state)
    KeyHandle.new(
      __MODULE__,
      algorithm,
      elem(state, 4),
      fn -> {holder, token} end,
      elem(state, 5)
    )
  end

  defp prepare_state(algorithm, material, opts, type, expected, capabilities) do
    {jose, family, _} = selection(algorithm)

    allowed =
      if match?({:jwe, _}, algorithm) or match?({:derive, _}, algorithm),
        do: [:equivalence, :capabilities, :issued_for],
        else: [:equivalence, :issued_for, :admission]

    Support.options(opts, allowed)
    binding_options(algorithm, opts)

    if Keyword.has_key?(opts, :capabilities) do
      selected = Keyword.fetch!(opts, :capabilities)

      ensure(
        is_list(selected) and selected != [] and Enum.uniq(selected) == selected and
          Enum.all?(selected, &(&1 in capabilities)),
        :invalid_options
      )
    end

    capabilities = Keyword.get(opts, :capabilities, capabilities)
    equivalence = Keyword.get(opts, :equivalence)

    if Keyword.has_key?(opts, :equivalence) do
      ensure(
        family == :hmac and is_binary(equivalence) and byte_size(equivalence) in 1..256,
        :invalid_options
      )
    end

    ensure(type != :rsa_pss or jose in ~w(PS256 PS384 PS512), :key_mismatch)
    public = derive(material, type)
    expected_material = if is_struct(expected, PublicKey), do: expected.material, else: expected

    ensure(
      expected_material == nil or (public != nil and public.material == expected_material),
      :invalid_key
    )

    validate_operation(algorithm, material, public)
    public = if is_struct(expected, PublicKey), do: PublicKey.validate!(expected), else: public

    identity =
      case public do
        nil ->
          %KeyIdentity{kind: if(equivalence, do: :symmetric, else: :unknown), value: equivalence}

        key ->
          %KeyIdentity{kind: :public, value: KeyIdentity.normalize(key.material)}
      end

    held_material =
      if match?({:jwe, alg} when alg in @ecdh, algorithm), do: {:ecdh, material}, else: material

    {
      algorithm,
      held_material,
      public,
      identity,
      capabilities,
      Keyword.get(opts, :issued_for),
      Keyword.get(opts, :admission)
    }
  end

  defp binding_options(algorithm, opts) do
    ensure(KeyHandle.purpose?(Keyword.get(opts, :issued_for)), :invalid_options)

    if Keyword.has_key?(opts, :admission) do
      Gate.validate!(Keyword.fetch!(opts, :admission), algorithm)
    end
  end

  defp selection({:derive, "hkdf-sha256"}), do: {"hkdf-sha256", :ikm, [:derive]}

  defp selection({:jwe, jose}) when jose in ["RSA-OAEP", "RSA-OAEP-256"],
    do: {jose, :rsa, [:unwrap]}

  defp selection({:jwe, jose}) when jose in ["A128KW", "A256KW"],
    do: {jose, :aes, [:wrap, :unwrap]}

  defp selection({:jwe, jose}) when jose in ["A128GCMKW", "A256GCMKW"],
    do: {jose, :aes, [:unwrap]}

  defp selection({:jwe, jose}) when jose in @ecdh, do: {jose, :ecdh, [:unwrap]}

  defp selection({:jwe, "dir"}), do: {"dir", :cek, [:unwrap]}

  defp selection(algorithm) do
    {jose, {family, _, _, _}} = Algorithm.resolve(algorithm)
    {jose, family, [:sign, :verify]}
  end

  defp validate_operation({:derive, "hkdf-sha256"}, {:ikm, bytes}, _) do
    ensure(is_binary(bytes) and byte_size(bytes) in 32..64, :invalid_key)
  end

  defp validate_operation({:derive, "hkdf-sha256"}, _, _), do: fail(:key_mismatch)

  defp validate_operation({:jwe, alg}, material, public)
       when alg in ["RSA-OAEP", "RSA-OAEP-256"] do
    ensure(match?({:rsa, _}, material), :key_mismatch)
    {:rsa, private} = material
    Crypto.validate_rsa_private!(private)
    {:rsa, n, e} = public.material
    cek = :crypto.strong_rand_bytes(32)

    wrapped =
      RequestSeal.JOSE.KeyManagement.wrap(alg, cek, %{}, {:rsa, {:RSAPublicKey, n, e}})
      |> unwrap()

    recovered =
      RequestSeal.JOSE.KeyManagement.unwrap(alg, wrapped.encrypted_key, %{}, material) |> unwrap()

    ensure(:crypto.hash_equals(cek, recovered), :invalid_key)
  end

  defp validate_operation({:jwe, alg}, {:aes, kek}, _)
       when alg in ~w(A128KW A256KW A128GCMKW A256GCMKW) do
    width = if alg in ~w(A128KW A128GCMKW), do: 16, else: 32
    ensure(is_binary(kek) and byte_size(kek) == width, :invalid_key)

    if alg in ~w(A128KW A256KW) do
      cek = :crypto.strong_rand_bytes(32)
      wrapped = RequestSeal.JOSE.KeyManagement.wrap(alg, cek, %{}, {:aes, kek}) |> unwrap()

      recovered =
        RequestSeal.JOSE.KeyManagement.unwrap(alg, wrapped.encrypted_key, %{}, {:aes, kek})
        |> unwrap()

      ensure(:crypto.hash_equals(cek, recovered), :invalid_key)
    end
  end

  defp validate_operation({:jwe, "dir"}, {:cek, key}, _),
    do: ensure(is_binary(key) and byte_size(key) in [16, 32], :invalid_key)

  defp validate_operation({:jwe, alg}, material, public) when alg in @ecdh do
    ensure(match?({:ec, _, _}, material) or match?({:x25519, _}, material), :key_mismatch)
    agreed = RequestSeal.JOSE.KeyManagement.agree(alg, "A256GCM", public, %{}) |> unwrap()

    params =
      RequestSeal.JOSE.KeyManagement.Agreement.header_params!(
        alg,
        Map.put(agreed.header, "enc", "A256GCM")
      )

    recovered =
      RequestSeal.JOSE.KeyManagement.unwrap(alg, agreed.encrypted_key, params, {:ecdh, material})
      |> unwrap()

    ensure(:crypto.hash_equals(agreed.cek, recovered), :invalid_key)
  end

  defp validate_operation({:jwe, _}, _, _), do: fail(:key_mismatch)

  defp validate_operation(algorithm, material, public) do
    signature = Crypto.sign(algorithm, "", material) |> unwrap()
    Crypto.verify(algorithm, "", signature, public || material) |> unwrap()
  end

  @doc """
  Stop a local holder and confirm destruction. Releasing it again returns `:ok`.

  Waits up to 5,000 ms for the holder to exit. Later operations on the handle
  return `:key_not_found`.

  ## Parameters

    * `handle` - a `t:RequestSeal.KeyHandle.t/0` created by this custodian.

  ## Returns

    * `:ok` - the holder has exited, or had already exited.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_handle` (not a handle created by this custodian, or a malformed
      one) and `:deadline_exceeded` (the holder did not exit within 5,000 ms).
      Meanings: `RequestSeal.Custody.Error`.

  ## Examples

      iex> {:ok, handle} = RequestSeal.Custody.Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)})
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
      iex> RequestSeal.Custody.sign(handle, "order 5512 shipped")
      {:error, %RequestSeal.Custody.Error{reason: :key_not_found, retryable: false}}
      iex> RequestSeal.Custody.Local.release(:not_a_handle)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_handle, retryable: false}}
  """
  @spec release(KeyHandle.t()) :: :ok | {:error, RequestSeal.Custody.Error.t()}
  def release(handle) do
    Support.safe(
      fn ->
        ensure(match?(%KeyHandle{custodian: __MODULE__}, handle), :invalid_handle)
        ensure(
          map_size(handle) == map_size(%KeyHandle{}) and is_function(handle.ref, 0),
          :invalid_handle
        )
        release(handle.ref, default_context()) |> Support.unwrap()
      end,
      :invalid_handle
    )
  end

  @doc false
  @impl true
  def release(ref, context) do
    {pid, token} = address(ref)
    monitor = Process.monitor(pid)

    try do
      send(pid, {:release, token})

      receive do
        {:DOWN, ^monitor, :process, ^pid, _} -> :ok
      after
        max(Context.remaining(context), 0) -> {:error, :deadline_exceeded}
      end
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  @impl true
  def sign(ref, algorithm, bytes, context)
      when is_binary(bytes) and byte_size(bytes) <= @max_bytes_ceiling,
      do: request(ref, {:sign, algorithm, bytes}, context)

  def sign(_, _, _, _), do: {:error, :invalid_data}

  @impl true
  def verify(ref, algorithm, bytes, signature, context)
      when is_binary(bytes) and byte_size(bytes) <= @max_bytes_ceiling,
      do: request(ref, {:verify, algorithm, bytes, signature}, context)

  def verify(_, _, _, _, _), do: {:error, :invalid_data}

  @impl true
  @doc false
  def unwrap(ref, algorithm, items, sink, context),
    do: request(ref, {:unwrap, algorithm, items, sink}, context)

  @impl true
  @doc false
  def wrap(ref, algorithm, cek, context), do: request(ref, {:wrap, algorithm, cek}, context)

  @impl true
  @doc false
  def derive(ref, %DeriveRequest{} = request, context),
    do: request(ref, {:derive, request}, context)

  @impl true
  @doc false
  def commit(ref, token, context), do: request(ref, {:commit, token}, context)

  @impl true
  def public_key(ref), do: request(ref, :public_key, default_context())

  @impl true
  def identity(ref), do: request(ref, :identity, default_context())

  @impl true
  def binding(ref, context), do: request(ref, :binding, context)

  defp default_context do
    %RequestSeal.Custody.Context{
      owner: self(),
      deadline: System.monotonic_time(:millisecond) + 5_000
    }
  end

  defp address(ref) do
    {pid, token} = ref.()

    ensure(
      is_pid(pid) and node(pid) == node() and is_binary(token) and byte_size(token) == 32,
      :invalid_handle
    )

    {pid, token}
  end

  defp request(ref, operation, context) do
    {pid, token} = address(ref)
    monitor = Process.monitor(pid)
    reply = :erlang.alias()

    try do
      send(pid, {:request, token, self(), reply, context, operation})

      receive do
        {^reply, result} -> result
        {:DOWN, ^monitor, :process, ^pid, _} -> {:error, :key_not_found}
      after
        max(Context.remaining(context), 0) -> {:error, :deadline_exceeded}
      end
    after
      :erlang.unalias(reply)
      Process.demonitor(monitor, [:flush])
    end
  end

  defp start_holder(
         state,
         owner \\ self(),
         deadline \\ System.monotonic_time(:millisecond) + 5_000,
         pending \\ :committed
       ) do
    initializer = self()
    token = :crypto.strong_rand_bytes(32)
    # Spawn captures only nonsecret addressing state. Sensitivity precedes the
    # initialization message, including CSPRNG generation and parent-to-child keys.
    {pid, monitor} = spawn_monitor(fn -> holder_init(owner, initializer, token, deadline) end)

    try do
      await_holder(pid, monitor, token, :ready, deadline)
      send(pid, {:initialize, token, state, pending})
      await_holder(pid, monitor, token, :initialized, deadline)
      {pid, token}
    catch
      kind, reason ->
        cleanup_monitor = Process.monitor(pid)
        Process.exit(pid, :kill)

        receive do
          {:DOWN, ^cleanup_monitor, :process, ^pid, _} -> :ok
        end

        :erlang.raise(kind, reason, __STACKTRACE__)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp await_holder(pid, monitor, token, phase, deadline) do
    receive do
      {candidate, ^phase} ->
        if valid_token?(candidate, token),
          do: :ok,
          else: await_holder(pid, monitor, token, phase, deadline)

      {candidate, {:initialization_failed, error}} ->
        if valid_token?(candidate, token),
          do: Support.unwrap(error),
          else: await_holder(pid, monitor, token, phase, deadline)

      {:DOWN, ^monitor, :process, ^pid, _} ->
        fail(:custodian_failure)
    after
      max(0, deadline - System.monotonic_time(:millisecond)) ->
        fail(:deadline_exceeded)
    end
  end

  defp holder_init(owner, initializer, token, deadline) do
    Process.flag(:sensitive, true)
    monitor = Process.monitor(owner)
    send(initializer, {token, :ready})
    holder_initialize(owner, initializer, monitor, token, deadline)
  end

  defp holder_initialize(owner, initializer, monitor, token, deadline) do
    receive do
      {:initialize, candidate, input, pending} ->
        if valid_token?(candidate, token) do
          result = Support.safe(fn -> {:ok, initial_state(input)} end, :custodian_failure)

          case result do
            {:ok, state} ->
              if Process.alive?(owner) and System.monotonic_time(:millisecond) < deadline do
                if pending != :committed do
                  Process.send_after(
                    self(),
                    {:commit_expired, token},
                    max(0, deadline - System.monotonic_time(:millisecond))
                  )
                end

                send(initializer, {token, :initialized})
                holder_loop(owner, monitor, token, state, pending)
              end

            {:error, _} = error ->
              send(initializer, {token, {:initialization_failed, error}})
          end
        else
          holder_initialize(owner, initializer, monitor, token, deadline)
        end

      {:DOWN, ^monitor, :process, ^owner, _} ->
        :ok
    after
      max(0, deadline - System.monotonic_time(:millisecond)) ->
        :ok
    end
  end

  defp initial_state({:generate, algorithm, family, opts, capabilities}) do
    material = generated_material(algorithm, family, opts)
    # Generation has its own capability option for every family; imported signing
    # keys retain new/3's existing option contract.
    prepare_state(
      algorithm,
      material,
      Keyword.take(opts, [:issued_for, :admission]),
      nil,
      nil,
      capabilities
    )
  end

  defp initial_state(state), do: state

  defp holder_loop(owner, monitor, token, state, pending) do
    receive do
      {:DOWN, ^monitor, :process, ^owner, _} ->
        :ok

      {:release, candidate} ->
        if valid_token?(candidate, token),
          do: :ok,
          else: holder_loop(owner, monitor, token, state, pending)

      {:commit_expired, candidate} ->
        if pending != :committed and valid_token?(candidate, token),
          do: :ok,
          else: holder_loop(owner, monitor, token, state, pending)

      {:request, candidate, runner, reply, context, operation} ->
        if valid_token?(candidate, token) and Process.alive?(runner) do
          next = handle_request(owner, reply, context, operation, state, pending)
          if next != :destroy, do: holder_loop(owner, monitor, token, state, next)
        else
          holder_loop(owner, monitor, token, state, pending)
        end

      {:system, from, _request} ->
        # Never expose secret-bearing state through sys, even while uncommitted.
        :gen.reply(from, {:error, :unsupported_operation})
        holder_loop(owner, monitor, token, state, pending)

      _ ->
        holder_loop(owner, monitor, token, state, pending)
    end
  end

  defp handle_request(owner, reply, context, {:commit, candidate}, _, {deadline, token}) do
    cond do
      System.monotonic_time(:millisecond) >= deadline or Context.remaining(context) <= 0 ->
        send(reply, {reply, {:error, :deadline_exceeded}})
        :destroy

      Process.alive?(owner) and Process.alive?(context.owner) and valid_token?(candidate, token) ->
        # One mailbox turn: the returned state invalidates expiry before another
        # message can be handled. No caller code runs in this process.
        pending = :committed
        send(reply, {reply, :ok})
        pending

      true ->
        send(reply, {reply, {:error, :unavailable}})
        if Process.alive?(owner), do: {deadline, token}, else: :destroy
    end
  end

  defp handle_request(_, reply, _, {:commit, _}, _, :committed) do
    send(reply, {reply, {:error, :unavailable}})
    :committed
  end

  defp handle_request(owner, reply, context, operation, state, pending) do
    if Process.alive?(owner) and Process.alive?(context.owner) and Context.remaining(context) > 0 do
      result =
        if pending == :committed do
          Support.safe(
            fn ->
              check_binding(operation, state, context)
              holder_operation(operation, state, context)
            end,
            :custodian_failure
          )
        else
          {:error, :unavailable}
        end

      if Context.remaining(context) > 0, do: send(reply, {reply, result})
    end

    pending
  end

  defp valid_token?(candidate, token)
       when is_binary(candidate) and byte_size(candidate) == 32 and
              is_binary(token) and byte_size(token) == 32,
       do: :crypto.hash_equals(candidate, token)

  defp valid_token?(_, _), do: false

  defp check_binding(
         operation,
         {algorithm, _, _, _, _, purpose, _},
         %Context{} = context
       )
       when is_tuple(operation) do
    ensure(
      context.issued_for == purpose and
        context.operation_family in [nil, KeyHandle.family(algorithm)],
      :key_mismatch
    )
  end

  defp check_binding(_, _, _), do: :ok

  defp holder_operation({:derive, request}, {bound, {:ikm, ikm}, _, _, capabilities, _, _}, context) do
    ensure(bound == {:derive, "hkdf-sha256"} and :derive in capabilities, :unsupported_operation)
    ensure(request.owner == context.owner and Process.alive?(request.owner), :unavailable)
    ensure(is_binary(request.token) and byte_size(request.token) == 32, :invalid_options)
    {_, _, defaults} = Derivation.family(request.target)
    selected = Derivation.capabilities([capabilities: request.capabilities], defaults)
    material = Derivation.material(ikm, request.target, request.domain)
    state = prepare_state(request.target.algorithm, material, [], nil, nil, selected)

    {pid, token} =
      start_holder(state, request.owner, context.deadline, {context.deadline, request.token})

    {:ok, fn -> {pid, token} end}
  end

  defp holder_operation({:derive, _}, _, _), do: {:error, :unsupported_operation}

  defp holder_operation(
         {:unwrap, algorithm, items, sink},
         {bound, material, _, _, capabilities, _, _},
         context
       ) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:unwrap in capabilities, :unsupported_operation)
    {:jwe, alg} = bound

    monitor = Process.monitor(context.owner)

    try do
      Enum.reduce_while(items, :ok, fn {index, encrypted, params, bits}, :ok ->
        cond do
          owner_cancelled?(monitor) ->
            {:halt, {:error, :custodian_failure}}

          Context.remaining(context) > 0 ->
            outcome =
              case RequestSeal.JOSE.KeyManagement.unwrap(alg, encrypted, params, material) do
                {:ok, cek} when bits in [128, 256] and is_binary(cek) and bit_size(cek) == bits ->
                  {:ok, cek}

                _ ->
                  :error
              end

            Sink.deliver(sink, index, outcome)
            {:cont, :ok}

          true ->
            {:halt, {:error, :deadline_exceeded}}
        end
      end)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp holder_operation(
         {:sign, algorithm, bytes},
         {bound, material, _, _, capabilities, _, admission},
         context
       ) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:sign in capabilities, :unsupported_operation)

    if admission == nil do
      Crypto.sign(algorithm, bytes, material, max_bytes: Crypto.max_bytes_ceiling())
    else
      Gate.sign(bytes, admission, context, algorithm, fn ->
        Crypto.sign(algorithm, bytes, material, max_bytes: Crypto.max_bytes_ceiling())
      end)
    end
  end

  defp holder_operation(operation, state, _context), do: holder_operation(operation, state)

  defp owner_cancelled?(monitor) do
    receive do
      {:DOWN, ^monitor, :process, _, _} -> true
    after
      0 -> false
    end
  end

  defp holder_operation(
         {:verify, algorithm, bytes, signature},
         {bound, material, public, _, capabilities, _, _}
       ) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:verify in capabilities, :unsupported_operation)

    Crypto.verify(algorithm, bytes, signature, public || material,
      max_bytes: Crypto.max_bytes_ceiling()
    )
  end

  defp holder_operation(:public_key, {_, _, nil, _, _, _, _}), do: {:error, :no_public_key}
  defp holder_operation(:public_key, {_, _, public, _, _, _, _}), do: {:ok, public}
  defp holder_operation(:identity, {_, _, _, identity, _, _, _}), do: identity

  defp holder_operation(:binding, {algorithm, _, public, _, _, issued_for, _}),
    do: {:ok, %{algorithm: algorithm, public_key: public, issued_for: issued_for}}

  defp holder_operation({:wrap, algorithm, cek}, {bound, material, _, _, capabilities, _, _}) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:wrap in capabilities, :unsupported_operation)
    {:jwe, alg} = bound

    case RequestSeal.JOSE.KeyManagement.wrap(alg, cek, %{}, material) do
      {:ok, %{encrypted_key: encrypted}} -> {:ok, %{encrypted_key: encrypted, params: %{}}}
      _ -> {:error, :custodian_failure}
    end
  end

  defp derive({:rsa, {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}}, type),
    do: unwrap(PublicKey.import({type || :rsa, n, e}, :raw))

  defp derive({:ec, crv, scalar}, _) do
    {curve, _, _} = Algorithm.curve(crv)
    {point, _} = :crypto.generate_key(:ecdh, curve, scalar)
    unwrap(PublicKey.import({:ec, crv, point}, :raw))
  end

  defp derive({:x25519, scalar}, _) do
    ensure(is_binary(scalar) and byte_size(scalar) == 32, :invalid_key)
    {public, _} = :crypto.generate_key(:ecdh, :x25519, scalar)
    unwrap(PublicKey.import({:x25519, public}, :raw))
  end

  defp derive({:ed25519, seed}, _) do
    ensure(is_binary(seed) and byte_size(seed) == 32, :invalid_key)
    {public, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    unwrap(PublicKey.import({:ed25519, public}, :raw))
  end

  defp derive({:ikm, _}, _), do: nil
  defp derive({:hmac, _}, _), do: nil
  defp derive({:aes, _}, _), do: nil
  defp derive({:cek, _}, _), do: nil
  defp derive(_, _), do: fail(:invalid_key)

  defp decode(value, :pem, jose) do
    ensure(is_binary(value) and byte_size(value) in 1..16_384, :invalid_key)

    ensure(
      not String.contains?(value, ["ENCRYPTED PRIVATE KEY", "Proc-Type: 4,ENCRYPTED"]),
      :unsupported_format
    )

    [entry] = :public_key.pem_decode(value)
    {type, der, encryption} = entry
    ensure(encryption == :not_encrypted, :unsupported_format)

    {material, restriction, expected} =
      case type do
        :RSAPrivateKey -> {{:rsa, canonical(:RSAPrivateKey, der)}, :rsa, nil}
        :ECPrivateKey -> ec_private(canonical(:ECPrivateKey, der))
        :PrivateKeyInfo -> pkcs8(der)
        _ -> fail(:invalid_key)
      end

    {material, restriction, expected, capabilities(jose)}
  end

  defp decode(value, :der, jose) do
    ensure(is_binary(value) and byte_size(value) in 1..16_384, :invalid_key)
    {material, restriction, expected} = pkcs8(value)
    {material, restriction, expected, capabilities(jose)}
  end

  defp decode(value, :jwk, jose) do
    ensure(is_map(value) and not is_struct(value) and map_size(value) <= 32, :invalid_key)
    ensure(not Map.has_key?(value, "oth"), :invalid_key)

    for key <- ~w(alg use key_ops),
        do: ensure(not Map.has_key?(value, key) or value[key] != nil, :invalid_key)

    encryption =
      jose in @ecdh or jose in ~w(RSA-OAEP RSA-OAEP-256 A128KW A256KW A128GCMKW A256GCMKW dir)

    use = if encryption, do: "enc", else: "sig"

    allowed_ops =
      cond do
        jose in @ecdh -> ~w(encrypt decrypt wrapKey unwrapKey deriveKey deriveBits)
        encryption -> ~w(encrypt decrypt wrapKey unwrapKey)
        true -> ~w(sign verify)
      end

    required_ops =
      cond do
        jose in @ecdh -> ~w(decrypt unwrapKey deriveKey deriveBits)
        jose in ~w(A128KW A256KW) -> ~w(encrypt decrypt wrapKey unwrapKey)
        encryption -> ~w(decrypt unwrapKey)
        true -> ~w(sign)
      end

    ensure(value["alg"] in [nil, jose] and value["use"] in [nil, use], :key_mismatch)
    ops = value["key_ops"]

    ensure(
      ops == nil or
        (is_list(ops) and length(ops) <= length(allowed_ops) and Enum.uniq(ops) == ops and
           Enum.all?(ops, &(&1 in allowed_ops))),
      :invalid_key
    )

    ensure(ops == nil or Enum.any?(ops, &(&1 in required_ops)), :key_mismatch)

    capabilities =
      cond do
        jose in ~w(A128KW A256KW) ->
          Enum.filter([:wrap, :unwrap], fn capability ->
            ops == nil or
              Enum.any?(
                ops,
                &(&1 in if(capability == :wrap,
                    do: ~w(encrypt wrapKey),
                    else: ~w(decrypt unwrapKey)
                  ))
              )
          end)

        encryption ->
          [:unwrap]

        ops == nil or "verify" in ops ->
          [:sign, :verify]

        true ->
          [:sign]
      end

    {material, expected} =
      case value do
        %{
          "kty" => "RSA",
          "n" => n,
          "e" => e,
          "d" => d,
          "p" => p,
          "q" => q,
          "dp" => dp,
          "dq" => dq,
          "qi" => qi
        } ->
          values = Enum.map([n, e, d, p, q, dp, dq, qi], &uint/1)
          [n, e, d, p, q, dp, dq, qi] = values

          {{:rsa, {:RSAPrivateKey, :"two-prime", n, e, d, p, q, dp, dq, qi, :asn1_NOVALUE}},
           {:rsa, n, e}}

        %{"kty" => "EC", "crv" => crv, "x" => x, "y" => y, "d" => d} ->
          {_, width, _} = Algorithm.curve(crv)
          x = b64(x)
          y = b64(y)
          d = b64(d)

          ensure(
            byte_size(x) == width and byte_size(y) == width and byte_size(d) == width,
            :invalid_key
          )

          {{:ec, crv, d}, {:ec, crv, <<4, x::binary, y::binary>>}}

        %{"kty" => "OKP", "crv" => "X25519", "x" => x, "d" => d} ->
          {{:x25519, b64(d)}, {:x25519, b64(x)}}

        %{"kty" => "OKP", "crv" => "Ed25519", "x" => x, "d" => d} ->
          {{:ed25519, b64(d)}, {:ed25519, b64(x)}}

        %{"kty" => "oct", "k" => k} ->
          kind =
            cond do
              jose == "dir" -> :cek
              jose in ~w(A128KW A256KW A128GCMKW A256GCMKW) -> :aes
              true -> :hmac
            end

          {{kind, b64(k)}, nil}

        _ ->
          fail(:invalid_key)
      end

    expected =
      if expected == nil do
        nil
      else
        %PublicKey{
          material: expected,
          algorithm: value["alg"],
          use: value["use"],
          operations: ops
        }
      end

    {material, nil, expected, capabilities}
  end

  defp decode(_, _, _), do: fail(:unsupported_format)

  defp capabilities(jose) when jose in @ecdh, do: [:unwrap]

  defp capabilities(jose) when jose in ~w(RSA-OAEP RSA-OAEP-256 A128GCMKW A256GCMKW dir),
    do: [:unwrap]

  defp capabilities(jose) when jose in ~w(A128KW A256KW), do: [:wrap, :unwrap]
  defp capabilities(_), do: [:sign, :verify]

  defp canonical(type, der) do
    decoded = :public_key.der_decode(type, der)
    ensure(:public_key.der_encode(type, decoded) == der, :invalid_key)
    decoded
  end

  defp pkcs8(der) do
    # public_key's PrivateKeyInfo decoder unwraps RSA-PSS and fills default
    # parameters. Read the container first to preserve absent vs constrained PSS.
    info =
      case :"PKCS-FRAME".decode(:PrivateKeyInfo, der) do
        {:ok, info} -> info
        _ -> fail(:unsupported_format)
      end

    {:ok, encoded} = :"PKCS-FRAME".encode(:PrivateKeyInfo, info)
    ensure(encoded == der, :invalid_key)

    {oid, params, private} = Support.pkcs8_components(info)

    params =
      case params do
        {:asn1_OPENTYPE, bytes} -> bytes
        absent -> absent
      end

    case oid do
      oid when oid in [@rsa, @pss] ->
        ensure(
          if(oid == @pss, do: params == :asn1_NOVALUE, else: params in [:asn1_NOVALUE, <<5, 0>>]),
          :unsupported_format
        )

        {{:rsa, canonical(:RSAPrivateKey, private)}, if(oid == @pss, do: :rsa_pss, else: :rsa),
         nil}

      @ec ->
        curve = :public_key.der_decode(:EcpkParameters, params)
        {:ECPrivateKey, version, scalar, inner, point, attrs} = canonical(:ECPrivateKey, private)
        ensure(inner == :asn1_NOVALUE or inner == curve, :invalid_key)
        ec_private({:ECPrivateKey, version, scalar, curve, point, attrs})

      @ed ->
        ensure(params == :asn1_NOVALUE, :invalid_key)
        <<4, 32, seed::binary-size(32)>> = private
        {{:ed25519, seed}, nil, nil}

      _ ->
        fail(:unsupported_format)
    end
  end

  defp ec_private({:ECPrivateKey, _, scalar, {:namedCurve, oid}, point, _}) do
    crv =
      case oid do
        {1, 2, 840, 10045, 3, 1, 7} -> "P-256"
        {1, 3, 132, 0, 34} -> "P-384"
        _ -> fail(:invalid_key)
      end

    expected = if point == :asn1_NOVALUE, do: nil, else: {:ec, crv, point}
    {{:ec, crv, scalar}, nil, expected}
  end

  defp b64(value) do
    ensure(is_binary(value) and byte_size(value) in 1..21_846, :invalid_key)
    {:ok, bytes} = Base.url_decode64(value, padding: false)
    ensure(Base.url_encode64(bytes, padding: false) == value, :invalid_key)
    bytes
  end

  defp uint(value) do
    ensure(is_binary(value) and byte_size(value) <= 1366, :invalid_key)
    bytes = b64(value)
    ensure(:binary.first(bytes) != 0, :invalid_key)
    :binary.decode_unsigned(bytes)
  end
end
