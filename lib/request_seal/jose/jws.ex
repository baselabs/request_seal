defmodule RequestSeal.JOSE.JWS do
  @moduledoc """
  Compact RFC 7515 signatures over exact protected and payload segments.

  `sign/4` builds the protected header from ordered pairs; `sign_protected/4`
  signs caller-serialized protected JSON bytes unchanged; `verify/2` checks a
  received compact JWS under an explicit policy. No received header is serialized
  again: verification signs over the received protected segment.

  `kid` and `x5c` are only untrusted header data; they establish no key trust or
  network permission. Cryptographic validity supplies no principal, claims
  validation, freshness, replay protection, or authorization.
  """
  alias RequestSeal.KeyHandle
  alias RequestSeal.JOSE.{Header, Support}
  alias RequestSeal.JOSE.JWS.Result
  import Support

  @doc """
  Sign a nonempty payload into a compact JWS, serializing ordered header pairs.

  The protected header is compact JSON: top-level members keep caller order, and
  nested JSON objects are serialized in map order. Use `sign_protected/4` when the
  exact protected bytes matter.

  ## Parameters

    * `header` - `t:RequestSeal.JOSE.header/0`, at most 64 pairs, nesting depth at
      most four, serialized size at most 16,384 bytes. `"alg"` is required and
      must be one of `"RS256"`, `"PS256"`, `"PS384"`, `"PS512"`, `"HS256"`,
      `"ES256"`, `"ES384"`, or `"EdDSA"`. `"crit"`, `"zip"`, `"jku"`, `"x5u"`,
      `"jwk"`, and `"b64"` reject regardless of their values.
    * `payload` - nonempty binary. The signing input and the compact result are
      each bounded to 1,048,576 bytes.
    * `signer` - a `RequestSeal.KeyHandle` whose algorithm is `{:jws, alg}` and
      that has the `:sign` capability. Signing runs in a custody worker under
      the timeout.
    * `opts` - keyword list.

  ## Options

    * `:timeout` - integer milliseconds, 1 to 300,000. Default 5,000.
    * `:issued_for` - required for an assigned handle. Omission and nil select
      unassigned custody.

  ## Returns

    * `{:ok, compact}` - `protected.payload.signature`, each segment unpadded
      Base64url.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_options` (unknown, duplicate, or out-of-range option, or a signer
      that is neither form), `:invalid_serialization` (non-binary payload),
      `:detached_payload` (empty payload), `:limit` (more than 64 pairs or an
      oversized result), `:invalid_header` (including a header that is not a list
      of `{name, value}` pairs), `:duplicate_member`, `:unsupported_critical_header`,
      `:compression_unsupported`, `:unsupported_header`, `:algorithm_not_permitted`,
      `:algorithm_mismatch` (handle bound to another algorithm), `:signer_failed`
      (signer error, exception, malformed result, or unusable handle), and
      `:deadline_exceeded` (the only retryable reason). Meanings:
      `RequestSeal.JOSE.Error`.

  ## Examples

      iex> {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
      iex> {:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}, {"kid", "build-signer-1"}], ~s({"artifact":"release.tar.gz"}), handle)
      iex> [protected, _payload, _signature] = String.split(token, ".")
      iex> Base.url_decode64!(protected, padding: false)
      ~s({"alg":"EdDSA","kid":"build-signer-1"})
      iex> {:error, error} = RequestSeal.JOSE.JWS.sign([{"alg", "ES256"}], "build log", handle)
      iex> error.reason
      :algorithm_mismatch
      iex> {:error, error} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], "", handle)
      iex> error.reason
      :detached_payload
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec sign(
          RequestSeal.JOSE.header(),
          binary(),
          RequestSeal.KeyHandle.t(),
          keyword()
        ) :: {:ok, binary()} | {:error, RequestSeal.JOSE.Error.t()}
  def sign(header, payload, signer, opts \\ []) do
    safe(fn ->
      {timeout, purpose} = signing_options(opts, signer)
      bytes(payload)
      ensure(payload != "", :detached_payload)
      {protected, h} = Header.serialize(header)
      alg = selected(h, :jws, algorithms(:jws))
      base = protected <> "." <> b64(payload)
      bytes(base)
      signature = Support.sign(signer, alg, base, timeout, purpose)
      compact = base <> "." <> b64(signature)
      bytes(compact)
      {:ok, compact}
    end)
  end

  @doc """
  Sign caller-serialized protected JSON bytes without reserializing them.

  The protected segment is the unpadded Base64url encoding of `protected_json`
  exactly as supplied.

  ## Parameters

    * `protected_json` - binary JSON object, at most 16,384 bytes, nesting depth at
      most four, at most 64 members per object and 64 entries per array, integers
      within ±999,999,999,999,999, no floats, and no duplicate members at any
      depth. `"alg"` is required and must be one of the eight algorithms listed
      in `sign/4`; `"crit"`, `"zip"`, `"jku"`, `"x5u"`, `"jwk"`, and `"b64"`
      reject regardless of their values.
    * `payload` - nonempty binary. The signing input and the compact result are
      each bounded to 1,048,576 bytes.
    * `signer` - a `RequestSeal.KeyHandle`, as in `sign/4`.
    * `opts` - keyword list.

  ## Options

    * `:timeout` - integer milliseconds, 1 to 300,000. Default 5,000.
    * `:issued_for` - required for an assigned handle. Omission and nil select
      unassigned custody.

  ## Returns

    * `{:ok, compact}` - `protected.payload.signature`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - the same reasons as `sign/4`:
      `:invalid_options`, `:invalid_serialization`, `:detached_payload`, `:limit`,
      `:invalid_header` (including JSON that is not an object or is not valid),
      `:duplicate_member`, `:unsupported_critical_header`,
      `:compression_unsupported`, `:unsupported_header`, `:algorithm_not_permitted`,
      `:algorithm_mismatch`, `:signer_failed`, and `:deadline_exceeded`. Meanings:
      `RequestSeal.JOSE.Error`.

  ## Examples

      iex> {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
      iex> protected = ~s({"kid":"telemetry-1", "alg":"EdDSA"})
      iex> {:ok, token} = RequestSeal.JOSE.JWS.sign_protected(protected, ~s({"cpu":0.42}), handle)
      iex> [segment, _payload, _signature] = String.split(token, ".")
      iex> Base.url_decode64!(segment, padding: false) == protected
      true
      iex> {:error, error} = RequestSeal.JOSE.JWS.sign_protected(~s({"alg":"EdDSA","alg":"EdDSA"}), "reading", handle)
      iex> error.reason
      :duplicate_member
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec sign_protected(
          binary(),
          binary(),
          RequestSeal.KeyHandle.t(),
          keyword()
        ) ::
          {:ok, binary()} | {:error, RequestSeal.JOSE.Error.t()}
  def sign_protected(protected_json, payload, signer, opts \\ []) do
    safe(fn ->
      {timeout, purpose} = signing_options(opts, signer)
      bytes(payload)
      ensure(payload != "", :detached_payload)
      h = Header.json(protected_json)
      alg = selected(h, :jws, algorithms(:jws))
      base = b64(protected_json) <> "." <> b64(payload)
      bytes(base)
      signature = Support.sign(signer, alg, base, timeout, purpose)
      compact = base <> "." <> b64(signature)
      bytes(compact)
      {:ok, compact}
    end)
  end

  defp signing_options(opts, signer) do
    timeout = timeout(opts, [:timeout, :issued_for])
    purpose = Keyword.get(opts, :issued_for)
    ensure(KeyHandle.purpose?(purpose), :invalid_options)

    case signer do
      %KeyHandle{issued_for: assigned} -> ensure(purpose == assigned, :issued_for_mismatch, :key)
      _ -> ensure(purpose == nil, :issued_for_mismatch, :key)
    end

    {timeout, purpose}
  end

  @doc """
  Verify a compact JWS over its received protected and payload segments (RFC 7515).

  Set `:require_issued_for` in the policy to verify with an assigned handle.
  Omission and nil select keys without a purpose assignment.

  Key resolution and verification run in a sensitive custody worker under one
  absolute deadline, with caller cancellation. Protected bytes are never
  reserialized.

  ## Parameters

    * `compact` - binary compact JWS, at most 1,048,576 bytes, with exactly three
      segments, a nonempty payload, and a protected segment of at most 21,846
      bytes. JSON serializations (input starting with `{` or `[`) reject.
      The protected header follows the bounds in `sign_protected/4`.
    * `policy` - a map containing exactly these atom keys:
      * `:algorithms` - nonempty unique list selected from `"RS256"`,
        `"PS256"`, `"PS384"`, `"PS512"`, `"HS256"`, `"ES256"`, `"ES384"`, and
        `"EdDSA"`. The received `alg` must be in this list.
      * `:timeout` - integer milliseconds, 1 to 300,000, shared by key
        resolution and verification.
      * `:protected` - exactly `%{expected: map, permitted: names,
        embedded_key: :refuse | :require}`. Expected values are decoded JSON
        terms compared exactly; absence and difference both return
        `:protected_mismatch`. At most 64 string keys and 16,384 serialized
        bytes are allowed. Permitted names are a unique list of at most 64
        strings. Overlap, alg or jwk in either set, and any extra field reject
        as `:invalid_policy`. The read set is alg, plus jwk under :require;
        every other member must be expected or permitted, else
        `:unexpected_member`. x5c is uninterpreted and needs explicit naming.
      * `:key_resolver` - arity one receiving `%{algorithm: alg, header: header}`
        and, under :require, `embedded_key: PublicKey.t()`. It returns `:error`
        or exactly `{:ok, %{algorithm: same_alg, key: key}}`. Under :refuse,
        key is a PublicKey or a :verify KeyHandle bound to `{:jws, alg}`;
        closures and :embedded return `:key_resolver_failed`. Under :require,
        only `key: :embedded` is accepted; public keys and handles are refused.

  Admission checks header refusals and algorithm selection, then the member
  set and expected values before resolution. Under :refuse, jwk is unsupported.
  Under :require, jwk must be a public RSA (only kty/n/e, 2,048–8,192 bits), EC
  (only kty/crv/x/y, P-256 or P-384), or OKP Ed25519 (only kty/crv/x) object
  accepted by `RequestSeal.PublicKey.import/2`. Missing/extra/private members,
  oct, X25519, nonobjects, or import failure give `:invalid_header`/`:input`.
  Shape precedes binding: a valid imported key incompatible with alg gives
  `:algorithm_mismatch`/`:key`. Both checks precede the resolver. The signature
  is always checked against the selected embedded key over the received bytes.
  jku and x5u remain unsupported; x5c supplies no automatic certificate trust.
  This is the RFC 9449 embedded signature-key primitive, without DPoP claims,
  method/URI/time/token binding, replay, identity, or authorization checks.

  ## Returns

    * `{:ok, %RequestSeal.JOSE.JWS.Result{}}` - only after verification; carries
      `algorithm`, decoded `header`, received `protected` segment, and `payload`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_policy`, `:invalid_serialization`, `:unsupported_serialization`,
      `:limit`, `:invalid_base64`, `:invalid_header`, `:duplicate_member`,
      `:unexpected_member`, `:protected_mismatch` (input layer),
      `:unsupported_critical_header` (`"crit"`), `:compression_unsupported`
      (`"zip"`), `:unsupported_header` (`"jku"`, `"x5u"`, `"b64"` regardless of
      value, and `"jwk"` under `:refuse`), `:algorithm_not_permitted`, `:detached_payload` (empty payload
      segment), `:unknown_key` (resolver returned `:error`), `:algorithm_mismatch`
      (resolver returned another algorithm, embedded binding mismatch, or selected an X25519 key), `:key_resolver_failed` (resolver
      exception or invalid entry), `:invalid_signature` (empty or invalid
      signature, or custody verification failure), and `:deadline_exceeded` (the
      only retryable reason). Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

  This example constructs and verifies a local RFC 8037 Ed25519 JWS:

      iex> {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
      iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
      iex> {:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], "payload", handle)
      iex> policy = %{algorithms: ["EdDSA"], timeout: 5_000, protected: %{expected: %{}, permitted: [], embedded_key: :refuse}, key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: key}} end}
      iex> {:ok, result} = RequestSeal.JOSE.JWS.verify(token, policy)
      iex> result.payload
      "payload"
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
      iex> {:error, error} = RequestSeal.JOSE.JWS.verify(token, Map.put(policy, :extra, true))
      iex> error.reason
      :invalid_policy
      iex> {:error, error} = RequestSeal.JOSE.JWS.verify(token, %{policy | key_resolver: fn _ -> :error end})
      iex> error.reason
      :unknown_key
  """
  @spec verify(binary(), map()) :: {:ok, Result.t()} | {:error, RequestSeal.JOSE.Error.t()}
  def verify(compact, policy) do
    safe(fn ->
      p = policy(policy, :jws)
      worker(p.timeout, fn -> verify_internal(compact, p) end, :invalid_signature, :crypto)
    end)
  end

  defp verify_internal(compact, p) do
    [protected, payload_wire, signature_wire] = compact(compact, 3)
    h = Header.parse(protected, p.protected.embedded_key)
    alg = selected(h, :jws, p.algorithms)
    read = if p.protected.embedded_key == :require, do: ~w(alg jwk), else: ~w(alg)
    protected!(h, p.protected.expected, p.protected.permitted, read)
    embedded = if p.protected.embedded_key == :require, do: embedded!(h["jwk"], alg), else: nil
    ensure(payload_wire != "", :detached_payload)
    payload = decode(payload_wire)
    signature = decode(signature_wire)
    ensure(signature != "", :invalid_signature, :crypto)
    request = %{algorithm: alg, header: h}
    request = if embedded, do: Map.put(request, :embedded_key, embedded), else: request
    entry = resolve(p.key_resolver, request)
    ensure(Enum.sort(Map.keys(entry)) == [:algorithm, :key], :key_resolver_failed, :key)
    base = protected <> "." <> payload_wire

    key =
      if p.protected.embedded_key == :require do
        ensure(entry.key == :embedded, :key_resolver_failed, :key)
        embedded
      else
        ensure(entry.key != :embedded, :key_resolver_failed, :key)
        entry.key
      end

    purpose = Map.get(p, :require_issued_for)

    if purpose != nil do
      ensure(match?(%KeyHandle{issued_for: ^purpose}, key), :issued_for_mismatch, :key)
    end

    result =
      case key do
        %RequestSeal.PublicKey{} = key ->
          ensure(not match?({:x25519, _}, key.material), :algorithm_mismatch, :key)
          RequestSeal.Crypto.verify({:jws, alg}, base, signature, key)

        %RequestSeal.KeyHandle{} = handle ->
          ensure(handle.algorithm == {:jws, alg}, :algorithm_mismatch, :key)
          ensure(handle.issued_for == purpose, :issued_for_mismatch, :key)

          RequestSeal.Custody.verify(handle, base, signature,
            timeout: p.timeout,
            issued_for: purpose,
            operation: :jws
          )

        _ ->
          fail(:key_resolver_failed, :key)
      end

    ensure(result == :ok, :invalid_signature, :crypto)
    {:ok, %Result{algorithm: alg, header: h, protected: protected, payload: payload}}
  end

  defp embedded!(jwk, alg) do
    ensure(is_map(jwk) and not is_struct(jwk), :invalid_header)

    keys =
      case jwk do
        %{"kty" => "RSA"} -> ~w(e kty n)
        %{"kty" => "EC", "crv" => crv} when crv in ["P-256", "P-384"] -> ~w(crv kty x y)
        %{"kty" => "OKP", "crv" => "Ed25519"} -> ~w(crv kty x)
        _ -> fail(:invalid_header)
      end

    ensure(Enum.sort(Map.keys(jwk)) == keys, :invalid_header)

    key =
      case RequestSeal.PublicKey.import(jwk, :jwk) do
        {:ok, key} -> key
        _ -> fail(:invalid_header)
      end

    bound =
      RequestSeal.Crypto.Support.safe(:key_mismatch, fn ->
        RequestSeal.PublicKey.bind!(key, RequestSeal.Crypto.Algorithm.resolve({:jws, alg}))
        :ok
      end)

    ensure(bound == :ok, :algorithm_mismatch, :key)
    key
  end
end
