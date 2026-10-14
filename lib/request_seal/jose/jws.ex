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
      that has the `:sign` capability, or an arity-two function receiving
      `({:jws, alg}, signing_input)` and returning `{:ok, signature}` (1 to 16,384
      bytes) or `{:error, term}`. Both run in a custody worker under the timeout.
    * `opts` - keyword list.

  ## Options

    * `:timeout` - integer milliseconds, 1 to 300,000. Default 5,000.

  ## Returns

    * `{:ok, compact}` - `protected.payload.signature`, each segment unpadded
      Base64url.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_options` (unknown, duplicate, or out-of-range option, or a signer
      that is neither form), `:invalid_serialization` (non-binary payload),
      `:detached_payload` (empty payload), `:limit` (more than 64 pairs or an
      oversized result), `:invalid_header` (including, from 0.5.0 (unreleased), a header that
      is not a list of `{name, value}` pairs; 0.4.1 returns `:limit`), `:duplicate_member`, `:unsupported_critical_header`,
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
          RequestSeal.KeyHandle.t() | RequestSeal.Policy.signer(),
          keyword()
        ) :: {:ok, binary()} | {:error, RequestSeal.JOSE.Error.t()}
  def sign(header, payload, signer, opts \\ []) do
    safe(fn ->
      timeout = timeout(opts)
      bytes(payload)
      ensure(payload != "", :detached_payload)
      {protected, h} = Header.serialize(header)
      alg = selected(h, :jws, algorithms(:jws))
      base = protected <> "." <> b64(payload)
      bytes(base)
      signature = Support.sign(signer, alg, base, timeout)
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
    * `signer` - a `RequestSeal.KeyHandle` or arity-two function, as in `sign/4`.
    * `opts` - keyword list.

  ## Options

    * `:timeout` - integer milliseconds, 1 to 300,000. Default 5,000.

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
          RequestSeal.KeyHandle.t() | RequestSeal.Policy.signer(),
          keyword()
        ) ::
          {:ok, binary()} | {:error, RequestSeal.JOSE.Error.t()}
  def sign_protected(protected_json, payload, signer, opts \\ []) do
    safe(fn ->
      timeout = timeout(opts)
      bytes(payload)
      ensure(payload != "", :detached_payload)
      h = Header.json(protected_json)
      alg = selected(h, :jws, algorithms(:jws))
      base = b64(protected_json) <> "." <> b64(payload)
      bytes(base)
      signature = Support.sign(signer, alg, base, timeout)
      compact = base <> "." <> b64(signature)
      bytes(compact)
      {:ok, compact}
    end)
  end

  @doc """
  Verify a compact JWS over its received protected and payload segments (RFC 7515).

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
      * `:key_resolver` - arity-one function receiving
        `%{algorithm: wire_name, header: decoded_header_map}`. It returns
        `:error` or `{:ok, %{algorithm: same_wire_name, key: key}}` with exactly
        those two entry keys. `key` is a `RequestSeal.PublicKey` or an arity-three
        verification function receiving `({:jws, wire_name}, exact_base_bytes,
        signature_bytes)` and returning exactly `:ok` on validity; any other
        return, including `{:ok, value}`, is `:invalid_signature`. Use the
        function form for `"HS256"` so the secret stays in caller-owned custody.

  ## Returns

    * `{:ok, %RequestSeal.JOSE.JWS.Result{}}` - only after verification; carries
      `algorithm`, decoded `header`, received `protected` segment, and `payload`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_policy`, `:invalid_serialization`, `:unsupported_serialization`,
      `:limit`, `:invalid_base64`, `:invalid_header`, `:duplicate_member`,
      `:unsupported_critical_header` (`"crit"`), `:compression_unsupported`
      (`"zip"`), `:unsupported_header` (`"jku"`, `"x5u"`, `"jwk"`, `"b64"`, regardless
      of value), `:algorithm_not_permitted`, `:detached_payload` (empty payload
      segment), `:unknown_key` (resolver returned `:error`), `:algorithm_mismatch`
      (resolver returned another algorithm), `:key_resolver_failed` (resolver
      exception or invalid entry), `:invalid_signature` (empty or invalid
      signature, or verification-function failure), and `:deadline_exceeded` (the
      only retryable reason). Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

  This example constructs and verifies a local RFC 8037 Ed25519 JWS:

      iex> {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
      iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
      iex> {:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], "payload", handle)
      iex> policy = %{algorithms: ["EdDSA"], timeout: 5_000, key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: key}} end}
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
    h = Header.parse(protected)
    alg = selected(h, :jws, p.algorithms)
    ensure(payload_wire != "", :detached_payload)
    payload = decode(payload_wire)
    signature = decode(signature_wire)
    ensure(signature != "", :invalid_signature, :crypto)
    entry = resolve(p.key_resolver, %{algorithm: alg, header: h})
    ensure(Enum.sort(Map.keys(entry)) == [:algorithm, :key], :key_resolver_failed, :key)
    base = protected <> "." <> payload_wire

    result =
      case entry.key do
        %RequestSeal.PublicKey{} = key ->
          RequestSeal.Crypto.verify({:jws, alg}, base, signature, key)

        fun when is_function(fun, 3) ->
          callback(fn -> fun.({:jws, alg}, base, signature) end, :invalid_signature, :crypto)

        _ ->
          fail(:key_resolver_failed, :key)
      end

    ensure(result == :ok, :invalid_signature, :crypto)
    {:ok, %Result{algorithm: alg, header: h, protected: protected, payload: payload}}
  end
end
