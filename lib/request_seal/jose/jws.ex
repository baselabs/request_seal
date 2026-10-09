defmodule RequestSeal.JOSE.JWS do
  @moduledoc """
  Compact RFC 7515 signatures over exact protected and payload segments.

  `sign/4` takes ordered header pairs, nonempty payload bytes, an algorithm-bound
  `KeyHandle` or `Policy.signer`, and only `timeout: milliseconds` (default 5,000;
  1–300,000). Protected headers use compact JSON: top-level members keep caller
  order, and nested JSON objects are serialized in map order. Callers needing
  exact protected bytes use `sign_protected/4`. No received header is serialized again.

  `sign_protected/4` accepts caller-serialized protected JSON bytes without
  reserialization, with the same bounds and header rejections as `Header.json/1`.
  Payload, signer, timeout, and compact-output bounds match `sign/4`.

  `verify/2` takes a map containing exactly `:algorithms` (nonempty unique list
  of the eight Crypto JWS names), `:timeout` (1–300,000), and `:key_resolver`.
  The arity-one resolver receives `%{algorithm: wire_name, header: map}` and
  returns `{:ok, %{algorithm: same_wire_name, key: PublicKey_or_verify_fun}}`
  or `:error`. A verification function receives `({:jws, name}, base, signature)`;
  HMAC secrets remain inside that function's custody. All callbacks use the
  custody worker and an absolute operation deadline. `kid` and `x5c` are only
  untrusted header data; they establish no key trust or network permission.

  Returns `{:ok, compact}` / `{:ok, Result}` or `{:error, JOSE.Error}`.
  Empty payloads reject as `:detached_payload`. Cryptographic validity supplies
  no principal, claims validation, freshness, replay protection, or authorization.
  """
  alias RequestSeal.JOSE.{Header, Support}
  alias RequestSeal.JOSE.JWS.Result
  import Support

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

  @doc "Sign caller-serialized protected JSON bytes without reserialization."
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

  The policy must be a map containing exactly these atom keys:

  * `:algorithms`: a nonempty unique list selected from `"RS256"`, `"PS256"`,
    `"PS384"`, `"PS512"`, `"HS256"`, `"ES256"`, `"ES384"`, and `"EdDSA"`.
  * `:timeout`: an integer from 1 through 300,000 milliseconds, shared by key
    resolution and verification under one absolute deadline.
  * `:key_resolver`: an arity-one function receiving
    `%{algorithm: wire_name, header: decoded_header_map}`. It returns `:error`
    or `{:ok, %{algorithm: same_wire_name, key: public_key_or_verify_function}}`,
    with exactly those two entry keys. The verification function has arity three,
    receives `({:jws, wire_name}, exact_base_bytes, signature_bytes)`, and returns
    exactly `:ok` on validity. Any other return, including `{:ok, value}`, is
    `:invalid_signature`. Use it for HMAC so secrets remain in caller-owned custody.

  Returns `{:ok, RequestSeal.JOSE.JWS.Result.t()}` only after verification,
  otherwise `{:error, RequestSeal.JOSE.Error.t()}`. Error reasons are
  `:invalid_policy`, `:invalid_serialization`, `:unsupported_serialization`,
  `:limit`, `:invalid_base64`, `:invalid_header`, `:duplicate_member`,
  `:unsupported_critical_header`, `:compression_unsupported`, `:unsupported_header`,
  `:algorithm_not_permitted`, `:detached_payload`, `:unknown_key`,
  `:algorithm_mismatch`, `:key_resolver_failed`, `:invalid_signature`, and
  `:deadline_exceeded`. Resolver exceptions or invalid entries return
  `:key_resolver_failed`; resolver `:error` returns `:unknown_key`; verification
  callback failures return `:invalid_signature`. Only `:deadline_exceeded` is
  retryable. Protected header `"crit"` rejects as `:unsupported_critical_header`,
  `"zip"` as `:compression_unsupported`, and `"jku"`, `"x5u"`, `"jwk"`, and
  `"b64"` as `:unsupported_header`, regardless of their values.
  Resolver and verification callbacks execute in a sensitive worker with deadline
  and caller cancellation. Input is bounded to 1,048,576 bytes. Empty or detached
  payloads and noncompact serializations reject. Protected bytes are never
  reserialized. Header `kid`/`x5c` values confer no trust or network permission.
  Valid cryptography supplies no identity, claims validation, replay protection,
  freshness, or authorization.

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
