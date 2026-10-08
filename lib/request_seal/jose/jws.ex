defmodule RequestSeal.JOSE.JWS do
  @moduledoc """
  Compact RFC 7515 signatures over exact protected and payload segments.

  `sign/4` takes ordered header pairs, nonempty payload bytes, an algorithm-bound
  `KeyHandle` or `Policy.signer`, and only `timeout: milliseconds` (default 5,000;
  1–300,000). The ordered serializer uses CRLF and one space between members,
  matching RFC 7515 A.1. No received header is serialized again.

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
