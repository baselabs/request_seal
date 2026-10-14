defmodule RequestSeal.JOSE.JWE do
  @moduledoc """
  Compact RFC 7516 encryption with explicitly pinned algorithms and AES GCM.

  `encrypt/4` generates a fresh content-encryption key (CEK) and IV and hands the
  CEK to the recipient's public key or a caller wrapper; `decrypt/2` authenticates
  and decrypts under an explicit policy. Key management is `RSA-OAEP-256`,
  `RSA-OAEP`, `A128GCMKW`, `A256GCMKW`, or `dir`; content encryption is `A128GCM`
  or `A256GCM`. No symmetric secret can be supplied in a public key or header.

  On the decryption handle path, RSA-OAEP private operations stay inside the
  handle's sensitive local holder; the callback path can still use caller-owned
  raw key material. Resolver and callback unwrap execute in JWE's sensitive
  worker. On the handle path, the CEK passes from the sensitive local holder
  through a separate sensitive custody runner and middle process to that JWE
  worker. These four processes see the CEK; JWE's outer middle process and the
  decrypt caller receive only the authenticated result. All work shares one
  absolute deadline. Unwrap failure uses a fresh random CEK and still attempts
  tag authentication; both paths return `:decryption_failed`.

  A released or unavailable resolved handle makes decryption fail with the same
  complete error as a forged message, by design. Check
  `RequestSeal.Custody.public_key(handle)` at startup: `{:ok, public_key}` confirms
  public resolution; `{:error, error}` reports custody availability separately
  from message processing. Handle algorithm/capability mismatch also follows the
  unwrap-failure path. Resolver algorithm mismatch remains a key-selection error,
  and deadline expiration remains distinct.

  CEK/IV use the real CSPRNG. Decrypted data stays in the private worker until
  full authentication succeeds; no partial result is returned. IVs are 12 bytes,
  tags 16 bytes, CEKs exactly 16/32 bytes. The protected segment is verbatim AAD.
  Recipient integrity establishes no sender identity, request association, claims
  validation, or authorization.
  """
  alias RequestSeal.{Custody, KeyHandle, PublicKey, JOSE}
  alias JOSE.{Header, KeyManagement, Support}
  alias JOSE.JWE.Result
  import Support

  @doc """
  Encrypt plaintext into a compact JWE with fresh CEK and IV bytes (RFC 7516).

  The protected header is compact JSON: top-level members keep caller order,
  followed by recipient additions sorted by member name; nested JSON objects are
  serialized in map order. For JWS signatures needing exact protected bytes, use
  `RequestSeal.JOSE.JWS.sign_protected/4`. Wrapping and encryption run in a
  sensitive worker with deadline and caller cancellation. This function accepts
  no policy map; decryption selects its own explicit policy.

  ## Parameters

    * `header` - `t:RequestSeal.JOSE.header/0` with unique members, at most 64
      pairs, nesting depth at most four, serialized size at most 16,384 bytes.
      `"alg"` must be `"RSA-OAEP-256"`, `"RSA-OAEP"`, `"A128GCMKW"`, `"A256GCMKW"`,
      or `"dir"`; `"enc"` must be `"A128GCM"` or `"A256GCM"`. `"crit"`, `"zip"`,
      `"jku"`, `"x5u"`, `"jwk"`, and `"b64"` reject regardless of their values.
    * `plaintext` - binary, at most 1,048,576 bytes; the compact result has the
      same bound.
    * `recipient` - one of:
      * a `RequestSeal.PublicKey` with RSA material, for `"RSA-OAEP"` and
        `"RSA-OAEP-256"`. Its `algorithm` must be nil or the header `alg`, `use`
        nil or `"enc"`, and `operations` nil or include `"encrypt"` or `"wrapKey"`.
      * an arity-two function receiving `(wire_algorithm, generated_cek_bytes)`
        and returning `{:ok, %{encrypted_key: bytes, header: additions_map}}`
        with exactly those keys. Additions may contain only `"iv"`/`"tag"`, only
        for `"A128GCMKW"`/`"A256GCMKW"`, cannot replace caller members, and become
        authenticated protected headers. For `"dir"`, the function provisions the
        generated CEK to its recipient through caller-owned custody and returns an
        empty encrypted key. `RequestSeal.JOSE.KeyManagement.wrap/4` produces this
        result shape.
    * `opts` - keyword list.

  ## Options

    * `:timeout` - integer milliseconds, 1 to 300,000. Default 5,000.

  ## Returns

    * `{:ok, compact}` - five unpadded Base64url segments:
      `protected.encrypted_key.iv.ciphertext.tag`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_options` (option or recipient form), `:invalid_serialization`
      (non-binary plaintext), `:limit` (more than 64 pairs or an oversized
      result), `:invalid_header` (including, from 0.5.0 (unreleased), a header that is not a list of
      `{name, value}` pairs), `:duplicate_member`
      (including an addition that repeats a caller member),
      `:unsupported_critical_header`, `:compression_unsupported`,
      `:unsupported_header` (including disallowed additions),
      `:algorithm_not_permitted` (unsupported `alg`, or missing or unsupported
      `enc`),
      `:algorithm_mismatch` (public key unusable for `alg`), `:invalid_base64`,
      `:invalid_iv`, `:invalid_tag` (malformed `iv`/`tag` additions),
      `:decryption_failed` (encrypted key with the wrong width for `alg`),
      `:entropy_failure`, `:signer_failed` (wrapper error, exception, or invalid
      result; invalid public key), and `:deadline_exceeded` (the only retryable
      reason). This function has no key resolver and does not return
      `:key_resolver_failed`. Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

  This example uses actual RFC 7518 AES GCM key wrapping and content encryption:

      iex> wrapping_key = {:aes, :crypto.strong_rand_bytes(32)}
      iex> wrap = fn algorithm, cek -> RequestSeal.JOSE.KeyManagement.wrap(algorithm, cek, %{}, wrapping_key) end
      iex> {:ok, token} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256GCMKW"}, {"enc", "A256GCM"}], "payload", wrap, timeout: 5_000)
      iex> is_binary(token) and length(String.split(token, ".")) == 5
      true
      iex> {:error, error} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256GCMKW"}, {"enc", "A256GCM"}], "payload", wrap, timeout: 0)
      iex> error.reason
      :invalid_options
      iex> {:error, error} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256GCMKW"}, {"enc", "A256GCM"}, {"zip", "DEF"}], "payload", wrap)
      iex> error.reason
      :compression_unsupported
  """
  @spec encrypt(JOSE.header(), binary(), PublicKey.t() | function(), keyword()) ::
          {:ok, binary()} | {:error, JOSE.Error.t()}
  def encrypt(header, plaintext, recipient, opts \\ []) do
    safe(fn ->
      timeout = timeout(opts)

      worker(
        timeout,
        fn -> encrypt_internal(header, plaintext, recipient) end,
        :signer_failed,
        :crypto
      )
    end)
  end

  defp encrypt_internal(header, plaintext, recipient) do
    bytes(plaintext)
    h = Header.from_pairs(header)
    alg = selected(h, :jwe, algorithms(:jwe), encryption())
    cek = random(width(h["enc"]))
    iv = random(12)

    wrap =
      case recipient do
        %PublicKey{} = key ->
          public!(key, alg)
          {:rsa, n, e} = key.material
          KeyManagement.wrap(alg, cek, h, {:rsa, {:RSAPublicKey, n, e}})

        fun when is_function(fun, 2) ->
          callback(fn -> fun.(alg, cek) end, :signer_failed, :crypto)

        _ ->
          fail(:invalid_options)
      end

    {ek, additions} =
      case wrap do
        {:ok, %{encrypted_key: ek, header: extra} = result}
        when map_size(result) == 2 and is_binary(ek) and is_map(extra) ->
          {ek, extra}

        {:error, %JOSE.Error{reason: :entropy_failure}} ->
          fail(:entropy_failure, :crypto)

        _ ->
          fail(:signer_failed, :crypto)
      end

    ensure(
      map_size(additions) <= 2 and Enum.all?(Map.keys(additions), &(&1 in ~w(iv tag))),
      :unsupported_header
    )

    ensure(alg in ~w(A128GCMKW A256GCMKW) or additions == %{}, :unsupported_header)
    ensure(not Enum.any?(Map.keys(additions), &Map.has_key?(h, &1)), :duplicate_member)
    {protected, h} = Header.serialize(header ++ Enum.sort(additions))
    encrypted_key!(alg, ek, h)

    {ct, tag} =
      :crypto.crypto_one_time_aead(cipher(h["enc"]), cek, iv, plaintext, protected, 16, true)

    compact = Enum.map_join([protected, b64(ek), b64(iv), b64(ct), b64(tag)], ".", & &1)
    bytes(compact)
    {:ok, compact}
  end

  @doc """
  Authenticate and decrypt a compact JWE under an explicit policy (RFC 7516).

  Resolution, unwrapping, and authentication share one absolute deadline with
  sensitive workers and caller cancellation. No plaintext leaves the worker
  before full tag authentication. The received protected segment is used verbatim
  as AAD.

  ## Parameters

    * `compact` - binary compact JWE, at most 1,048,576 bytes, with exactly five
      segments. JSON serializations (input starting with `{` or `[`) reject. The
      protected header follows the bounds in `RequestSeal.JOSE.JWS.sign_protected/4`
      and is at most 21,846 Base64url bytes. The IV must decode to 12 bytes and the
      tag to 16 bytes. The encrypted key must be empty for `"dir"`, the CEK width
      for GCM key wrapping (with protected `"iv"` and `"tag"` members), and 256 to
      1,024 bytes for RSA.
    * `policy` - a map containing exactly these atom keys:
      * `:algorithms` - nonempty unique list selected from `"RSA-OAEP-256"`,
        `"RSA-OAEP"`, `"A128GCMKW"`, `"A256GCMKW"`, and `"dir"`.
      * `:encryption` - nonempty unique list selected from `"A128GCM"` and
        `"A256GCM"`.
      * `:max_plaintext` - integer bytes, 1 to 1,048,576; bounds the ciphertext.
      * `:timeout` - integer milliseconds, 1 to 300,000.
      * `:key_resolver` - arity-one function receiving
        `%{algorithm: wire_name, encryption: wire_name, header: decoded_header_map}`.
        It returns `:error`,
        `{:ok, %{algorithm: same_name, unwrap: arity_two_function}}`, or
        `{:ok, %{algorithm: same_name, key: custody_handle}}`, with exactly two
        entry keys. Unwrap receives `(encrypted_key_bytes, header)` and returns
        `{:ok, cek_bytes}` or `{:error, term}`; a CEK whose width differs from the
        `enc` key size counts as failure. The `key:` handle form works only for
        `"RSA-OAEP"` and `"RSA-OAEP-256"`, binding `{:jwe, same_name}` with only
        `:unwrap` capability; RSA private operations stay in custody. `"dir"`,
        `"A128GCMKW"`, and `"A256GCMKW"` require the `unwrap:` callback. A handle
        supplied for one of those algorithms returns `:decryption_failed`.

  ## Returns

    * `{:ok, %RequestSeal.JOSE.JWE.Result{}}` - carries `algorithm`, `encryption`,
      decoded `header`, received `protected` segment, and `plaintext`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_policy`, `:invalid_serialization`, `:unsupported_serialization`,
      `:limit` (including ciphertext above `:max_plaintext`), `:invalid_base64`,
      `:invalid_header`, `:duplicate_member`, `:unsupported_critical_header`,
      `:compression_unsupported`, `:unsupported_header`, `:algorithm_not_permitted`
      (`alg` or `enc` outside the policy), `:invalid_iv`, `:invalid_tag`,
      `:unknown_key` (resolver returned `:error`), `:algorithm_mismatch` (resolver
      returned another algorithm), `:key_resolver_failed` (resolver exception or
      invalid entry), `:entropy_failure`, `:decryption_failed` (wrong encrypted-key
      width, unwrap failure, or authentication failure), and `:deadline_exceeded`
      (the only retryable reason). Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

  This is a local RFC 7518 round trip, using real key wrapping and AEAD:

      iex> wrapping_key = {:aes, :crypto.strong_rand_bytes(32)}
      iex> wrap = fn algorithm, cek -> RequestSeal.JOSE.KeyManagement.wrap(algorithm, cek, %{}, wrapping_key) end
      iex> {:ok, token} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256GCMKW"}, {"enc", "A256GCM"}], "payload", wrap)
      iex> unwrap = fn bytes, header -> RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", bytes, header, wrapping_key) end
      iex> policy = %{algorithms: ["A256GCMKW"], encryption: ["A256GCM"], max_plaintext: 1_024, timeout: 5_000, key_resolver: fn _ -> {:ok, %{algorithm: "A256GCMKW", unwrap: unwrap}} end}
      iex> {:ok, result} = RequestSeal.JOSE.JWE.decrypt(token, policy)
      iex> result.plaintext
      "payload"
      iex> {:error, error} = RequestSeal.JOSE.JWE.decrypt(token, Map.delete(policy, :encryption))
      iex> error.reason
      :invalid_policy
      iex> other_key = {:aes, :crypto.strong_rand_bytes(32)}
      iex> wrong = fn bytes, header -> RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", bytes, header, other_key) end
      iex> {:error, error} = RequestSeal.JOSE.JWE.decrypt(token, %{policy | key_resolver: fn _ -> {:ok, %{algorithm: "A256GCMKW", unwrap: wrong}} end})
      iex> error.reason
      :decryption_failed
  """
  @spec decrypt(binary(), map()) :: {:ok, Result.t()} | {:error, JOSE.Error.t()}
  def decrypt(compact, policy) do
    safe(fn ->
      p = policy(policy, :jwe)
      deadline = System.monotonic_time(:millisecond) + p.timeout

      worker(
        p.timeout,
        fn -> decrypt_internal(compact, p, deadline) end,
        :decryption_failed,
        :crypto
      )
    end)
  end

  defp decrypt_internal(compact, p, deadline) do
    [protected, ek_wire, iv_wire, ct_wire, tag_wire] = compact(compact, 5)
    h = Header.parse(protected)
    alg = selected(h, :jwe, p.algorithms, p.encryption)
    ek = decode(ek_wire)
    iv = decode(iv_wire)
    ensure(byte_size(iv) == 12, :invalid_iv)
    tag = decode(tag_wire)
    ensure(byte_size(tag) == 16, :invalid_tag)
    ct = decode(ct_wire)
    ensure(byte_size(ct) <= p.max_plaintext, :limit)
    encrypted_key!(alg, ek, h)
    entry = resolve(p.key_resolver, %{algorithm: alg, encryption: h["enc"], header: h})

    unwrap = unwrapper(entry, alg, deadline)

    # Generate fallback unconditionally so the success path also performs CSPRNG work.
    fallback = random(width(h["enc"]))
    unwrapped = safe(fn -> unwrap.(ek, h) end, :decryption_failed, :crypto)
    ensure(System.monotonic_time(:millisecond) < deadline, :deadline_exceeded, :crypto)

    {cek, valid_unwrap} =
      case unwrapped do
        {:ok, key} when is_binary(key) and byte_size(key) == byte_size(fallback) -> {key, true}
        _ -> {fallback, false}
      end

    plaintext = :crypto.crypto_one_time_aead(cipher(h["enc"]), cek, iv, ct, protected, tag, false)
    ensure(is_binary(plaintext) and valid_unwrap, :decryption_failed, :crypto)

    {:ok,
     %Result{
       algorithm: alg,
       encryption: h["enc"],
       header: h,
       protected: protected,
       plaintext: plaintext
     }}
  end

  defp unwrapper(%{algorithm: _, unwrap: fun} = entry, _, _)
       when map_size(entry) == 2 and is_function(fun, 2) do
    fun
  end

  defp unwrapper(%{algorithm: _, key: %KeyHandle{} = handle} = entry, alg, deadline)
       when map_size(entry) == 2 do
    fn bytes, _header ->
      ensure(handle.algorithm == {:jwe, alg}, :decryption_failed, :crypto)
      ensure(handle.capabilities == [:unwrap], :decryption_failed, :crypto)
      remaining = deadline - System.monotonic_time(:millisecond)
      ensure(remaining > 0, :deadline_exceeded, :crypto)
      Custody.unwrap(handle, bytes, timeout: remaining)
    end
  end

  defp unwrapper(_, _, _), do: fail(:key_resolver_failed, :key)

  defp encrypted_key!("dir", ek, _), do: ensure(ek == "", :decryption_failed, :crypto)

  defp encrypted_key!(alg, ek, h) when alg in ~w(A128GCMKW A256GCMKW) do
    ensure(byte_size(ek) == width(h["enc"]), :decryption_failed, :crypto)
    ensure(byte_size(decode(h["iv"])) == 12, :invalid_iv)
    ensure(byte_size(decode(h["tag"])) == 16, :invalid_tag)
  end

  defp encrypted_key!(_, ek, _),
    do: ensure(byte_size(ek) in 256..1024, :decryption_failed, :crypto)

  defp public!(key, alg) do
    PublicKey.validate!(key)

    ensure(
      alg in ~w(RSA-OAEP RSA-OAEP-256) and match?({:rsa, _, _}, key.material),
      :algorithm_mismatch,
      :key
    )

    ensure(
      key.algorithm in [nil, alg] and key.use in [nil, "enc"] and
        (key.operations == nil or Enum.any?(key.operations, &(&1 in ~w(encrypt wrapKey)))),
      :algorithm_mismatch,
      :key
    )
  end

  defp width("A128GCM"), do: 16
  defp width("A256GCM"), do: 32
  defp cipher("A128GCM"), do: :aes_128_gcm
  defp cipher("A256GCM"), do: :aes_256_gcm
end
