defmodule RequestSeal.JOSE.JWE do
  @moduledoc """
  Compact RFC 7516 encryption with explicitly pinned algorithms and AES GCM.

  `encrypt/4` takes ordered protected header pairs with `alg`/`enc`, plaintext
  bytes, and a `PublicKey` or arity-two wrapper `(wire_algorithm, generated_cek)`.
  The wrapper returns `{:ok, %{encrypted_key: bytes, header: additions_map}}`;
  additions are protected, cannot replace caller members, and may contain only
  `iv`/`tag` for GCMKW. Protected headers use compact JSON: top-level members keep
  caller order, followed by additions sorted by member name; nested JSON objects
  are serialized in map order. For JWS signatures needing exact protected bytes,
  use `RequestSeal.JOSE.JWS.sign_protected/4`. For `dir`, the wrapper must
  provision the generated CEK to its recipient through caller-owned custody
  and return an empty encrypted key.
  No symmetric secret can be supplied in a public key or header. Only
  `timeout: milliseconds` is accepted (default 5,000; 1–300,000).

  `decrypt/2` requires exactly `:algorithms`, `:encryption`, `:max_plaintext`
  (1–1,048,576), `:timeout` (1–300,000), and `:key_resolver`. Algorithms are
  unique nonempty lists selected from RSA-OAEP-256, RSA-OAEP, A128GCMKW,
  A256GCMKW, dir; content encryption is A128GCM or A256GCM. The arity-one
  resolver receives `%{algorithm: name, encryption: name, header: map}` and
  returns `{:ok, %{algorithm: same_name, unwrap: arity_two_fun}}`,
  `{:ok, %{algorithm: same_name, key: custody_handle}}`, or `:error`.
  A custody handle must bind `{:jwe, same_name}` with `:unwrap` capability;
  RSA-OAEP private operations stay inside its sensitive local holder. The
  existing callback path can still use caller-owned raw key material.
  Unwrap receives `(encrypted_key_bytes, header)` and returns `{:ok, cek}` or
  `{:error, term}`. Resolver and unwrap execute within one sensitive custody
  worker and one absolute deadline. Unwrap failure uses a fresh random CEK and
  still attempts tag authentication; both paths return `:decryption_failed`.

  CEK/IV use the real CSPRNG. Decrypted data stays in the private worker until
  full authentication succeeds; no partial result is returned. IVs are 12 bytes,
  tags 16 bytes, CEKs exactly 16/32 bytes. The protected segment is verbatim AAD.
  Returns `{:ok, compact}` / `{:ok, Result}` or `{:error, JOSE.Error}`.
  """
  alias RequestSeal.{Custody, KeyHandle, PublicKey, JOSE}
  alias JOSE.{Header, KeyManagement, Support}
  alias JOSE.JWE.Result
  import Support

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
       when map_size(entry) == 2 and is_function(fun, 2),
       do: fun

  defp unwrapper(%{algorithm: _, key: %KeyHandle{} = handle} = entry, alg, deadline)
       when map_size(entry) == 2 do
    ensure(handle.algorithm == {:jwe, alg}, :algorithm_mismatch, :key)
    ensure(handle.capabilities == [:unwrap], :algorithm_mismatch, :key)

    fn bytes, _header ->
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
