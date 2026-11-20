defmodule RequestSeal.JOSE.JWE do
  @moduledoc """
  Compact RFC 7516 encryption with explicitly pinned algorithms and AES GCM.

  `encrypt/4` generates a fresh content-encryption key (CEK) and IV and hands the
  CEK to an RSA public key, AES-KW handle, or caller wrapper. ECDH-ES instead
  agrees a fresh CEK with a public recipient, adding its public ephemeral key;
  `decrypt/2` authenticates
  and decrypts under an explicit policy. Key management is `RSA-OAEP-256`,
  `RSA-OAEP`, `A128KW`, `A256KW`, or the ECDH-ES family; decryption also admits A128GCMKW,
  A256GCMKW, and `dir`. Content encryption is A128GCM or A256GCM. No symmetric secret can be supplied in a public key or header.

  Decryption resolves only custody handles. CEKs pass directly from sensitive
  holders through range-owned sinks; custody workers return summaries.
  Admission and resolution end at R, unwrap at U, and content authentication at
  D. A random CEK is prepared on every key-management path, success included.
  Key-management failure still runs AEAD and returns `:decryption_failed`.
  `decrypt_many/2` shares these rules and groups items into one call per handle.

  A released or unavailable resolved handle makes decryption fail with the same
  complete error as a forged message, by design. Check
  `RequestSeal.Custody.public_key(handle)` at startup for asymmetric handles:
  `{:ok, public_key}` confirms public resolution. Symmetric handles have no
  public export; `Custody.identity/1` can check holder availability, keeping
  the identity out of general results, logs, and telemetry. Handle algorithm/capability mismatch also follows the
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
  alias KeyManagement.Agreement
  @ecdh ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)
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
      `"alg"` must be RSA-OAEP-256, RSA-OAEP, A128KW, A256KW,
      ECDH-ES, ECDH-ES+A128KW, or ECDH-ES+A256KW;
      GCMKW and `dir` are refused as `:algorithm_not_permitted`, layer `:input`,
      before recipient validation, custody, or random draws; `"enc"` must be `"A128GCM"` or `"A256GCM"`. `"crit"`, `"zip"`,
      `"jku"`, `"x5u"`, `"jwk"`, and `"b64"` reject regardless of their values.
    * `plaintext` - binary, at most 1,048,576 bytes; the compact result has the
      same bound.
    * `recipient` - one of:
      * a `RequestSeal.PublicKey` with RSA material, for `"RSA-OAEP"` and
        `"RSA-OAEP-256"`. Its `algorithm` must be nil or the header `alg`, `use`
        nil or `"enc"`, and `operations` nil or include `"encrypt"` or `"wrapKey"`.
      * a P-256, P-384, or X25519 `RequestSeal.PublicKey` for ECDH-ES and
        its +A128KW/+A256KW variants. Its metadata must permit key agreement.
        Decoded `apu`/`apv` are bounded to 1,024 bytes and distinct when both
        are present; their caller-supplied Base64url is preserved. A fresh
        ephemeral key supplies `epk`, which cannot replace a caller member.
      * a `RequestSeal.KeyHandle` binding `{:jwe, "A128KW"}` or
        `{:jwe, "A256KW"}` and granting `:wrap`. Custody wraps a copy of the
        generated CEK and returns no header additions.
      * an arity-two function receiving `(wire_algorithm, generated_cek_bytes)`
        and returning `{:ok, %{encrypted_key: bytes, header: %{}}}`. This
        callback form is refused for ECDH-ES before key work and never
        receives an agreed CEK.
    * `opts` - keyword list.

  ## Options

    * `:timeout` - integer milliseconds, 1 to 300,000. Default 5,000.

  ## Returns

    * `{:ok, compact}` - five unpadded Base64url segments:
      `protected.encrypted_key.iv.ciphertext.tag`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_options` (option or recipient form), `:invalid_serialization`
      (non-binary plaintext), `:limit` (more than 64 pairs or an oversized
      result), `:invalid_header` (including a header that is not a list of
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

  This example uses actual RFC 3394 AES-KW and AES-GCM content encryption:

      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jwe, "A256KW"}, {:aes, :crypto.strong_rand_bytes(32)})
      iex> {:ok, token} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", handle)
      iex> is_binary(token) and length(String.split(token, ".")) == 5
      true
      iex> RequestSeal.Custody.release(handle)
      :ok
  """
  @spec encrypt(JOSE.header(), binary(), PublicKey.t() | KeyHandle.t(), keyword()) ::
          {:ok, binary()} | {:error, JOSE.Error.t()}
  def encrypt(header, plaintext, recipient, opts \\ []) do
    safe(fn ->
      timeout = timeout(opts)

      worker(
        timeout,
        fn ->
          encrypt_internal(
            header,
            plaintext,
            recipient,
            System.monotonic_time(:millisecond) + timeout
          )
        end,
        :signer_failed,
        :crypto
      )
    end)
  end

  defp encrypt_internal(header, plaintext, recipient, deadline) do
    h = Header.from_pairs(header)
    alg = selected(h, :jwe, algorithms(:jwe_encrypt), encryption())
    bytes(plaintext)
    ensure(alg not in @ecdh or is_struct(recipient, PublicKey), :invalid_options)

    {cek, ek, additions} =
      if alg in @ecdh do
        params_in = Agreement.header_parties!(h)

        case KeyManagement.agree(alg, h["enc"], recipient, params_in) do
          {:ok, result} -> {result.cek, result.encrypted_key, result.header}
          {:error, %JOSE.Error{} = error} -> fail(error.reason, error.layer)
        end
      else
        cek = random(width(h["enc"]))
        {ek, additions} = wrap_recipient(alg, cek, h, recipient, deadline)
        {cek, ek, additions}
      end

    iv = random(12)

    ensure(
      additions == %{} or (alg in @ecdh and Map.keys(additions) == ["epk"]),
      :unsupported_header
    )

    ensure(not Enum.any?(Map.keys(additions), &Map.has_key?(h, &1)), :duplicate_member)
    {protected, h} = Header.serialize(header ++ Enum.sort(additions))
    encrypted_key!(alg, ek, h)

    {ct, tag} =
      :crypto.crypto_one_time_aead(cipher(h["enc"]), cek, iv, plaintext, protected, 16, true)

    compact = Enum.map_join([protected, b64(ek), b64(iv), b64(ct), b64(tag)], ".", & &1)
    bytes(compact)
    {:ok, compact}
  end

  defp wrap_recipient(alg, cek, h, recipient, deadline) do
    wrap =
      case recipient do
        %PublicKey{} = key ->
          public!(key, alg)
          {:rsa, n, e} = key.material
          KeyManagement.wrap(alg, cek, h, {:rsa, {:RSAPublicKey, n, e}})

        %KeyHandle{} = handle ->
          ensure(
            alg in ~w(A128KW A256KW) and handle.algorithm == {:jwe, alg},
            :algorithm_mismatch,
            :key
          )

          remaining = deadline - System.monotonic_time(:millisecond)
          ensure(remaining > 0, :deadline_exceeded, :crypto)

          case Custody.wrap(handle, cek, timeout: remaining) do
            {:ok, %{encrypted_key: ek, params: params}} when params == %{} ->
              {:ok, %{encrypted_key: ek, header: %{}}}

            {:error, %{reason: :deadline_exceeded}} ->
              fail(:deadline_exceeded, :crypto)

            _ ->
              fail(:signer_failed, :crypto)
          end

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

    {ek, additions}
  end

  @doc """
  Authenticate and decrypt a compact JWE under an explicit policy (RFC 7516).

  Protected bytes remain verbatim AEAD associated data. Sensitive range workers
  withhold plaintext until full authentication; the coordinator handles only control data.
  Caller death cancels work. No key operation runs through a resolver closure.

  ## Parameters

    * `compact` - at most 1,048,576 bytes, exactly five canonical unpadded
      Base64url segments. JSON serializations reject. Protected JSON is at most
      16,384 bytes (21,846 encoded), depth four, with at most 64 entries per
      object/array, bounded integers, no floats and no duplicate members.
      The content IV is 12 bytes and tag 16 bytes; ciphertext is bounded by
      `:max_plaintext`.
    * `policy` - exactly `:algorithms`, `:encryption`, `:max_plaintext`,
      `:timeout`, `:resolve_timeout`, `:unwrap_timeout`, `:key_resolver`,
      and `:protected`, with no defaults:
      * `:algorithms` - nonempty unique selection of RSA-OAEP, RSA-OAEP-256,
        A128KW, A256KW, A128GCMKW, A256GCMKW, dir, ECDH-ES,
        ECDH-ES+A128KW, ECDH-ES+A256KW.
      * `:encryption` - nonempty unique selection of A128GCM and A256GCM.
      * `:max_plaintext` - 1–1,048,576 bytes.
      * `:timeout`, `:resolve_timeout`, `:unwrap_timeout` - required integer
        milliseconds 1–300,000; resolve_timeout + unwrap_timeout < timeout.
        Thus timeout is at least 3 ms. From call start t0, R is
        t0 + resolve_timeout, D is t0 + timeout, and U is actual resolution
        completion + unwrap_timeout. Size the reserved remainder for content
        authentication at `:max_plaintext`.
      * `:protected` - exactly `%{expected: map, permitted: names}`. Expected
        values use exact decoded JSON equality; absent and different values both
        give `:protected_mismatch`. The map has at most 64 string keys and
        serializes to at most 16,384 bytes. Permitted names are at most 64 unique
        UTF-8 strings, each at most 16,384 bytes. Overlap, or naming any of alg/enc/iv/tag/epk/apu/apv, is
        `:invalid_policy`. An empty expected map is valid; the consumer chooses
        its completeness. Members must be read for the selected algorithm, in
        expected, or permitted; others give `:unexpected_member`.
      * `:key_resolver` - arity one, receiving `%{algorithm: alg, encryption: enc,
        header: decoded_header}`; returns `:error` or exactly
        `{:ok, %{algorithm: same_alg, key: custody_handle}}`. The handle binds
        `{:jwe, alg}` and grants `:unwrap`; mismatched or unavailable handles take
        the uniform key-management failure path. An `unwrap:` entry is refused.

  Admission proceeds in order: compact/header refusals; algorithm allowlists;
  content structure and public wrap/agreement params; member set; expectations;
  resolution. GCMKW iv/tag are decoded and checked before width failures take
  effect. ECDH public epk/party checks precede resolution; held-key checks stay
  in custody. Encrypted-key width is recorded, never rejected early: RSA permits
  256–1,024 bytes (custody checks the modulus); KW permits 24/40 bytes for
  128/256-bit content keys; GCMKW permits the CEK width; dir/direct ECDH require
  empty bytes. A width-failed token still receives member/expectation checks,
  then bypasses the resolver, unwrap, and every RFC 3394 round.

  A fallback CEK is drawn before key management on every path. Only a width-valid
  accepted sink delivery sets the one success flag. Every other key-management
  outcome uses the prepared fallback and runs AEAD, succeeding only if both the
  success flag and tag validation hold. The content-authentication event is
  recorded once when AEAD returns and emitted by the caller after teardown, with only
  `outcome: :ok | :failed`. Width is public and its bypass reveals no key fact.

  Admission unfinished at R returns `:deadline_exceeded`/`:input`; a resolver
  unfinished at R returns `:key_resolver_failed`/`:key`. Unwrap unfinished at U
  still authenticates with the fallback and returns `:decryption_failed`/`:crypto`.
  Content authentication unfinished at D returns `:deadline_exceeded`/`:crypto`.
  F = D + 100 ms. Teardown has B(n) = 20 ms + 15 microseconds per item;
  the caller stamps its wait-end by F + B(n), before cleanup and telemetry handlers.
  Single open uses n = 1 once cardinality is accepted. A suspended guard cannot extend the caller's wait.

  The policy excluding `protected.expected` is bounded to 4,096 words, including
  closure environments. Each expectation is bounded to 4,096 words and a total
  of 16,384 binary bytes, before UTF-8 validation or serialization. Exceeding any
  of these bounds, or the permitted-name byte bound, is `:invalid_policy`.
  Resolvers with a large keyring capture a registered name, ETS table or
  `persistent_term` key. Returned handles have the same 4,096-word and
  16,384-binary-byte bounds, including their closure environments; oversized
  answers are `:key_resolver_failed`. Optional `content: :object` decodes only
  authenticated plaintext and also retains its bytes in the result.

  All headers read before authentication are untrusted: even a forged header
  matching expectations can reach resolution and custody. Resolvers must have no
  authorization, replay-consumption, or other trusted side effects. Expected
  values are public context; the mismatch reason never identifies a member.
  Normalize this predicate at a boundary that considers it sensitive. Successful
  decryption establishes recipient integrity only.

  ## Returns

    * `{:ok, %RequestSeal.JOSE.JWE.Result{}}` - carries `algorithm`, `encryption`,
      decoded `header`, received `protected` segment, and `plaintext`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - reasons this function can return:
      `:invalid_policy`, `:invalid_serialization`, `:unsupported_serialization`,
      `:limit` (including ciphertext above `:max_plaintext`), `:invalid_base64`,
      `:invalid_header`, `:duplicate_member`, `:unsupported_critical_header`,
      `:compression_unsupported`, `:unsupported_header`, `:algorithm_not_permitted`
      (`alg` or `enc` outside the policy), `:invalid_iv`, `:invalid_tag`,
      `:unexpected_member`, `:protected_mismatch` (input layer),
      `:unknown_key` (resolver returned `:error`), `:algorithm_mismatch` (resolver
      returned another algorithm), `:key_resolver_failed` (resolver exception or
      invalid entry), `:entropy_failure`, `:decryption_failed` (wrong encrypted-key
      width, unwrap failure, or authentication failure), and `:deadline_exceeded`
      (the only retryable reason). Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

  This round trip uses real AES-KW custody and authenticated encryption:

      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jwe, "A256KW"}, {:aes, :crypto.strong_rand_bytes(32)})
      iex> {:ok, token} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", handle)
      iex> policy = %{algorithms: ["A256KW"], encryption: ["A256GCM"], max_plaintext: 1024, timeout: 5000, resolve_timeout: 1000, unwrap_timeout: 1000, protected: %{expected: %{}, permitted: []}, key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: handle}} end}
      iex> {:ok, result} = RequestSeal.JOSE.JWE.decrypt(token, policy)
      iex> result.plaintext
      "payload"
      iex> RequestSeal.Custody.release(handle)
      :ok
  """
  @spec decrypt(binary(), map()) :: {:ok, Result.t()} | {:error, JOSE.Error.t()}
  def decrypt(compact, policy) do
    JOSE.JWE.Open.open(compact, policy, :single)
  end

  @doc """
  Authenticate a bounded batch of compact JWEs, returning positional results.

  Each item has exactly `:token` (compact bytes) and `:expected` (public protected
  context). The policy has exactly `:algorithms`, `:encryption`, `:max_plaintext`,
  `:max_tokens` (1–10,000), `:max_total_input` and `:max_total_plaintext`
  (1–67,108,864 bytes each), `:timeout`, `:resolve_timeout`, `:unwrap_timeout`,
  `:key_resolver`, and `:protected`, which contains only `:permitted`.
  Algorithm, ciphertext, expectation and permitted-name bounds are `decrypt/2`'s.
  Total input includes token bytes and serialized expectations; total plaintext
  is the sum of ciphertext widths. All three aggregate limits precede key work.

  With call start t0, admission/resolution ends at R = t0 + resolve_timeout;
  each group's unwrap ends at U = resolution_end + unwrap_timeout; all work ends
  at D = t0 + timeout. Budgets are required integers 1–300,000 ms and their sum
  must be strictly below timeout. F = D + 100 ms; the caller stamps wait-end
  by F + B(n), where B(n) = 20 ms + 15 microseconds per item. Admission at R is `:deadline_exceeded`/`:input`; resolution at R
  is `:key_resolver_failed`/`:key`; unwrap at U still authenticates under a
  prepared random CEK and is `:decryption_failed`/`:crypto`; unfinished AEAD at D
  is `:deadline_exceeded`/`:crypto`.

  A guard creates an heir registry and a coordinator. A sensitive preflight
  worker validates all aggregate limits before at most min(n, 32, online
  schedulers) sensitive range workers admit contiguous ranges. Each accepted
  width-valid item starts a resolver immediately. Grouping uses a digest plus
  full handle equality, after the batch-wide resolution barrier and every
  resolver's end notice. Each group makes one custody call. Range-owned aliases
  preserve accepted deliveries and discard late ones. Width failures authenticate
  without waiting for resolvers. Only fully authenticated plaintext reaches the
  caller, which withholds the public result until finalization.

  Caller death or F makes the guard kill the coordinator before sweeping its
  registry. Caller-code children transfer private heir notices and have no
  reason-bearing library links or monitors while executing callbacks. Each child
  checks caller ownership and its deadline immediately before its callback.
  There are at most n + 35 library-owned processes alive, 2n + 35 created over
  the call, n + 3 simultaneous ETS tables, and one two-cell atomics array. Single
  open creates six processes and five tables over its lifetime. Caller-created
  callback descendants remain the callback's responsibility.

  The policy and expectation bounds, permitted-name bound and returned-handle
  bound are `decrypt/2`'s. An oversized expectation is positional `:invalid_policy`;
  an oversized policy or name is outer `:invalid_policy`.

  Returns `{:ok, results}` (including `{:ok, []}`), each result being `decrypt/2`'s
  success or error. Item shape errors are `:invalid_serialization`; invalid
  expectations are `:invalid_policy`. All other item reasons are exactly
  `decrypt/2`'s: `:unsupported_serialization`, `:limit`, `:invalid_base64`,
  `:invalid_header`, `:duplicate_member`, `:unsupported_critical_header`,
  `:compression_unsupported`, `:unsupported_header`, `:algorithm_not_permitted`,
  `:invalid_iv`, `:invalid_tag`, `:unexpected_member`, `:protected_mismatch`,
  `:unknown_key`, `:algorithm_mismatch`, `:key_resolver_failed`, `:entropy_failure`,
  `:decryption_failed`, and `:deadline_exceeded`.
  Outer errors (no results) are `:invalid_policy`, `:invalid_serialization` for
  a nonproper list, `:limit` for aggregate bounds, or `:deadline_exceeded` if
  D passes before cardinality is accepted or the caller reaches F + B(n).
  `:internal_failure` reports a broken library
  lifecycle or a preflight overrun. Only `:deadline_exceeded` is retryable.

  The content-authentication event has only `outcome: :ok | :failed`, once after
  each real AEAD returns, emitted after teardown. Batch telemetry contains only `count`, `groups`,
  `failed`, and `deadline_exceeded` measurements. Custody unwrap carries only
  `duration` and `items`. Resolvers read unauthenticated data and must have no
  authorization, replay-consumption, or other trusted side effects; expectations
  are public context and are the consumer's responsibility. Normalize expectation
  refusals at a boundary that considers the predicate sensitive.
  """
  @spec decrypt_many([%{token: binary(), expected: map()}], map()) ::
          {:ok, [{:ok, Result.t()} | {:error, JOSE.Error.t()}]} | {:error, JOSE.Error.t()}
  def decrypt_many(items, policy) do
    JOSE.JWE.Open.open(items, policy, :batch)
  end

  defp encrypted_key!(alg, ek, h) when alg in ~w(A128KW A256KW ECDH-ES+A128KW ECDH-ES+A256KW),
    do: ensure(byte_size(ek) == width(h["enc"]) + 8, :decryption_failed, :crypto)

  defp encrypted_key!(alg, ek, _) when alg in ["dir", "ECDH-ES"],
    do: ensure(ek == "", :decryption_failed, :crypto)

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
