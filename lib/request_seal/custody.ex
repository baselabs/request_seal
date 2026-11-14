defmodule RequestSeal.Custody do
  @moduledoc """
  Caller-owned signing, secret verification, key wrapping/unwrapping, and public metadata.

  Each callback runs in a fresh runner, never linked to the caller. A monitored
  middle process traps exits, monitors the caller before linking the runner, and
  terminates the runner when the caller dies, even
  when a callback is blocked. Both processes set `Process.flag(:sensitive, true)`
  before any custody work, for every operation. Runner exceptions are reduced to
  `:custodian_failure` without logging exception text.
  Deadline expiry kills the runner and drains its
  uniquely tagged result. Loading the library starts no process, store, or
  background work. Local handle construction explicitly starts its key holder.

  Each operation validates its options, the handle, and its inputs before any
  custody work; the function documentation lists the bounds and the error
  reasons each one can return.
  Signing returns bytes; verification establishes mathematical validity only.
  Neither establishes identity attribution, authorization, or replay protection.

  Custodians are trusted code: they must return only public keys and nonsecret
  identities, never log secrets, and must propagate the context deadline and
  cancellation to any additional work they own. Killing the worker closes sockets
  it owns; it cannot revoke work already accepted by an external peer.
  A custodian signing with `RequestSeal.Crypto.sign/4` or verifying with
  `RequestSeal.Crypto.verify/5` must pass
  `max_bytes: RequestSeal.Crypto.max_bytes_ceiling()` because custody has already
  enforced the caller's bound, which `RequestSeal.Custody.Context` does not carry.
  """
  alias RequestSeal.{KeyHandle, KeyIdentity, PublicKey}
  alias RequestSeal.Custody.{Context, Error, Sink, Support}
  import Support, only: [fail: 1, ensure: 2]

  @type key_algorithm :: {:jwe, binary()}
  @type algorithm ::
          RequestSeal.Crypto.algorithm()
          | key_algorithm()
          | {:derive, binary()}
          | {atom(), term()}
  @type params ::
          %{}
          | %{iv: <<_::96>>, tag: <<_::128>>}
          | %{
              epk: PublicKey.t(),
              apu: binary(),
              apv: binary(),
              algorithm_id: binary(),
              key_bits: 128 | 256
            }
  @type item :: {non_neg_integer(), binary(), params(), 128 | 256}

  @callback sign(term(), algorithm(), binary(), Context.t()) ::
              {:ok, binary()} | {:error, Error.reason()}
  @callback verify(term(), algorithm(), binary(), binary(), Context.t()) ::
              :ok | {:error, Error.reason()}
  @callback public_key(term()) :: {:ok, PublicKey.t()} | {:error, Error.reason()}
  @callback identity(term()) :: KeyIdentity.t() | {:error, Error.reason()}
  @callback unwrap(term(), key_algorithm(), [item()], Sink.t(), Context.t()) ::
              :ok | {:error, Error.reason()}
  @callback wrap(term(), key_algorithm(), binary(), Context.t()) ::
              {:ok, %{encrypted_key: binary(), params: params()}} | {:error, Error.reason()}
  @callback release(term(), Context.t()) :: :ok | {:error, Error.reason()}
  @optional_callbacks verify: 5, unwrap: 5, wrap: 4, release: 2

  @doc """
  Unwrap a bounded list with the handle's exact key-management algorithm.

  `items` contains 1–10,000 `{encrypted_key, params, content_bits}` tuples in
  input order. Each encrypted key is a binary of 0–1,024 bytes, and content bits
  are 128 or 256. Params are exactly `%{}` for RSA-OAEP, AES-KW, and `dir`, or
  `%{iv: twelve_bytes, tag: sixteen_bytes}` for AES-GCMKW, or
  `%{epk: public_key, apu: bytes, apv: bytes, algorithm_id: id, key_bits: bits}`
  for ECDH-ES. Params are decoded before custody; no header is parsed here.
  The handle must grant
  `:unwrap`. Only `:timeout` is accepted: 1–300,000 ms, default 5,000; unknown,
  duplicate, and invalid options reject before the handle and items.

  The owner accepts each delivery strictly before one absolute monotonic
  deadline. A settled position never changes. Expiry revokes the alias, drains
  tagged envelopes, then times out undelivered positions. A call summary settles
  only positions still undelivered; an accepted prefix survives later failure.
  CEKs travel straight from the holder to the owner, bypassing the runner.

  Returns `{:ok, results}` in input order, with each result `{:ok, cek}`,
  `{:error, :decryption_failed}`, or `{:error, :deadline_exceeded}`. Input and
  handle validation returns `{:error, Custody.Error.t()}` with
  `:invalid_options`, `:invalid_handle`, `:unsupported_algorithm`,
  `:unsupported_operation`, or `:invalid_data`. Callback failures settle
  undelivered items without exposing diagnostics. Direct callers own the
  returned CEKs; authenticate content before exposing plaintext.

      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jwe, "A256KW"}, {:aes, <<0::256>>})
      iex> {:ok, wrapped} = RequestSeal.Custody.wrap(handle, <<0::128>>)
      iex> RequestSeal.Custody.unwrap(handle, [{wrapped.encrypted_key, %{}, 128}])
      {:ok, [{:ok, <<0::128>>}]}
      iex> RequestSeal.Custody.release(handle)
      :ok
  """
  @spec unwrap(KeyHandle.t(), [{binary(), params(), 128 | 256}], keyword()) ::
          {:ok, [{:ok, binary()} | {:error, :decryption_failed | :deadline_exceeded}]}
          | {:error, Error.t()}
  def unwrap(handle, items, opts \\ []) do
    started = System.monotonic_time()

    try do
      Support.safe(
        fn ->
          timeout = Support.timeout(opts)

          context = %Context{
            owner: self(),
            deadline: System.monotonic_time(:millisecond) + timeout
          }

          handle!(handle)
          ensure(:unwrap in handle.capabilities, :unsupported_operation)
          indexed = items!(handle.algorithm, items)
          sink = Sink.new(indexed, context)
          results = Sink.collect(sink, fn -> unwrap(handle, indexed, sink, context) end)

          {:ok,
           Enum.map(results, fn
             {:ok, cek} -> {:ok, cek}
             :error -> {:error, :decryption_failed}
             :timeout -> {:error, :deadline_exceeded}
           end)}
        end,
        :custodian_failure
      )
    after
      RequestSeal.Telemetry.emit(
        [:request_seal, :custody, :unwrap],
        System.monotonic_time() - started,
        %{}
      )
    end
  end

  # Internal delivery form: the caller supplies its own sink. JWE's sensitive
  # worker owns that sink and collects it; the runner returns only the summary.
  @doc false
  @spec unwrap(KeyHandle.t(), [item()], Sink.t(), Context.t()) :: {:ok, :ok} | {:error, term()}
  def unwrap(handle, items, sink, context) do
    run(context, fn ->
      handle!(handle)
      ensure(:unwrap in handle.capabilities, :unsupported_operation)

      normalize(
        :unwrap,
        handle.custodian.unwrap(handle.ref, handle.algorithm, items, sink, context)
      )
    end)
  end

  defp items!(algorithm, items) do
    ensure(is_list(items) and length(items) in 1..10_000, :invalid_data)
    {:jwe, alg} = algorithm

    Enum.with_index(items, fn
      {encrypted, params, bits}, index
      when is_binary(encrypted) and byte_size(encrypted) <= 1024 and bits in [128, 256] ->
        ensure(
          match?(
            :ok,
            RequestSeal.JOSE.Support.safe(fn ->
              RequestSeal.JOSE.KeyManagement.validate_params!(alg, params)
            end)
          ),
          :invalid_data
        )

        {index, encrypted, params, bits}

      _, _ ->
        fail(:invalid_data)
    end)
  end

  @doc """
  Wrap a 128- or 256-bit CEK with an AES-KW handle granting `:wrap`.

  The CEK is a binary of exactly 16 or 32 bytes. Options are exactly `:timeout`,
  1–300,000 ms (default 5,000). Returns
  `{:ok, %{encrypted_key: bytes, params: %{}}}`; validation, capability,
  deadline, or custodian failure returns a bounded `Custody.Error`. GCMKW and
  `dir` handles cannot wrap. Telemetry contains only `outcome: :ok | :failed`.
  """
  @spec wrap(KeyHandle.t(), binary(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def wrap(handle, cek, opts \\ []) do
    started = System.monotonic_time()

    result =
      operation(handle, :wrap, opts, fn _ ->
        ensure(is_binary(cek) and byte_size(cek) in [16, 32], :invalid_data)
        [cek]
      end)

    outcome = if match?({:ok, _}, result), do: :ok, else: :failed

    RequestSeal.Telemetry.emit(
      [:request_seal, :custody, :wrap],
      System.monotonic_time() - started,
      %{outcome: outcome}
    )

    result
  end

  @doc """
  Release a handle through its custodian under the default 5,000 ms deadline.

  Idempotent: `:ok` confirms the key is destroyed or never existed. A timeout
  or custodian error does not confirm destruction; the caller may retry.
  A custodian without `release/2` returns `:unsupported_operation`. Invalid
  handles and callback failures return bounded `Custody.Error` values.
  """
  @spec release(KeyHandle.t()) :: :ok | {:error, Error.t()}
  def release(handle), do: operation(handle, :release, [], fn _ -> [] end)

  @doc """
  Sign exact bounded bytes with the algorithm bound to a handle.

  The custodian's signing callback runs in a fresh sensitive runner under the
  operation deadline, as described in the module documentation.

  ## Parameters

    * `handle` - a `t:RequestSeal.KeyHandle.t/0` with the `:sign` capability.
    * `bytes` - the exact binary to sign, at most `:max_bytes` bytes.
    * `opts` - keyword list; see Options.

  ## Options

    * `:timeout` - operation deadline in milliseconds, integer 1–300,000
      (`:infinity` is refused). Default `5_000`.
    * `:max_bytes` - largest accepted `bytes` size, integer
      1–16,777,216 (`RequestSeal.Crypto.max_bytes_ceiling/0`). Default `1_048_576`.

  Unknown, duplicate, out-of-range, or non-integer options return
  `:invalid_options` before the handle is checked.

  ## Returns

    * `{:ok, signature}` - signature bytes, 1–16,384 bytes long.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_options`, `:invalid_handle`, `:unsupported_algorithm` (the handle
      names an unknown algorithm), `:unsupported_operation` (the handle lacks
      `:sign`), `:invalid_data` (`bytes` is not a binary or exceeds `:max_bytes`),
      `:deadline_exceeded`, `:key_not_found` (local holder released or stopped, or
      agent key removed), `:invalid_signing_output` (the custodian returned a
      non-binary, empty, or over-16,384-byte signature), and `:custodian_failure`.
      Custodian reasons pass through: both built-in custodians return
      `:key_mismatch` when the handle's `algorithm` no longer matches the
      custodian's bound algorithm, and `RequestSeal.Custody.SSHAgent` also returns
      `:custodian_unavailable`, `:custodian_rejected`, and `:custodian_protocol`.
      A custodian reason outside the `RequestSeal.Custody.Error` list becomes
      `:custodian_failure`. Meanings: `RequestSeal.Custody.Error`.

  ## Examples

  Opt into a larger input bound on each signing and verification call. This
  local example uses actual Ed25519 cryptography under RFC 8032; it is not an
  external conformance vector.

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> bytes = :binary.copy(<<0>>, 1_235_403)
      iex> {:ok, signature} = RequestSeal.Custody.sign(handle, bytes, max_bytes: 2_097_152)
      iex> RequestSeal.Custody.verify(handle, bytes, signature, max_bytes: 2_097_152)
      :ok
      iex> RequestSeal.Custody.sign(handle, bytes)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_data, retryable: false}}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec sign(KeyHandle.t(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(handle, bytes, opts \\ []) do
    operation(
      handle,
      :sign,
      opts,
      fn max ->
        data!(bytes, max)
        [bytes]
      end,
      [:timeout, :max_bytes]
    )
  end

  @doc """
  Verify exact bytes through secret custody or the custodian's public key.

  A custodian that implements the optional `c:verify/5` callback verifies inside
  its own boundary (HMAC custody uses this path). Otherwise the custodian's
  public key is resolved and the signature is checked with
  `RequestSeal.Crypto.verify/5`. `:ok` establishes mathematical validity only.

  ## Parameters

    * `handle` - a `t:RequestSeal.KeyHandle.t/0` with the `:verify` capability.
    * `bytes` - the exact signed binary, at most `:max_bytes` bytes.
    * `signature` - the signature binary, at most 16,384 bytes.
    * `opts` - keyword list; see Options.

  ## Options

    * `:timeout` - operation deadline in milliseconds, integer 1–300,000
      (`:infinity` is refused). Default `5_000`.
    * `:max_bytes` - largest accepted `bytes` size, integer
      1–16,777,216 (`RequestSeal.Crypto.max_bytes_ceiling/0`). Default `1_048_576`.

  Unknown, duplicate, out-of-range, or non-integer options return
  `:invalid_options` before handle or capability validation.

  ## Returns

    * `:ok` - the signature is mathematically valid for `bytes`.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_options`, `:invalid_handle`, `:unsupported_algorithm` (the handle
      names an unknown algorithm), `:unsupported_operation` (the handle lacks
      `:verify`), `:invalid_data` (`bytes` is not a binary or exceeds
      `:max_bytes`), `:invalid_signature` (`signature` is not a binary, or it does
      not verify), `:limit` (`signature` exceeds 16,384 bytes),
      `:deadline_exceeded`, `:key_not_found` (local holder released or stopped),
      and `:custodian_failure`. Key-binding reasons pass through from the
      custodian or from `RequestSeal.Crypto.verify/5`: `:key_mismatch` (the key
      or the handle's `algorithm` does not fit the bound algorithm),
      `:invalid_key`, and `:no_public_key` (a custodian without `c:verify/5` that
      has no public key). A custodian reason outside the
      `RequestSeal.Custody.Error` list becomes `:custodian_failure`. Meanings:
      `RequestSeal.Custody.Error`.

  ## Examples

  A telemetry batch signed with an HMAC handle verifies inside custody; a
  changed batch does not.

      iex> {:ok, handle} = RequestSeal.Custody.Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)})
      iex> batch = ~s({"sensor":"line-4","readings":[21.4,21.6]})
      iex> {:ok, tag} = RequestSeal.Custody.sign(handle, batch)
      iex> RequestSeal.Custody.verify(handle, batch, tag)
      :ok
      iex> RequestSeal.Custody.verify(handle, batch <> " ", tag)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_signature, retryable: false}}
      iex> RequestSeal.Custody.verify(handle, batch, tag, timeout: 0)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_options, retryable: false}}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec verify(KeyHandle.t(), binary(), binary(), keyword()) :: :ok | {:error, Error.t()}
  def verify(handle, bytes, signature, opts \\ []) do
    operation(
      handle,
      :verify,
      opts,
      fn max ->
        data!(bytes, max)
        ensure(is_binary(signature), :invalid_signature)
        ensure(byte_size(signature) <= 16_384, :limit)
        [bytes, signature]
      end,
      [:timeout, :max_bytes]
    )
  end

  @doc """
  Resolve validated public-only material; symmetric keys return `:no_public_key`.

  Resolution runs under the default 5,000 ms deadline and takes no options. The
  custodian's returned key is revalidated before it is returned.

  ## Parameters

    * `handle` - any valid `t:RequestSeal.KeyHandle.t/0`, including an unwrap-only
      handle.

  ## Returns

    * `{:ok, %RequestSeal.PublicKey{}}` - validated public material with any
      algorithm, use, and operation restrictions the key carries.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_handle`, `:unsupported_algorithm` (the handle names an unknown
      algorithm), `:no_public_key` (symmetric custody), `:key_not_found` (local holder
      released or stopped), `:deadline_exceeded`, `:invalid_key` (the custodian
      returned public material that fails validation), and `:custodian_failure`.
      A custodian reason outside the `RequestSeal.Custody.Error` list becomes
      `:custodian_failure`. Meanings: `RequestSeal.Custody.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, %RequestSeal.PublicKey{material: {:ed25519, public}}} = RequestSeal.Custody.public_key(handle)
      iex> byte_size(public)
      32
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
      iex> RequestSeal.Custody.public_key(handle)
      {:error, %RequestSeal.Custody.Error{reason: :key_not_found, retryable: false}}

      iex> {:ok, handle} = RequestSeal.Custody.Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)})
      iex> RequestSeal.Custody.public_key(handle)
      {:error, %RequestSeal.Custody.Error{reason: :no_public_key, retryable: false}}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec public_key(KeyHandle.t()) :: {:ok, PublicKey.t()} | {:error, Error.t()}
  def public_key(handle), do: operation(handle, :public_key, [], fn _max -> [] end)

  @doc """
  Resolve internal trusted equivalence; keep the value out of general results.

  Resolution runs under the default 5,000 ms deadline and takes no options. The
  result is a `RequestSeal.KeyIdentity`; compare identities only with
  `RequestSeal.KeyIdentity.same?/2`, and keep them out of general results, logs,
  and telemetry.

  ## Parameters

    * `handle` - any valid `t:RequestSeal.KeyHandle.t/0`.

  ## Returns

    * `{:ok, %RequestSeal.KeyIdentity{}}` - kind `:public` (validated public
      components, with `:rsa_pss` normalized to `:rsa`), `:symmetric` (an opaque
      custodian-supplied binary of 1–256 bytes), or `:unknown` (value `nil`).
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_handle`, `:unsupported_algorithm` (the handle names an unknown
      algorithm), `:key_not_found` (local holder released or stopped),
      `:deadline_exceeded`, `:invalid_key` (a public identity fails validation),
      and `:custodian_failure` (including any other identity shape). Meanings:
      `RequestSeal.Custody.Error`.

  ## Examples

  Two handles constructed from the same build-signing seed have the same public
  identity.

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, first} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, second} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
      iex> {:ok, a} = RequestSeal.Custody.identity(first)
      iex> {:ok, b} = RequestSeal.Custody.identity(second)
      iex> RequestSeal.KeyIdentity.same?(a, b)
      true
      iex> RequestSeal.Custody.Local.release(first)
      :ok
      iex> RequestSeal.Custody.Local.release(second)
      :ok
      iex> RequestSeal.Custody.identity(first)
      {:error, %RequestSeal.Custody.Error{reason: :key_not_found, retryable: false}}
  """
  @spec identity(KeyHandle.t()) :: {:ok, KeyIdentity.t()} | {:error, Error.t()}
  def identity(handle), do: operation(handle, :identity, [], fn _max -> [] end)

  defp operation(handle, op, opts, args, allowed \\ [:timeout]) do
    Support.safe(
      fn ->
        timeout = Support.timeout(opts, allowed)
        max = Support.max_bytes(opts)
        handle!(handle)

        ensure(
          op not in [:sign, :verify, :wrap] or op in handle.capabilities,
          :unsupported_operation
        )

        ensure(
          op != :release or function_exported?(handle.custodian, :release, 2),
          :unsupported_operation
        )

        args = args.(max)
        context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}

        case run(context, fn -> invoke(handle, op, args, context) end) do
          {:ok, :ok} when op in [:verify, :release] -> :ok
          result -> result
        end
      end,
      :custodian_failure
    )
  end

  defp handle!(%KeyHandle{} = handle) do
    ensure(
      map_size(handle) == 5 and is_atom(handle.custodian) and is_function(handle.ref, 0),
      :invalid_handle
    )

    ensure(
      is_list(handle.capabilities) and handle.capabilities != [] and
        Enum.all?(handle.capabilities, &(&1 in [:sign, :verify, :wrap, :unwrap])) and
        Enum.uniq(handle.capabilities) == handle.capabilities,
      :invalid_handle
    )

    ensure(
      Code.ensure_loaded?(handle.custodian) and function_exported?(handle.custodian, :sign, 4) and
        function_exported?(handle.custodian, :public_key, 1) and
        function_exported?(handle.custodian, :identity, 1),
      :invalid_handle
    )

    case handle.algorithm do
      {:jwe, alg}
      when alg in ~w(RSA-OAEP RSA-OAEP-256 A128GCMKW A256GCMKW dir A128KW A256KW ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW) ->
        allowed = if alg in ~w(A128KW A256KW), do: [:wrap, :unwrap], else: [:unwrap]
        ensure(Enum.all?(handle.capabilities, &(&1 in allowed)), :invalid_handle)

        for {capability, arity} <- [unwrap: 5, wrap: 4], capability in handle.capabilities do
          ensure(function_exported?(handle.custodian, capability, arity), :invalid_handle)
        end

      _ ->
        ensure(not Enum.any?(handle.capabilities, &(&1 in [:wrap, :unwrap])), :invalid_handle)
        RequestSeal.Crypto.Algorithm.resolve(handle.algorithm)
    end
  end

  defp handle!(_), do: fail(:invalid_handle)
  defp data!(bytes, max), do: ensure(is_binary(bytes) and byte_size(bytes) <= max, :invalid_data)

  defp invoke(handle, :verify, [bytes, signature], context) do
    result =
      if function_exported?(handle.custodian, :verify, 5) do
        handle.custodian.verify(handle.ref, handle.algorithm, bytes, signature, context)
      else
        public = handle.custodian.public_key(handle.ref) |> Support.unwrap()

        RequestSeal.Crypto.verify(handle.algorithm, bytes, signature, public,
          max_bytes: RequestSeal.Crypto.max_bytes_ceiling()
        )
      end

    normalize(:verify, result)
  end

  defp invoke(handle, op, args, context) when op in [:sign, :wrap],
    do:
      normalize(
        op,
        apply(handle.custodian, op, [handle.ref, handle.algorithm | args] ++ [context])
      )

  defp invoke(handle, :release, [], context),
    do: normalize(:release, handle.custodian.release(handle.ref, context))

  defp invoke(handle, op, [], _), do: normalize(op, apply(handle.custodian, op, [handle.ref]))

  defp normalize(_, {:error, %{reason: reason}}), do: {:error, Error.new(reason)}
  defp normalize(_, {:error, reason}) when is_atom(reason), do: {:error, Error.new(reason)}
  defp normalize(:verify, :ok), do: :ok

  defp normalize(:sign, {:ok, bytes}) when is_binary(bytes) and byte_size(bytes) in 1..16_384,
    do: {:ok, bytes}

  defp normalize(:sign, {:ok, _}), do: {:error, Error.new(:invalid_signing_output)}

  defp normalize(op, :ok) when op in [:unwrap, :release], do: :ok

  defp normalize(:wrap, {:ok, %{encrypted_key: bytes, params: params} = value})
       when map_size(value) == 2 and is_binary(bytes) and byte_size(bytes) in [24, 40] and
              params == %{},
       do: {:ok, value}

  defp normalize(:public_key, {:ok, %PublicKey{} = public}) do
    PublicKey.validate!(public)
    {:ok, public}
  end

  defp normalize(:identity, %KeyIdentity{kind: :public, value: value} = identity)
       when map_size(identity) == 3 do
    Support.unwrap(PublicKey.import(value, :raw))
    {:ok, %{identity | value: KeyIdentity.normalize(value)}}
  end

  defp normalize(:identity, %KeyIdentity{kind: :symmetric, value: value} = identity)
       when map_size(identity) == 3 and is_binary(value) and byte_size(value) in 1..256,
       do: {:ok, identity}

  defp normalize(:identity, %KeyIdentity{kind: :unknown, value: nil} = identity)
       when map_size(identity) == 3, do: {:ok, identity}

  defp normalize(_, _), do: {:error, Error.new(:custodian_failure)}

  @doc """
  Run a zero-arity callback in a sensitive process under an absolute deadline.

  An expired deadline returns immediately without invoking the callback. The
  caller and `context.owner` are both monitored; either dying cancels the
  callback, including blocked callbacks that trap exits. Nested runs monitor
  their immediate caller as well as their context owner, so cancellation
  propagates through nested operations. An already-dead context owner prevents
  the callback from starting.

  The callback and its supervising middle process set sensitivity before work.
  Neither is linked to the caller. The runner is terminated and its exit awaited
  before the middle process sends a result; the caller awaits the middle process's
  exit before returning. Deadline expiry cancels the runner and awaits cleanup.
  Work inside a dirty NIF cannot be preempted: cancellation waits for the runner's
  exit, so a long native call can overshoot the deadline.
  Replies use a revocable process alias: queued replies are drained and later
  replies to that alias are discarded, without consuming unrelated caller messages.

  Callbacks are trusted code. They must propagate the deadline and cancellation
  to additional processes or external work they start. Cancellation cannot undo
  effects already accepted by a peer, prevent messages explicitly sent to a caller
  PID by callback code, or terminate arbitrary unlinked callback descendants.
  Use nested `run/2` calls for work requiring the same cancellation boundary.

  ## Parameters

    * `context` - a `RequestSeal.Custody.Context` with an integer `deadline` in
      monotonic milliseconds and an `owner` PID. Construct the deadline with
      `System.monotonic_time(:millisecond) + timeout`.
    * `callback` - a zero-arity function returning `:ok`, `{:ok, value}`, or
      `{:error, reason}`.

  ## Returns

    * `{:ok, value}` or `{:error, reason}` - the callback's own result, unchanged;
      `:ok` becomes `{:ok, :ok}`. Callback errors and successful values belong to
      the caller and are not redacted.
    * `{:error, %RequestSeal.Custody.Error{}}` - produced by `run/2` itself:
      * a custody or cryptographic validation failure thrown inside the callback
        keeps its bounded `RequestSeal.Custody.Error` reason;
      * `:custodian_failure` (`retryable: false`) for any other return,
        exception, unrecognized throw, exit, unexpected worker termination, or
        owner death, without retaining exception text;
      * `:deadline_exceeded` (`retryable: true`) when the deadline expires;
      * `:invalid_options` (`retryable: false`) for an invalid context or
        callback argument.

    Meanings: `RequestSeal.Custody.Error`.

  ## Examples

      iex> context = %RequestSeal.Custody.Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
      iex> RequestSeal.Custody.run(context, fn -> {:ok, :completed} end)
      {:ok, :completed}
      iex> RequestSeal.Custody.run(context, fn -> :ok end)
      {:ok, :ok}
      iex> RequestSeal.Custody.run(context, fn -> raise "crawler fetch failed" end)
      {:error, %RequestSeal.Custody.Error{reason: :custodian_failure, retryable: false}}
      iex> expired = %RequestSeal.Custody.Context{owner: self(), deadline: System.monotonic_time(:millisecond) - 1}
      iex> RequestSeal.Custody.run(expired, fn -> {:ok, :never_runs} end)
      {:error, %RequestSeal.Custody.Error{reason: :deadline_exceeded, retryable: true}}
      iex> RequestSeal.Custody.run(context, fn _ -> :ok end)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_options, retryable: false}}
  """
  @spec run(Context.t(), (-> :ok | {:ok, term()} | {:error, term()})) ::
          {:ok, term()} | {:error, term()}
  def run(%Context{deadline: deadline, owner: owner} = context, callback)
      when is_integer(deadline) and is_pid(owner) and is_function(callback, 0) do
    cond do
      Context.remaining(context) <= 0 -> {:error, Error.new(:deadline_exceeded)}
      owner_dead?(owner) -> {:error, Error.new(:custodian_failure)}
      true -> run_worker(context, callback)
    end
  end

  def run(_, _), do: {:error, Error.new(:invalid_options)}

  defp run_worker(context, callback) do
    caller = self()
    reply = :erlang.alias()

    {worker, monitor} =
      spawn_monitor(fn ->
        Process.flag(:sensitive, true)
        watch_owner(caller, reply, context, callback)
      end)

    try do
      receive_result(context, worker, monitor, reply)
    after
      :erlang.unalias(reply)
      flush(reply)
    end
  end

  defp receive_result(context, worker, monitor, reply) do
    receive do
      {^reply, result} ->
        await_worker(worker, monitor)

        if Context.remaining(context) > 0,
          do: result,
          else: {:error, Error.new(:deadline_exceeded)}

      {:DOWN, ^monitor, :process, ^worker, _} ->
        {:error, Error.new(:custodian_failure)}
    after
      context |> Context.remaining() |> max(0) |> min(4_294_967_295) ->
        if Context.remaining(context) > 0 do
          receive_result(context, worker, monitor, reply)
        else
          :erlang.unalias(reply)
          send(worker, {:cancel, reply})
          await_worker(worker, monitor)
          {:error, Error.new(:deadline_exceeded)}
        end
    end
  end

  defp await_worker(worker, monitor) do
    receive do
      {:DOWN, ^monitor, :process, ^worker, _} -> :ok
    end
  end

  defp watch_owner(caller, reply, context, callback) do
    Process.flag(:trap_exit, true)
    caller_ref = Process.monitor(caller)
    owner_ref = if context.owner == caller, do: caller_ref, else: Process.monitor(context.owner)
    middle = self()

    cond do
      Context.remaining(context) <= 0 ->
        send(reply, {reply, {:error, Error.new(:deadline_exceeded)}})

      owner_dead?(context.owner) ->
        send(reply, {reply, {:error, Error.new(:custodian_failure)}})

      true ->
        receive do
          {:DOWN, ^owner_ref, :process, _, _} ->
            send(reply, {reply, {:error, Error.new(:custodian_failure)}})

          {:DOWN, ^caller_ref, :process, ^caller, _} ->
            :ok
        after
          0 ->
            runner =
              spawn_link(fn ->
                Process.flag(:sensitive, true)
                result = Support.safe(callback, :custodian_failure) |> run_result()
                send(middle, {reply, result})
              end)

            watch_runner(caller, caller_ref, owner_ref, reply, context, runner)
        end
    end
  end

  defp owner_dead?(owner) when node(owner) == node(), do: not Process.alive?(owner)
  defp owner_dead?(_), do: false

  defp watch_runner(caller, caller_ref, owner_ref, reply, context, runner) do
    receive do
      {^reply, result} ->
        stop_runner(runner)
        send(reply, {reply, result})

      {:DOWN, ^caller_ref, :process, ^caller, _} ->
        stop_runner(runner)

      {:DOWN, ^owner_ref, :process, _, _} ->
        stop_runner(runner)
        send(reply, {reply, {:error, Error.new(:custodian_failure)}})

      {:cancel, ^reply} ->
        stop_runner(runner)

      {:EXIT, ^runner, _} ->
        :ok
    after
      context |> Context.remaining() |> max(0) |> min(4_294_967_295) ->
        if Context.remaining(context) > 0 do
          watch_runner(caller, caller_ref, owner_ref, reply, context, runner)
        else
          stop_runner(runner)
          send(reply, {reply, {:error, Error.new(:deadline_exceeded)}})
        end
    end
  end

  defp run_result(:ok), do: {:ok, :ok}
  defp run_result({tag, _} = result) when tag in [:ok, :error], do: result
  defp run_result(_), do: {:error, Error.new(:custodian_failure)}

  defp stop_runner(runner) do
    Process.exit(runner, :kill)

    receive do
      {:EXIT, ^runner, _} -> :ok
    end
  end

  defp flush(tag) do
    receive do
      {^tag, _} -> flush(tag)
    after
      0 -> :ok
    end
  end
end
