defmodule RequestSeal.Custody do
  @moduledoc """
  Caller-owned signing, secret verification, key unwrapping, and public metadata.

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
  alias RequestSeal.Custody.{Context, Error, Support}
  import Support, only: [ensure: 2]

  @type unwrap_algorithm :: {:jwe, binary()}
  @type algorithm :: RequestSeal.Crypto.algorithm() | unwrap_algorithm()

  @callback sign(term(), RequestSeal.Crypto.algorithm(), binary(), Context.t()) ::
              {:ok, binary()} | {:error, Error.reason()}
  @callback verify(term(), RequestSeal.Crypto.algorithm(), binary(), binary(), Context.t()) ::
              :ok | {:error, Error.reason()}
  @callback public_key(term()) :: {:ok, PublicKey.t()} | {:error, Error.reason()}
  @callback identity(term()) :: KeyIdentity.t() | {:error, Error.reason()}
  @callback unwrap(term(), unwrap_algorithm(), binary(), Context.t()) ::
              {:ok, binary()} | {:error, Error.reason()}
  @optional_callbacks verify: 5, unwrap: 4

  @doc """
  Unwrap a bounded RSA-OAEP encrypted key using the handle's exact algorithm.

  Only `{:jwe, "RSA-OAEP"}` and `{:jwe, "RSA-OAEP-256"}` handles with the `:unwrap`
  capability are accepted. The result is the unwrapped key bytes, never the
  private key. Callers must authenticate content before exposing plaintext;
  `RequestSeal.JOSE.JWE` performs that step with a random fallback CEK on unwrap
  failure.

  Unwrapped bytes pass from the sensitive local holder through the sensitive
  custody runner and middle process to the caller. On the JWE handle path that
  caller is JWE's sensitive worker, which authenticates content before returning
  plaintext. A direct `unwrap/3` caller receives the bytes and owns their protection.

  JWE deliberately maps a released or unavailable handle to the same error as a
  forged message. Operators should check `RequestSeal.Custody.public_key(handle)`
  at startup to distinguish custody availability from message rejection;
  `{:ok, public_key}` confirms public resolution, while `{:error, error}` exposes
  the custody failure. Deadline expiration remains a distinct JWE error.

  ## Parameters

    * `handle` - a `t:RequestSeal.KeyHandle.t/0` whose algorithm is
      `{:jwe, "RSA-OAEP"}` or `{:jwe, "RSA-OAEP-256"}` and whose capabilities
      are exactly `[:unwrap]`.
    * `encrypted_key` - the JWE encrypted key, a binary of 1–1,024 bytes. Inside
      the custodian it must also equal the RSA modulus width.
    * `opts` - keyword list; see Options.

  ## Options

    * `:timeout` - operation deadline in milliseconds, integer 1–300,000
      (`:infinity` is refused). Default `5_000`.

  `:max_bytes` is refused. Unknown, duplicate, out-of-range, or non-integer
  options return `:invalid_options` before the handle is checked.

  ## Returns

    * `{:ok, key_bytes}` - the unwrapped key, 1–1,024 bytes.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_options`, `:invalid_handle` (malformed handle, or an `:unwrap`
      capability on a handle that is not an RSA-OAEP handle),
      `:unsupported_algorithm` (a non-JWE handle naming an unknown algorithm),
      `:unsupported_operation` (the handle lacks `:unwrap`), `:invalid_data`
      (`encrypted_key` is not a binary of 1–1,024 bytes), `:decryption_failed`
      (OAEP failure, modulus-width mismatch, or an empty plaintext),
      `:deadline_exceeded`, `:key_not_found` (holder released or stopped), and
      `:custodian_failure`. `RequestSeal.Custody.Local` also returns
      `:key_mismatch` when the handle's `algorithm` no longer matches its holder.
      A custodian reason outside the `RequestSeal.Custody.Error` list becomes
      `:custodian_failure`. Meanings: `RequestSeal.Custody.Error`.

  ## Examples

  A document recipient key unwraps a content-encryption key that was wrapped to
  its public key; a forged encrypted key is refused.

      iex> private = :public_key.generate_key({:rsa, 2048, 65_537})
      iex> {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} = private
      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jwe, "RSA-OAEP-256"}, {:rsa, private})
      iex> cek = :crypto.strong_rand_bytes(32)
      iex> {:ok, %{encrypted_key: encrypted_key}} =
      ...>   RequestSeal.JOSE.KeyManagement.wrap("RSA-OAEP-256", cek, %{}, {:rsa, {:RSAPublicKey, n, e}})
      iex> RequestSeal.Custody.unwrap(handle, encrypted_key) == {:ok, cek}
      true
      iex> RequestSeal.Custody.unwrap(handle, :binary.copy(<<1>>, 256))
      {:error, %RequestSeal.Custody.Error{reason: :decryption_failed, retryable: false}}
      iex> RequestSeal.Custody.unwrap(handle, encrypted_key, max_bytes: 1_024)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_options, retryable: false}}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec unwrap(KeyHandle.t(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def unwrap(handle, encrypted_key, opts \\ []) do
    operation(handle, :unwrap, opts, fn _max ->
      ensure(is_binary(encrypted_key) and byte_size(encrypted_key) in 1..1024, :invalid_data)
      [encrypted_key]
    end)
  end

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
      algorithm), `:no_public_key` (HMAC custody), `:key_not_found` (local holder
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
          op not in [:sign, :verify, :unwrap] or op in handle.capabilities,
          :unsupported_operation
        )

        args = args.(max)
        context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}

        case run(context, fn -> invoke(handle, op, args, context) end) do
          {:ok, :ok} when op == :verify -> :ok
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
        Enum.all?(handle.capabilities, &(&1 in [:sign, :verify, :unwrap])) and
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
      {:jwe, alg} when alg in ["RSA-OAEP", "RSA-OAEP-256"] ->
        ensure(handle.capabilities == [:unwrap], :invalid_handle)
        ensure(function_exported?(handle.custodian, :unwrap, 4), :invalid_handle)

      _ ->
        ensure(:unwrap not in handle.capabilities, :invalid_handle)
        RequestSeal.Crypto.Algorithm.resolve(handle.algorithm)
    end
  end

  defp handle!(_), do: ensure(false, :invalid_handle)
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

  defp invoke(handle, op, args, context) when op in [:sign, :unwrap],
    do:
      normalize(
        op,
        apply(handle.custodian, op, [handle.ref, handle.algorithm | args] ++ [context])
      )

  defp invoke(handle, op, [], _), do: normalize(op, apply(handle.custodian, op, [handle.ref]))

  defp normalize(_, {:error, %{reason: reason}}), do: {:error, Error.new(reason)}
  defp normalize(_, {:error, reason}) when is_atom(reason), do: {:error, Error.new(reason)}
  defp normalize(:verify, :ok), do: :ok

  defp normalize(:sign, {:ok, bytes}) when is_binary(bytes) and byte_size(bytes) in 1..16_384,
    do: {:ok, bytes}

  defp normalize(:sign, {:ok, _}), do: {:error, Error.new(:invalid_signing_output)}

  defp normalize(:unwrap, {:ok, bytes}) when is_binary(bytes) and byte_size(bytes) in 1..1024,
    do: {:ok, bytes}

  defp normalize(:unwrap, {:ok, <<>>}), do: {:error, Error.new(:decryption_failed)}

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
