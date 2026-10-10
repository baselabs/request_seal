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

  `sign/3`, `verify/4`, and `unwrap/3` accept `timeout: milliseconds` (default 5,000;
  1–300,000, no infinity). Signing and verification also accept per-call
  `max_bytes:` (integer 1–16,777,216, default 1,048,576). Bytes exceeding that
  value return `:invalid_data` before custody work. Out-of-range, non-integer,
  unknown, and duplicate options return `:invalid_options`. `unwrap/3` refuses
  `max_bytes:`. Public-key and identity resolution use the default deadline.
  Signatures and public container inputs are bounded to 16,384 bytes.
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
  @callback identity(term()) :: KeyIdentity.t()
  @callback unwrap(term(), unwrap_algorithm(), binary(), Context.t()) ::
              {:ok, binary()} | {:error, Error.reason()}
  @optional_callbacks verify: 5, unwrap: 4

  @doc """
  Unwrap a bounded RSA-OAEP encrypted key using the handle's exact algorithm.

  Only `{:jwe, "RSA-OAEP"}` and `{:jwe, "RSA-OAEP-256"}` handles with `:unwrap`
  capability are accepted. Encrypted keys are 1–1,024 bytes and must match the
  RSA modulus width inside the custodian. Returns unwrapped bytes, never the
  private key. OAEP failures return `:decryption_failed`; callers must authenticate
  content before exposing plaintext. `RequestSeal.JOSE.JWE` performs that step
  with a random fallback CEK on unwrap failure.

  Unwrapped bytes pass from the sensitive local holder through the sensitive
  custody runner and middle process to the caller. On the JWE handle path that
  caller is JWE's sensitive worker, which authenticates content before returning
  plaintext. A direct `unwrap/3` caller receives the bytes and owns their protection.
  An empty OAEP plaintext returns `:decryption_failed`.

  JWE deliberately maps a released or unavailable handle to the same error as a
  forged message. Operators should check `RequestSeal.Custody.public_key(handle)`
  at startup to distinguish custody availability from message rejection;
  `{:ok, public_key}` confirms public resolution, while `{:error, error}` exposes
  the custody failure. Deadline expiration remains a distinct JWE error.
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

  Opt into a larger input bound on each signing and verification call. This
  local example uses actual Ed25519 cryptography under RFC 8032; it is not an
  external conformance vector.

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> bytes = :binary.copy(<<0>>, 1_235_403)
      iex> {:ok, signature} = RequestSeal.Custody.sign(handle, bytes, max_bytes: 2_097_152)
      iex> RequestSeal.Custody.verify(handle, bytes, signature, max_bytes: 2_097_152)
      :ok
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

  Accepts `max_bytes:` (integer 1–16,777,216; default 1,048,576) and `timeout:`
  (1–300,000 milliseconds; default 5,000). Oversized inputs return `:invalid_data`;
  invalid options return `:invalid_options` before handle or capability validation.
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

  @doc "Resolve validated public-only material; symmetric keys return :no_public_key."
  @spec public_key(KeyHandle.t()) :: {:ok, PublicKey.t()} | {:error, Error.t()}
  def public_key(handle), do: operation(handle, :public_key, [], fn _max -> [] end)

  @doc "Resolve internal trusted equivalence; keep the value out of general results."
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

  `context` is a `RequestSeal.Custody.Context` with an integer `deadline` in
  monotonic milliseconds and an `owner` PID. Construct the deadline with
  `System.monotonic_time(:millisecond) + timeout`. An expired deadline returns
  immediately without invoking the callback. The caller and `context.owner`
  are both monitored; either dying cancels the callback, including blocked
  callbacks that trap exits. Nested runs monitor their immediate caller as well
  as their context owner, so cancellation propagates through nested operations.
  An already-dead context owner prevents the callback from starting. Owner death
  returns `{:error, %RequestSeal.Custody.Error{reason: :custodian_failure, retryable: false}}`.

  The callback and its supervising middle process set sensitivity before work.
  Neither is linked to the caller. The runner is terminated and its exit awaited
  before the middle process sends a result; the caller awaits the middle process's
  exit before returning. Deadline expiry cancels the runner and awaits cleanup.
  Work inside a dirty NIF cannot be preempted: cancellation waits for the runner's
  exit, so a long native call can overshoot the deadline.
  Replies use a revocable process alias: queued replies are drained and later
  replies to that alias are discarded, without consuming unrelated caller messages.

  Callback `{:ok, value}` and `{:error, reason}` results pass through unchanged;
  `:ok` becomes `{:ok, :ok}`. Callback errors and successful values belong to the
  caller and are not redacted. Custody and cryptographic validation failures
  retain their bounded `RequestSeal.Custody.Error` reason. Other returns,
  exceptions, unrecognized throws, exits, or unexpected worker termination return
  `{:error, %RequestSeal.Custody.Error{reason: :custodian_failure, retryable: false}}`
  without retaining exception text. Deadline expiry returns the same error shape
  with `reason: :deadline_exceeded, retryable: true`. Invalid context or callback
  arguments return `reason: :invalid_options, retryable: false`.

  Callbacks are trusted code. They must propagate the deadline and cancellation
  to additional processes or external work they start. Cancellation cannot undo
  effects already accepted by a peer, prevent messages explicitly sent to a caller
  PID by callback code, or terminate arbitrary unlinked callback descendants.
  Use nested `run/2` calls for work requiring the same cancellation boundary.

      iex> context = %RequestSeal.Custody.Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
      iex> RequestSeal.Custody.run(context, fn -> {:ok, :completed} end)
      {:ok, :completed}
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
