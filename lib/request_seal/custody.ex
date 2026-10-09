defmodule RequestSeal.Custody do
  @moduledoc """
  Caller-owned signing, secret verification, key unwrapping, and public metadata.

  Each callback runs in a fresh runner, never linked to the caller. A monitored
  middle process traps exits, monitors the caller before linking the runner, and
  terminates the runner when the caller dies, even
  when a callback is blocked. Runner exceptions are reduced to
  `:custodian_failure` without logging exception text.
  Deadline expiry kills the runner and drains its
  uniquely tagged result. Loading the library starts no process, store, or
  background work. Local handle construction explicitly starts its key holder.

  `sign/3`, `verify/4`, and `unwrap/3` accept only `timeout: milliseconds` (default 5,000;
  1–300,000, no infinity). Unknown and duplicate options reject. Public-key and
  identity resolution use the default deadline. Exact input bytes are limited to
  1,048,576; signatures and public container inputs are bounded to 16,384 bytes.
  Signing returns bytes; verification establishes mathematical validity only.
  Neither establishes identity attribution, authorization, or replay protection.

  Custodians are trusted code: they must return only public keys and nonsecret
  identities, never log secrets, and must propagate the context deadline and
  cancellation to any additional work they own. Killing the worker closes sockets
  it owns; it cannot revoke work already accepted by an external peer.
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
  """
  @spec unwrap(KeyHandle.t(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def unwrap(handle, encrypted_key, opts \\ []) do
    operation(handle, :unwrap, opts, fn ->
      ensure(is_binary(encrypted_key) and byte_size(encrypted_key) in 1..1024, :invalid_data)
      [encrypted_key]
    end)
  end

  @doc "Sign exact bounded bytes with the algorithm bound to a handle."
  @spec sign(KeyHandle.t(), binary(), keyword()) :: {:ok, binary()} | {:error, Error.t()}
  def sign(handle, bytes, opts \\ []) do
    operation(handle, :sign, opts, fn ->
      data!(bytes)
      [bytes]
    end)
  end

  @doc "Verify exact bytes through secret custody or the custodian's public key."
  @spec verify(KeyHandle.t(), binary(), binary(), keyword()) :: :ok | {:error, Error.t()}
  def verify(handle, bytes, signature, opts \\ []) do
    operation(handle, :verify, opts, fn ->
      data!(bytes)
      ensure(is_binary(signature), :invalid_signature)
      ensure(byte_size(signature) <= 16_384, :limit)
      [bytes, signature]
    end)
  end

  @doc "Resolve validated public-only material; symmetric keys return :no_public_key."
  @spec public_key(KeyHandle.t()) :: {:ok, PublicKey.t()} | {:error, Error.t()}
  def public_key(handle), do: operation(handle, :public_key, [], fn -> [] end)

  @doc "Resolve internal trusted equivalence; keep the value out of general results."
  @spec identity(KeyHandle.t()) :: {:ok, KeyIdentity.t()} | {:error, Error.t()}
  def identity(handle), do: operation(handle, :identity, [], fn -> [] end)

  defp operation(handle, op, opts, args) do
    Support.safe(
      fn ->
        timeout = Support.timeout(opts)
        handle!(handle)

        ensure(
          op not in [:sign, :verify, :unwrap] or op in handle.capabilities,
          :unsupported_operation
        )

        args = args.()
        context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}
        run(context, fn -> invoke(handle, op, args, context) end)
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
  defp data!(bytes), do: ensure(is_binary(bytes) and byte_size(bytes) <= 1_048_576, :invalid_data)

  defp invoke(handle, :verify, [bytes, signature], context) do
    result =
      if function_exported?(handle.custodian, :verify, 5) do
        handle.custodian.verify(handle.ref, handle.algorithm, bytes, signature, context)
      else
        public = handle.custodian.public_key(handle.ref) |> Support.unwrap()
        RequestSeal.Crypto.verify(handle.algorithm, bytes, signature, public)
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

  defp normalize(:unwrap, {:ok, bytes}) when is_binary(bytes) and byte_size(bytes) in 1..1024,
    do: {:ok, bytes}

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

  @doc false
  def run(%Context{} = context, callback) when is_function(callback, 0) do
    owner = self()
    tag = make_ref()

    {worker, monitor} = spawn_monitor(fn -> watch_owner(owner, tag, callback) end)

    receive do
      {^tag, result} ->
        Process.demonitor(monitor, [:flush])
        flush(tag)

        if Context.remaining(context) > 0,
          do: result,
          else: {:error, Error.new(:deadline_exceeded)}

      {:DOWN, ^monitor, :process, ^worker, _} ->
        flush(tag)
        {:error, Error.new(:custodian_failure)}
    after
      Context.remaining(context) ->
        send(worker, {:cancel, tag})

        receive do
          {:DOWN, ^monitor, :process, ^worker, _} -> :ok
        end

        flush(tag)
        {:error, Error.new(:deadline_exceeded)}
    end
  end

  defp watch_owner(owner, tag, callback) do
    Process.flag(:trap_exit, true)
    owner_ref = Process.monitor(owner)
    middle = self()

    runner =
      spawn_link(fn ->
        send(middle, {tag, Support.safe(callback, :custodian_failure)})
      end)

    receive do
      {^tag, result} ->
        stop_runner(runner)
        send(owner, {tag, result})

      {:DOWN, ^owner_ref, :process, ^owner, _} ->
        stop_runner(runner)

      {:cancel, ^tag} ->
        stop_runner(runner)

      {:EXIT, ^runner, _} ->
        :ok
    end
  end

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
