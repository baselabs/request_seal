defmodule RequestSeal.Test.JOSEBatchCustodian do
  @moduledoc false
  @behaviour RequestSeal.Custody
  alias RequestSeal.Custody.{Context, Sink}

  # A real cryptographic custodian with controlled delivery and lifecycle.
  def start(algorithm, material, mode, observer) do
    owner = self()

    holder =
      spawn(fn ->
        Process.flag(:sensitive, true)
        monitor = Process.monitor(owner)
        loop(algorithm, material, mode, observer, monitor)
      end)

    %RequestSeal.KeyHandle{
      custodian: __MODULE__,
      algorithm: {:jwe, algorithm},
      capabilities: [:unwrap],
      ref: fn -> holder end
    }
  end

  defp loop(alg, material, mode, observer, monitor) do
    receive do
      {:unwrap, runner, items, sink, context} ->
        send(observer, {:batch_holder, self(), runner, sink, context, length(items)})

        receive do
          :continue -> :ok
          {:DOWN, ^monitor, _, _, _} -> exit(:normal)
        end

        case mode do
          :error ->
            send(runner, {:summary, {:error, :custodian_failure}})

          :refuse ->
            Enum.each(items, fn {i, _, _, _} -> Sink.deliver(sink, i, :error) end)
            send(runner, {:summary, :ok})

          mode when mode in [:partial_error, :stall, :stubborn] ->
            [first | _] = items
            deliver(alg, material, first, sink, context)
            send(observer, {:batch_prefix, self()})
            if mode == :partial_error, do: send(runner, {:summary, {:error, :custodian_failure}})
            if mode == :stubborn, do: send(runner, :ignore_deadline)

          :all ->
            Enum.each(items, &deliver(alg, material, &1, sink, context))
            send(runner, {:summary, :ok})
        end

        loop(alg, material, mode, observer, monitor)

      {:DOWN, ^monitor, _, _, _} ->
        :ok
    end
  end

  defp deliver(alg, material, {i, encrypted, params, bits}, sink, context) do
    if Context.remaining(context) > 0 do
      result =
        case RequestSeal.JOSE.KeyManagement.unwrap(alg, encrypted, params, material) do
          {:ok, cek} when bit_size(cek) == bits -> {:ok, cek}
          _ -> :error
        end

      Sink.deliver(sink, i, result)
    end
  end

  @impl true
  def unwrap(ref, _, items, sink, context) do
    holder = ref.()
    monitor = Process.monitor(holder)
    send(holder, {:unwrap, self(), items, sink, context})

    receive do
      {:summary, result} ->
        Process.demonitor(monitor, [:flush])
        result

      :ignore_deadline ->
        # Deliberately block the real custodian callback beyond its deadline;
        # the library, rather than this peer, must terminate the operation.
        receive do: (:never -> :ok)

      {:DOWN, ^monitor, _, _, _} ->
        {:error, :key_not_found}
    after
      Context.remaining(context) -> {:error, :deadline_exceeded}
    end
  end

  @impl true
  def sign(_, _, _, _), do: {:error, :unsupported_operation}
  @impl true
  def public_key(_), do: {:error, :no_public_key}
  @impl true
  def identity(_), do: %RequestSeal.KeyIdentity{kind: :unknown, value: nil}
  @impl true
  def release(ref, _) do
    pid = ref.()
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    receive do: ({:DOWN, ^monitor, _, _, _} -> :ok)
  end
end
