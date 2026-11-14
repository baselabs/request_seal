defmodule RequestSeal.Custody.Sink do
  @moduledoc """
  Opaque, revocable delivery address for one indexed unwrap call.

  Custodians call `deliver/3` directly from the process holding the key. They
  never return a CEK through the custody runner. Only the owner decides whether
  a delivery arrived before its absolute deadline and settles each index once.
  """
  alias RequestSeal.Custody.Context
  @derive {Inspect, only: []}
  @enforce_keys [:owner, :address, :tag, :widths, :deadline]
  defstruct [:owner, :address, :tag, :widths, :deadline]

  @opaque t :: %__MODULE__{
            owner: pid(),
            address: reference(),
            tag: reference(),
            widths: %{non_neg_integer() => 128 | 256},
            deadline: integer()
          }

  @doc """
  Deliver an indexed unwrap outcome directly to its owner.

  Custodians send `{:ok, cek}` or `:error`, never `:timeout`, and check their
  context deadline before each item. Delivery does not confirm acceptance.
  The owner accepts only envelopes dequeued strictly before its deadline;
  unknown indices are discarded, and first settlement wins. Malformed outcomes
  or CEKs of the wrong width settle `:error`. Revoked aliases discard sends.
  """
  @spec deliver(t(), non_neg_integer(), {:ok, binary()} | :error) :: :ok
  def deliver(%__MODULE__{address: address, tag: tag}, index, outcome) do
    send(address, {tag, index, outcome})
    :ok
  end

  @doc false
  @spec new([RequestSeal.Custody.item()], Context.t()) :: t()
  def new(items, %Context{deadline: deadline}) do
    %__MODULE__{
      owner: self(),
      address: :erlang.alias(),
      tag: make_ref(),
      widths: Map.new(items, fn {index, _, _, bits} -> {index, bits} end),
      deadline: deadline
    }
  end

  @doc false
  @spec close(t()) :: :ok
  def close(%__MODULE__{owner: owner, address: address, tag: tag}) when owner == self() do
    :erlang.unalias(address)
    drain(tag)
  end

  defp drain(tag) do
    receive do
      {^tag, _, _} -> drain(tag)
      {^tag, _} -> drain(tag)
    after
      0 -> :ok
    end
  end

  @doc false
  @spec collect(t(), (-> term())) :: [{:ok, binary()} | :error | :timeout]
  def collect(%__MODULE__{owner: owner} = sink, callback) when owner == self() do
    # This helper sees only the call summary. Custody.run owns cancellation of
    # the callback; the CEKs go directly to this collecting owner.
    {helper, monitor} =
      spawn_monitor(fn ->
        Process.flag(:sensitive, true)
        result = RequestSeal.Custody.Support.safe(callback, :custodian_failure)
        send(sink.address, {sink.tag, result})
      end)

    try do
      positions = Map.new(sink.widths, fn {index, _} -> {index, :unsettled} end)

      collect_results(sink, positions, helper, monitor)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(&elem(&1, 1))
    after
      close(sink)
      Process.demonitor(monitor, [:flush])
    end
  end

  defp collect_results(sink, positions, helper, monitor) do
    tag = sink.tag

    receive do
      {^tag, index, outcome} ->
        if remaining(sink) > 0 do
          positions = settle(sink, positions, index, outcome)
          collect_results(sink, positions, helper, monitor)
        else
          expire(sink, positions, helper, monitor)
        end

      {^tag, _summary} ->
        # run/2 may already have replaced a late callback result with a deadline
        # error. A summary never overwrites a position accepted earlier.
        finish(sink, positions, helper, monitor)

      {:DOWN, ^monitor, :process, ^helper, _} ->
        finish(sink, positions, nil, nil)
    after
      max(remaining(sink), 0) -> expire(sink, positions, helper, monitor)
    end
  end

  defp settle(sink, positions, index, outcome) do
    case Map.fetch(positions, index) do
      {:ok, :unsettled} ->
        value =
          case outcome do
            {:ok, cek} when is_binary(cek) ->
              if bit_size(cek) == Map.fetch!(sink.widths, index), do: {:ok, cek}, else: :error

            _ ->
              :error
          end

        Map.put(positions, index, value)

      _ ->
        positions
    end
  end

  defp finish(sink, positions, helper, monitor) do
    if remaining(sink) > 0 do
      # The summary settles now. An envelope not yet dequeued cannot replace
      # that settlement, even when it is already queued behind the summary.
      positions = settle_rest(positions, :error)
      close(sink)
      await_helper(helper, monitor)
      positions
    else
      expire(sink, positions, helper, monitor)
    end
  end

  defp expire(sink, positions, helper, monitor) do
    # The order matters: revoke first, discard queued envelopes second, and
    # only then settle the remaining positions. Never accept a queued CEK here.
    close(sink)
    positions = settle_rest(positions, :timeout)
    await_helper(helper, monitor)
    positions
  end

  defp settle_rest(positions, outcome),
    do:
      Map.new(positions, fn {index, value} ->
        {index, if(value == :unsettled, do: outcome, else: value)}
      end)

  defp await_helper(nil, nil), do: :ok

  defp await_helper(helper, monitor) do
    receive do
      {:DOWN, ^monitor, :process, ^helper, _} -> :ok
    end
  end

  defp remaining(sink), do: sink.deadline - System.monotonic_time(:millisecond)
end
