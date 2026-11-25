defmodule RequestSeal.Replay.Pair do
  @moduledoc """
  Composes two caller-owned replay stores during a migration.

  Every accepted claim is new in the destination and then new in the retiring
  store. The same absolute deadline applies to both. A destination claim
  survives a refusal or failure in the retiring store. See the replay protection
  guide for the order of rollout and the retention window.
  """
  @behaviour RequestSeal.Replay

  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay.{Claim, Error, Store}

  @max_clock 253_402_300_799

  @doc """
  Returns a replay store with the destination first and retiring store second.

  Rejects invalid handles, identical handles, and nested pairs with
  `:invalid_store`. The caller must configure two distinct storage namespaces
  even when two handles point at different clients.
  """
  @spec store(Store.t(), Store.t()) :: {:ok, Store.t()} | {:error, Error.t()}
  def store(destination, retiring) do
    if distinct?(destination, retiring) do
      {:ok, %Store{adapter: __MODULE__, ref: {destination, retiring}}}
    else
      {:error, Error.new(:invalid_store)}
    end
  end

  @doc """
  Claims the destination first and, on a new claim, claims the retiring store.
  Implements the replay adapter callback under the caller's shared deadline.
  """
  @impl RequestSeal.Replay
  @spec claim(term(), Claim.t(), Context.t()) ::
          :claimed | :already_claimed | {:error, :unavailable | :timeout | :full | :failure}
  def claim({destination, retiring}, claim, %Context{} = context) do
    if distinct?(destination, retiring) and Claim.valid?(claim) do
      with :claimed <- invoke(:claim, :destination, destination, claim, context) do
        invoke(:claim, :retiring, retiring, claim, context)
      end
    else
      {:error, :failure}
    end
  end

  def claim(_, _, _), do: {:error, :failure}

  @doc """
  Sweeps both stores within the shared deadline and sums deleted entries.
  Externally managed stores contribute zero. When both are externally managed,
  returns `{:error, :externally_managed}`. Other errors take precedence in
  destination-first order. Implements the replay adapter callback.
  """
  @impl RequestSeal.Replay
  @spec sweep(term(), integer(), Context.t()) :: {:ok, non_neg_integer()} | {:error, atom()}
  def sweep({destination, retiring}, now, %Context{} = context)
      when is_integer(now) and now in 0..@max_clock do
    if distinct?(destination, retiring) do
      first = invoke(:sweep, :destination, destination, now, context)
      second = invoke(:sweep, :retiring, retiring, now, context)
      sweep_result(first, second)
    else
      {:error, :failure}
    end
  end

  def sweep(_, _, _), do: {:error, :failure}

  defp distinct?(%Store{adapter: left} = destination, %Store{adapter: right} = retiring)
       when left != __MODULE__ and right != __MODULE__ and destination != retiring,
       do: Store.valid?(destination) and Store.valid?(retiring)

  defp distinct?(_, _), do: false

  defp invoke(operation, position, store, input, context) do
    started = System.monotonic_time()

    result =
      if Context.remaining(context) > 0 do
        normalize(operation, call(operation, store, input, context))
      else
        {:error, :timeout}
      end

    {outcome, reason} =
      case result do
        {:error, reason} -> {:error, reason}
        {:ok, _} -> {:ok, nil}
        outcome -> {outcome, nil}
      end

    RequestSeal.Telemetry.emit(
      [:request_seal, :replay, :pair],
      System.monotonic_time() - started,
      %{operation: operation, position: position, outcome: outcome, reason: reason}
    )

    result
  end

  defp call(operation, store, input, context) do
    apply(store.adapter, operation, [store.ref, input, context])
  rescue
    _ -> {:error, :failure}
  catch
    :exit, _ -> {:error, :unavailable}
    _, _ -> {:error, :failure}
  end

  defp normalize(:claim, outcome) when outcome in [:claimed, :already_claimed], do: outcome
  defp normalize(:sweep, {:ok, count}) when is_integer(count) and count >= 0, do: {:ok, count}
  defp normalize(:sweep, {:error, :externally_managed} = result), do: result

  defp normalize(_, {:error, reason} = result)
       when reason in [:unavailable, :timeout, :full, :failure],
       do: result

  defp normalize(_, _), do: {:error, :failure}

  defp sweep_result({:ok, first}, {:ok, second}), do: {:ok, first + second}
  defp sweep_result({:error, :externally_managed}, second), do: second
  defp sweep_result(first, {:error, :externally_managed}), do: first
  defp sweep_result({:error, _} = first, _), do: first
  defp sweep_result(_, second), do: second
end
