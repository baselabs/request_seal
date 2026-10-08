defmodule RequestSeal.Replay do
  @moduledoc """
  Atomic whole-envelope replay port with caller-owned stores and commitments.

  Adapters implement `claim/3` and `sweep/3`. Claiming never evicts entries.
  A single monotonic deadline covers the commitment and store operation; caller
  death or deadline expiry kills the operation worker. Cancellation cannot undo
  an already committed claim. No error permits automatic retry.
  Multi-node operators sweep at `now - max_internode_skew` to preserve claims
  while any verifier still accepts the authenticated input.
  One namespace should use one freshness bound because duplicates never extend retention.
  """
  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay.{Claim, Error, Receipt, Store}

  @callback claim(term(), Claim.t(), Context.t()) ::
              :claimed | :already_claimed | {:error, :unavailable | :timeout | :full | :failure}
  @callback sweep(term(), integer(), Context.t()) :: {:ok, non_neg_integer()} | {:error, atom()}

  @doc "Submit one atomic claim under a bounded operation deadline."
  @spec claim(Store.t(), Claim.t(), keyword()) ::
          :claimed | :already_claimed | {:error, Error.t()}
  def claim(store, claim, opts) do
    safe(fn ->
      context = context!(opts)
      ensure(Store.valid?(store), :invalid_store)
      ensure(Claim.valid?(claim), :invalid_claim)
      run(context, fn -> invoke(store, claim, context) end)
    end)
  end

  @doc false
  def policy?(:not_required, _), do: true

  def policy?(
        %{identifier: :nonce, namespace: ns, commitment: fun, store: store, timeout: timeout} =
          replay,
        freshness
      ) do
    map_size(replay) == 5 and Claim.bounded?(ns) and is_function(fun, 1) and
      Store.valid?(store) and is_integer(timeout) and timeout in 1..300_000 and
      is_map(freshness) and (freshness.require_expires or freshness.max_age != nil)
  end

  def policy?(_, _), do: false

  @doc false
  def commit(replay, facts, retain_until) do
    context = context!(timeout: replay.timeout)

    run(context, fn ->
      key =
        case commitment(replay.commitment, facts) do
          {:ok, key} -> key
          _ -> throw({:commitment_failed})
        end

      claim = %Claim{namespace: replay.namespace, key: key, retain_until: retain_until}
      ensure(Claim.valid?(claim), :invalid_claim)
      ensure(Context.remaining(context) > 0, :store_timeout)

      case invoke(replay.store, claim, context) do
        :claimed ->
          {:ok, %Receipt{store: replay.store.adapter, retain_until: retain_until}}

        :already_claimed ->
          {:error, RequestSeal.Error.new(:replayed, :replay)}

        {:error, error} ->
          {:error, RequestSeal.Error.new(authentication_reason(error.reason), :replay)}
      end
    end)
    |> authentication_result()
  end

  defp authentication_result({:error, %Error{reason: reason}}),
    do: {:error, RequestSeal.Error.new(authentication_reason(reason), :replay)}

  defp authentication_result(other), do: other

  defp authentication_reason(reason) when reason in [:store_unavailable, :store_timeout],
    do: reason

  defp authentication_reason(_), do: :store_failed

  defp commitment(fun, facts) do
    case fun.(facts) do
      {:ok, key} when is_binary(key) and byte_size(key) in 1..256 -> {:ok, key}
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp invoke(store, claim, context) do
    case store.adapter.claim(store.ref, claim, context) do
      :claimed -> :claimed
      :already_claimed -> :already_claimed
      {:error, :unavailable} -> {:error, Error.new(:store_unavailable)}
      {:error, :timeout} -> {:error, Error.new(:store_timeout)}
      {:error, :full} -> {:error, Error.new(:store_full)}
      _ -> {:error, Error.new(:store_failed)}
    end
  end

  defp context!([{:timeout, timeout}]) when is_integer(timeout) and timeout in 1..300_000,
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}

  defp context!(_), do: throw({:replay_error, :invalid_options})
  defp ensure(true, _), do: :ok
  defp ensure(_, reason), do: throw({:replay_error, reason})

  defp safe(fun) do
    fun.()
  rescue
    _ -> {:error, Error.new(:store_failed)}
  catch
    {:replay_error, reason} -> {:error, Error.new(reason)}
    {:commitment_failed} -> {:error, RequestSeal.Error.new(:commitment_failed, :replay)}
    _, _ -> {:error, Error.new(:store_failed)}
  end

  defp run(context, callback) do
    owner = self()
    tag = make_ref()

    {worker, monitor} = spawn_monitor(fn -> watch_owner(owner, tag, callback) end)

    receive do
      {^tag, result} ->
        Process.demonitor(monitor, [:flush])
        flush(tag)

        if Context.remaining(context) > 0,
          do: result,
          else: {:error, Error.new(:store_timeout)}

      {:DOWN, ^monitor, :process, ^worker, _} ->
        flush(tag)
        {:error, Error.new(:store_failed)}
    after
      Context.remaining(context) ->
        send(worker, {:cancel, tag})

        receive do
          {:DOWN, ^monitor, :process, ^worker, _} -> :ok
        end

        flush(tag)
        {:error, Error.new(:store_timeout)}
    end
  end

  defp watch_owner(owner, tag, callback) do
    Process.flag(:trap_exit, true)
    owner_ref = Process.monitor(owner)
    middle = self()

    runner =
      spawn_link(fn ->
        send(middle, {tag, safe(callback)})
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
