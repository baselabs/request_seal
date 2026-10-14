defmodule RequestSeal.Replay do
  @moduledoc """
  Atomic whole-envelope replay port with caller-owned stores and commitments.

  Adapters implement `c:claim/3` and `c:sweep/3`. Claiming never evicts entries.
  Generic and Web Bot Auth verification reject a derived retention end above
  253,402,300,799 Unix seconds with `RequestSeal.Error` reason
  `:retention_exceeded` at `:replay` before commitment or storage. Such claims
  cannot be swept. Direct store callers still receive the existing invalid-claim
  failure; `RequestSeal.Replay.Claim.valid?/1` rejects them.
  Negative retention ends are already expired.
  A single monotonic deadline covers the commitment and store operation; caller
  death or deadline expiry kills the operation worker. Cancellation cannot undo
  an already committed claim. No error permits automatic retry.
  Multi-node operators sweep at `now - max_internode_skew` to preserve claims
  while any verifier still accepts the authenticated input.
  One namespace should use one freshness bound because duplicates never extend retention.
  """
  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay.{Claim, Error, Receipt, Store}

  @doc """
  Atomically record `claim` in the store `ref`, unless its namespace and key are already stored.

  `RequestSeal.Replay.claim/3` validates the claim and builds `context` before
  calling the adapter. An adapter honors `context` as the operation deadline
  and never evicts or refreshes an existing entry while claiming.

  ## Parameters

    * `ref` - the adapter's reference, taken from `RequestSeal.Replay.Store`'s `ref`.
    * `claim` - a `RequestSeal.Replay.Claim` with its namespace, key and exclusive
      retention end in Unix seconds.
    * `context` - a `RequestSeal.Custody.Context` carrying the absolute deadline.

  ## Returns

    * `:claimed` - the entry was stored by this call.
    * `:already_claimed` - an entry with the same namespace and key is stored.
    * `{:error, :unavailable}` - the store could not be reached.
    * `{:error, :timeout}` - the deadline expired; the claim may have been committed.
    * `{:error, :full}` - the store is at capacity.
    * `{:error, :failure}` - any other failure, including an invalid claim or reference.

  `RequestSeal.Replay.claim/3` maps these to `RequestSeal.Replay.Error` reasons
  `:store_unavailable`, `:store_timeout`, `:store_full` and `:store_failed`;
  any other adapter result also becomes `:store_failed`.
  """
  @callback claim(term(), Claim.t(), Context.t()) ::
              :claimed | :already_claimed | {:error, :unavailable | :timeout | :full | :failure}

  @doc """
  Delete stored claims whose exclusive retention end is at or before `now`.

  ## Parameters

    * `ref` - the adapter's reference, taken from `RequestSeal.Replay.Store`'s `ref`.
    * `now` - Unix seconds from 0 through 253,402,300,799, from a clock the caller
      trusts and reconciles with verification clocks.
    * `context` - a `RequestSeal.Custody.Context` carrying the absolute deadline.

  ## Returns

    * `{:ok, removed}` - the number of entries deleted.
    * `{:error, reason}` - an adapter-specific atom; the bundled adapters return
      `:failure`, `:timeout` or `:unavailable`, and `RequestSeal.Replay.AshOnetime`
      always returns `:externally_managed`.
  """
  @callback sweep(term(), 0..253_402_300_799, Context.t()) ::
              {:ok, non_neg_integer()} | {:error, atom()}

  @doc """
  Submit one atomic claim to a store under a bounded operation deadline.

  The claim runs in a monitored worker. Caller death or deadline expiry kills
  the worker; a store that already committed the claim keeps it.

  ## Parameters

    * `store` - a `RequestSeal.Replay.Store` whose adapter module is loaded and
      exports `claim/3` and `sweep/3`, for example from
      `RequestSeal.Replay.ETS.store/1`.
    * `claim` - a `RequestSeal.Replay.Claim` accepted by
      `RequestSeal.Replay.Claim.valid?/1`.
    * `opts` - keyword list; see Options.

  ## Options

    * `:timeout` - required, and the only accepted option: operation deadline in
      milliseconds, 1 through 300,000.

  ## Returns

    * `:claimed` - this call stored the claim.
    * `:already_claimed` - the store already holds the namespace and key.
    * `{:error, %RequestSeal.Replay.Error{}}` - reasons this function can return:
      `:invalid_options`, `:invalid_store`, `:invalid_claim`, `:store_unavailable`,
      `:store_timeout`, `:store_full`, `:store_failed`. `retryable` is always
      false. Meanings: `RequestSeal.Replay.Error`.

  ## Examples

      iex> {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 100)
      iex> store = RequestSeal.Replay.ETS.store(pid)
      iex> claim = %RequestSeal.Replay.Claim{
      ...>   namespace: "orders",
      ...>   key: "nonce-7f3a",
      ...>   retain_until: 1_900_000_000
      ...> }
      iex> RequestSeal.Replay.claim(store, claim, timeout: 1_000)
      :claimed
      iex> RequestSeal.Replay.claim(store, claim, timeout: 1_000)
      :already_claimed
      iex> RequestSeal.Replay.claim(store, %{claim | namespace: "telemetry"}, timeout: 1_000)
      :claimed
      iex> RequestSeal.Replay.claim(store, claim, timeout: 0)
      {:error, %RequestSeal.Replay.Error{reason: :invalid_options, retryable: false}}
      iex> RequestSeal.Replay.claim(store, %{claim | key: ""}, timeout: 1_000)
      {:error, %RequestSeal.Replay.Error{reason: :invalid_claim, retryable: false}}
      iex> GenServer.stop(pid)
      :ok
  """
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
