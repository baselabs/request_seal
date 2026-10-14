defmodule RequestSeal.Replay.ETS do
  @moduledoc """
  Local atomic replay store owned by a caller-supervised GenServer.

  The protected ETS table contains a reserved counter and namespace/key
  entries. Only this adapter may mutate it. Claims and explicit sweeps are serialized by its owner, preventing
  delete/insert races and enforcing an exact capacity. Duplicate claims never
  refresh retention. Owner termination loses all claims; this is not a durable
  or distributed store. Importing the module starts nothing.
  Multi-node operators sweep at `now - max_internode_skew` to preserve claims
  while any verifier still accepts the authenticated input.
  One namespace should use one freshness bound because duplicates never extend retention.
  """
  use GenServer
  @behaviour RequestSeal.Replay
  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay.{Claim, Store}

  @doc """
  Start a local store owned by the calling process, normally under a supervisor.

  The process is linked to the caller. Use `{RequestSeal.Replay.ETS, max_entries: n}`
  as a child specification.

  ## Parameters

    * `opts` - keyword list; see Options.

  ## Options

    * `:max_entries` - required, and the only accepted option: the exact number of
      claims the store holds, 1 through 10,000,000. A claim beyond it returns
      `{:error, :full}` until a sweep removes entries.

  ## Returns

    * `{:ok, pid}` - the started store owner.
    * `{:error, :invalid_options}` - a missing, extra or out-of-range option
      (a bare atom, not a `RequestSeal.Replay.Error`).
    * Any other `GenServer.start_link/3` result.

  ## Examples

      iex> {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 10_000)
      iex> is_pid(pid)
      true
      iex> GenServer.stop(pid)
      :ok
      iex> RequestSeal.Replay.ETS.start_link(max_entries: 0)
      {:error, :invalid_options}
  """
  def start_link([{:max_entries, max}]) when is_integer(max) and max in 1..10_000_000,
    do: GenServer.start_link(__MODULE__, max)

  def start_link(_), do: {:error, :invalid_options}

  @doc """
  Reference an existing caller-owned store for `RequestSeal.Replay.claim/3` or a replay policy.

  Building the reference does not contact the store.

  ## Parameters

    * `pid` - the pid returned by `start_link/1`.

  ## Returns

    * `RequestSeal.Replay.Store` - adapter `RequestSeal.Replay.ETS` with `pid` as its reference.
      A non-pid argument raises `FunctionClauseError`.

  ## Examples

      iex> {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 100)
      iex> store = RequestSeal.Replay.ETS.store(pid)
      iex> store.adapter
      RequestSeal.Replay.ETS
      iex> GenServer.stop(pid)
      :ok
  """
  @spec store(pid()) :: Store.t()
  def store(pid) when is_pid(pid), do: %Store{adapter: __MODULE__, ref: pid}

  @impl true
  def init(max) do
    table = :ets.new(__MODULE__, [:set, :protected])
    :ets.insert(table, {:count, 0})
    {:ok, %{table: table, max: max}}
  end

  @doc """
  Atomically store `claim` unless the store already holds its namespace and key.

  Implements `c:RequestSeal.Replay.claim/3`; most callers use
  `RequestSeal.Replay.claim/3`, which supplies the context and maps results to
  `RequestSeal.Replay.Error`. A duplicate never refreshes retention, and a stored
  entry stays until a sweep removes it, even after its retention end.

  ## Parameters

    * `pid` - the store owner from `start_link/1`.
    * `claim` - a `RequestSeal.Replay.Claim`.
    * `context` - a `RequestSeal.Custody.Context`; its remaining time bounds the call.

  ## Returns

    * `:claimed` - the entry was stored.
    * `:already_claimed` - the namespace and key are already stored (also when the
      store is full).
    * `{:error, :full}` - the store holds `max_entries` claims.
    * `{:error, :timeout}` - the deadline expired before or during the call.
    * `{:error, :unavailable}` - the owner process is not running.
    * `{:error, :failure}` - the claim fails `RequestSeal.Replay.Claim.valid?/1`,
      or an argument is not a claim or context.

  ## Examples

      iex> {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 1)
      iex> context = %RequestSeal.Custody.Context{
      ...>   owner: self(),
      ...>   deadline: System.monotonic_time(:millisecond) + 1_000
      ...> }
      iex> claim = %RequestSeal.Replay.Claim{namespace: "builds", key: "job-41", retain_until: 100}
      iex> RequestSeal.Replay.ETS.claim(pid, claim, context)
      :claimed
      iex> RequestSeal.Replay.ETS.claim(pid, claim, context)
      :already_claimed
      iex> RequestSeal.Replay.ETS.claim(pid, %{claim | key: "job-42"}, context)
      {:error, :full}
      iex> GenServer.stop(pid)
      :ok
  """
  @impl RequestSeal.Replay
  def claim(pid, %Claim{} = claim, %Context{} = context),
    do: call(pid, {:claim, claim, context}, context)

  def claim(_, _, _), do: {:error, :failure}

  @doc """
  Explicitly evict claims whose exclusive retention end is at or before `now`, with a 5,000 ms deadline.

  Same as `sweep/3` with a context whose deadline is 5,000 milliseconds from now.

  ## Parameters

    * `pid` - the store owner from `start_link/1`.
    * `now` - Unix seconds from 0 through 253,402,300,799.

  ## Returns

  Same as `sweep/3`.

  ## Examples

      iex> {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 100)
      iex> store = RequestSeal.Replay.ETS.store(pid)
      iex> claim = %RequestSeal.Replay.Claim{namespace: "messages", key: "m-1", retain_until: 1_000}
      iex> RequestSeal.Replay.claim(store, claim, timeout: 1_000)
      :claimed
      iex> RequestSeal.Replay.ETS.sweep(pid, 999)
      {:ok, 0}
      iex> RequestSeal.Replay.ETS.sweep(pid, 1_000)
      {:ok, 1}
      iex> RequestSeal.Replay.claim(store, claim, timeout: 1_000)
      :claimed
      iex> RequestSeal.Replay.ETS.sweep(pid, -1)
      {:error, :failure}
      iex> GenServer.stop(pid)
      :ok
  """
  def sweep(pid, now),
    do:
      sweep(pid, now, %Context{
        owner: self(),
        deadline: System.monotonic_time(:millisecond) + 5000
      })

  @doc """
  Evict claims whose exclusive retention end is at or before `now`.

  Implements `c:RequestSeal.Replay.sweep/3`. Sweeps are serialized with claims by
  the store owner.

  ## Parameters

    * `pid` - the store owner from `start_link/1`.
    * `now` - Unix seconds from 0 through 253,402,300,799.
    * `context` - a `RequestSeal.Custody.Context`; its remaining time bounds the call.

  ## Returns

    * `{:ok, removed}` - the number of claims deleted.
    * `{:error, :timeout}` - the deadline expired before or during the call.
    * `{:error, :unavailable}` - the owner process is not running.
    * `{:error, :failure}` - `now` is outside the range, or `context` is not a
      `RequestSeal.Custody.Context`.

  ## Examples

      iex> {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 100)
      iex> context = %RequestSeal.Custody.Context{
      ...>   owner: self(),
      ...>   deadline: System.monotonic_time(:millisecond) + 1_000
      ...> }
      iex> claim = %RequestSeal.Replay.Claim{namespace: "crawl", key: "page-9", retain_until: 50}
      iex> RequestSeal.Replay.ETS.claim(pid, claim, context)
      :claimed
      iex> RequestSeal.Replay.ETS.sweep(pid, 50, context)
      {:ok, 1}
      iex> RequestSeal.Replay.ETS.sweep(pid, 253_402_300_800, context)
      {:error, :failure}
      iex> GenServer.stop(pid)
      :ok
  """
  @impl RequestSeal.Replay
  def sweep(pid, now, %Context{} = context) when is_integer(now) and now in 0..253_402_300_799,
    do: call(pid, {:sweep, now, context}, context)

  def sweep(_, _, _), do: {:error, :failure}

  @impl GenServer
  def handle_call({:claim, %Claim{} = claim, %Context{} = context}, _from, state) do
    key = {:claim, claim.namespace, claim.key}

    result =
      cond do
        not Claim.valid?(claim) ->
          {:error, :failure}

        Context.remaining(context) == 0 ->
          {:error, :timeout}

        true ->
          reserved = :ets.update_counter(state.table, :count, 1)

          cond do
            reserved > state.max ->
              :ets.update_counter(state.table, :count, -1)
              if :ets.member(state.table, key), do: :already_claimed, else: {:error, :full}

            :ets.insert_new(state.table, {key, claim.retain_until}) ->
              :claimed

            true ->
              :ets.update_counter(state.table, :count, -1)
              :already_claimed
          end
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:sweep, now, %Context{} = context}, _from, state)
      when is_integer(now) and now in 0..253_402_300_799 do
    if Context.remaining(context) == 0 do
      {:reply, {:error, :timeout}, state}
    else
      removed =
        :ets.select_delete(state.table, [
          {{{:claim, :_, :_}, :"$1"}, [{:"=<", :"$1", now}], [true]}
        ])

      :ets.update_counter(state.table, :count, -removed)
      {:reply, {:ok, removed}, state}
    end
  end

  def handle_call(_, _from, state), do: {:reply, {:error, :failure}, state}

  defp call(pid, request, context) do
    GenServer.call(pid, request, max(1, Context.remaining(context)))
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, _ -> {:error, :unavailable}
  end
end
