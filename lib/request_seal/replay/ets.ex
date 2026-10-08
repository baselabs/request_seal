defmodule RequestSeal.Replay.ETS do
  @moduledoc """
  Local atomic replay store owned by a caller-supervised GenServer.

  `start_link/1` requires `max_entries: 1..10_000_000`. The protected ETS table
  contains a reserved counter and namespace/key entries. Only this adapter may
  mutate it. Claims and explicit sweeps are serialized by its owner, preventing
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

  @doc "Start a local store under caller supervision."
  def start_link([{:max_entries, max}]) when is_integer(max) and max in 1..10_000_000,
    do: GenServer.start_link(__MODULE__, max)

  def start_link(_), do: {:error, :invalid_options}

  @doc "Reference an existing caller-owned store."
  @spec store(pid()) :: Store.t()
  def store(pid) when is_pid(pid), do: %Store{adapter: __MODULE__, ref: pid}

  @impl true
  def init(max) do
    table = :ets.new(__MODULE__, [:set, :protected])
    :ets.insert(table, {:count, 0})
    {:ok, %{table: table, max: max}}
  end

  @impl RequestSeal.Replay
  def claim(pid, %Claim{} = claim, %Context{} = context),
    do: call(pid, {:claim, claim, context}, context)

  def claim(_, _, _), do: {:error, :failure}

  @doc "Explicitly evict claims whose exclusive retention end is at or before now."
  def sweep(pid, now),
    do:
      sweep(pid, now, %Context{
        owner: self(),
        deadline: System.monotonic_time(:millisecond) + 5000
      })

  @impl RequestSeal.Replay
  def sweep(pid, now, %Context{} = context) when is_integer(now),
    do: call(pid, {:sweep, now, context}, context)

  def sweep(_, _, _), do: {:error, :failure}

  @impl GenServer
  def handle_call({:claim, %Claim{} = claim, %Context{} = context}, _from, state) do
    key = {:claim, claim.namespace, claim.key}

    result =
      cond do
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
  def handle_call({:sweep, now, %Context{} = context}, _from, state) when is_integer(now) do
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
