defmodule RequestSeal.Idempotency.ETS do
  @moduledoc """
  Caller-supervised local storage for reservations and completed responses.
  One owner serializes inserts, fenced completion and sweeps. State ends with
  the owner. Applications needing restart or multi-node recovery supply a
  durable adapter with the same atomic transitions.
  """
  use GenServer
  @behaviour RequestSeal.Idempotency

  alias RequestSeal.Custody.Context
  alias RequestSeal.Idempotency.{Record, Reservation}

  @doc "Start a local store with the required `:max_entries` capacity (1–10,000)."
  @spec start_link(keyword()) :: GenServer.on_start() | {:error, :invalid_options}
  def start_link(max_entries: max) when is_integer(max) and max in 1..10_000,
    do: GenServer.start_link(__MODULE__, max)

  def start_link(_), do: {:error, :invalid_options}

  @doc "Build the store reference for `RequestSeal.Idempotency`."
  @spec store(pid()) :: RequestSeal.Idempotency.store()
  def store(pid) when is_pid(pid), do: {__MODULE__, pid}

  @impl RequestSeal.Idempotency
  def reserve(pid, record, context),
    do: call(pid, {:reserve, record}, context)

  @impl RequestSeal.Idempotency
  def store(pid, reservation, response, context),
    do: call(pid, {:store, reservation, response}, context)

  @impl RequestSeal.Idempotency
  def sweep(pid, now, context),
    do: call(pid, {:sweep, now}, context)

  @impl GenServer
  def init(max), do: {:ok, {:ets.new(__MODULE__, [:set, :private]), max}}

  @impl GenServer
  def handle_call({request, context}, _from, state) do
    reply =
      if Context.remaining(context) > 0 and Process.alive?(context.owner),
        do: perform(request, state),
        else: {:error, :timeout}

    {:reply, reply, state}
  end

  defp perform({:reserve, %Record{} = record}, {table, max}) do
    key = Record.key(record)
    fingerprint = record.fingerprint

    case :ets.lookup(table, key) do
      [{^key, _, other, _, _}] when other != fingerprint ->
        :conflict

      [{^key, _, ^fingerprint, _, {:stored, response}}] ->
        {:stored, response}

      [{^key, _, ^fingerprint, lease_end, _}] when lease_end > record.now ->
        :in_progress

      [{^key, retain_until, ^fingerprint, _, _}] when record.now < retain_until ->
        insert(table, record, key, max(retain_until, record.retain_until))

      [_] ->
        :in_progress

      [] ->
        if :ets.info(table, :size) < max,
          do: insert(table, record, key, record.retain_until),
          else: {:error, :full}
    end
  end

  defp perform({:store, %Reservation{record: record, token: token}, response}, {table, _}) do
    key = Record.key(record)
    fingerprint = record.fingerprint

    case :ets.lookup(table, key) do
      [{^key, retention, ^fingerprint, lease_end, {:pending, ^token}}] ->
        :ets.insert(table, {key, retention, fingerprint, lease_end, {:stored, response}})
        :stored

      _ ->
        :not_reserved
    end
  end

  defp perform({:sweep, now}, {table, _}),
    do:
      {:ok, :ets.select_delete(table, [{{:_, :"$1", :_, :_, :_}, [{:"=<", :"$1", now}], [true]}])}

  defp insert(table, record, key, retention) do
    token = :crypto.strong_rand_bytes(16)

    :ets.insert(
      table,
      {key, retention, record.fingerprint, record.lease_until, {:pending, token}}
    )

    {:reserved, token}
  end

  defp call(pid, request, %Context{} = context) when is_pid(pid) do
    case Context.remaining(context) do
      0 -> {:error, :timeout}
      remaining -> GenServer.call(pid, {request, context}, remaining)
    end
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, _ -> {:error, :unavailable}
  end

  defp call(_, _, _), do: {:error, :failure}
end
