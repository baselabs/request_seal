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
  alias RequestSeal.Idempotency
  alias RequestSeal.Idempotency.{Record, Reservation}

  @doc """
  Start a local store with required `:max_entries` capacity (1–10,000).
  The optional zero-arity `:clock` returns trusted Unix seconds from
  0 through 253,402,300,799. It defaults to the system Unix clock. The
  store uses its latest observed time if the clock moves backward.
  """
  @spec start_link(keyword()) :: GenServer.on_start() | {:error, :invalid_options}
  def start_link(opts) when is_list(opts) and length(opts) in 1..2 do
    with true <- Keyword.keyword?(opts),
         keys = Enum.sort(Keyword.keys(opts)),
         true <- keys in [[:max_entries], [:clock, :max_entries]],
         max when is_integer(max) and max in 1..10_000 <- opts[:max_entries],
         clock when is_function(clock, 0) <- Keyword.get(opts, :clock, &system_clock/0) do
      GenServer.start_link(__MODULE__, {max, clock})
    else
      _ -> {:error, :invalid_options}
    end
  end

  def start_link(_), do: {:error, :invalid_options}

  defp system_clock, do: System.system_time(:second)

  @doc "Build the store reference for `RequestSeal.Idempotency`."
  @spec store(pid()) :: RequestSeal.Idempotency.store()
  def store(pid) when is_pid(pid), do: {__MODULE__, pid}

  @impl RequestSeal.Idempotency
  def reserve(pid, record, context) do
    if Record.valid?(record),
      do: call(pid, {:reserve, record}, context),
      else: {:error, :failure}
  end

  @impl RequestSeal.Idempotency
  def store(pid, reservation, response, context) do
    if Idempotency.valid_reservation?(reservation) and Idempotency.response?(response),
      do: call(pid, {:store, reservation, response}, context),
      else: {:error, :failure}
  end

  @impl RequestSeal.Idempotency
  def sweep(pid, now, context) when is_integer(now) and now in 0..253_402_300_799,
    do: call(pid, {:sweep, now}, context)

  def sweep(_, _, _), do: {:error, :failure}

  @impl GenServer
  def init({max, clock}),
    do: {:ok, %{table: :ets.new(__MODULE__, [:set, :private]), max: max, clock: clock, now: 0}}

  @impl GenServer
  def handle_call({request, %Context{deadline: deadline, owner: owner} = context}, _from, state)
      when is_pid(owner) and node(owner) == node() and is_integer(deadline) do
    with true <- valid_request?(request),
         :ok <- check_live(context),
         {:ok, now} <- read_clock(state) do
      state = %{state | now: max(state.now, now)}
      reply = if check_live(context) == :ok, do: perform(request, state), else: {:error, :timeout}
      {:reply, reply, state}
    else
      {:error, :timeout} -> {:reply, {:error, :timeout}, state}
      _ -> {:reply, {:error, :failure}, state}
    end
  end

  def handle_call(_, _from, state), do: {:reply, {:error, :failure}, state}

  defp valid_request?({:reserve, record}), do: Record.valid?(record)

  defp valid_request?({:store, reservation, response}),
    do: Idempotency.valid_reservation?(reservation) and Idempotency.response?(response)

  defp valid_request?({:sweep, now}), do: is_integer(now) and now in 0..253_402_300_799
  defp valid_request?(_), do: false

  defp check_live(context) do
    if Context.remaining(context) > 0 and Process.alive?(context.owner),
      do: :ok,
      else: {:error, :timeout}
  end

  defp read_clock(state) do
    case state.clock.() do
      now when is_integer(now) and now in 0..253_402_300_799 -> {:ok, now}
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp perform({:reserve, record}, %{now: now})
       when record.now > now or record.lease_until <= now or record.retain_until <= now,
       do: :expired

  defp perform({:reserve, %Record{} = record}, %{table: table, max: max, now: now}) do
    key = Record.key(record)
    fingerprint = record.fingerprint

    case live_row(table, key, now) do
      [{^key, _, other, _, _}] when other != fingerprint ->
        :conflict

      [{^key, _, ^fingerprint, _, {:stored, response}}] ->
        {:stored, response}

      [{^key, _, ^fingerprint, lease_end, _}] when lease_end > now ->
        :in_progress

      [{^key, retain_until, ^fingerprint, _, _}] ->
        insert(table, record, key, max(retain_until, record.retain_until))

      [] ->
        if :ets.info(table, :size) < max,
          do: insert(table, record, key, record.retain_until),
          else: {:error, :full}
    end
  end

  defp perform(
         {:store, %Reservation{record: record, token: token}, response},
         %{table: table, now: now}
       ) do
    key = Record.key(record)
    fingerprint = record.fingerprint

    case :ets.lookup(table, key) do
      [{^key, retention, ^fingerprint, lease_end, {:pending, ^token}}]
      when now < retention and now < lease_end ->
        :ets.insert(table, {key, retention, fingerprint, lease_end, {:stored, response}})
        :stored

      _ ->
        :not_reserved
    end
  end

  defp perform({:sweep, cutoff}, %{table: table, now: now}) when cutoff <= now do
    {:ok,
     :ets.select_delete(table, [{{:_, :"$1", :_, :_, :_}, [{:"=<", :"$1", cutoff}], [true]}])}
  end

  defp perform({:sweep, _}, _), do: {:error, :failure}

  defp live_row(table, key, now) do
    case :ets.lookup(table, key) do
      [{^key, retention, _, _, _}] when retention <= now ->
        :ets.delete(table, key)
        []

      row ->
        row
    end
  end

  defp insert(table, record, key, retention) do
    token = :crypto.strong_rand_bytes(16)

    :ets.insert(
      table,
      {key, retention, record.fingerprint, record.lease_until, {:pending, token}}
    )

    {:reserved, token}
  end

  defp call(pid, request, %Context{deadline: deadline, owner: owner} = context)
       when is_pid(pid) and is_pid(owner) and node(owner) == node() and is_integer(deadline) do
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
