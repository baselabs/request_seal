defmodule RequestSeal.ReplayPairTest do
  use ExUnit.Case, async: false

  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay
  alias RequestSeal.Replay.{Claim, ETS, Error, Pair}

  # Every completed operation uses a real store. The wrapper controls when
  # the adapter reaches the store or returns its reply.
  defmodule ControlledETS do
    @moduledoc false
    @behaviour RequestSeal.Replay

    @impl true
    def claim({pid, mode}, claim, context),
      do: control(mode, context, fn -> ETS.claim(pid, claim, context) end)

    @impl true
    def sweep({pid, mode}, now, context),
      do: control(mode, context, fn -> ETS.sweep(pid, now, context) end)

    defp control(:immediate, _, operation), do: operation.()

    defp control(:late, context, operation) do
      result = operation.()
      Process.sleep(Context.remaining(context) + 5)
      result
    end

    defp control({:blocked, observer}, _, operation) do
      send(observer, {:blocked, self()})

      receive do
        :continue -> operation.()
      end
    end
  end

  setup do
    {:ok, destination} = ETS.start_link(max_entries: 100)
    {:ok, retiring} = ETS.start_link(max_entries: 100)
    destination = ETS.store(destination)
    retiring = ETS.store(retiring)
    {:ok, pair} = Pair.store(destination, retiring)
    claim = %Claim{namespace: "requests", key: "nonce", retain_until: 2_000}

    %{destination: destination, retiring: retiring, pair: pair, claim: claim}
  end

  test "concurrent claims have one winner and are present in both stores", ctx do
    results =
      1..16
      |> Task.async_stream(fn _ -> claim(ctx.pair, ctx.claim) end)
      |> Enum.frequencies()

    assert results == %{{:ok, :claimed} => 1, {:ok, :already_claimed} => 15}
    assert :already_claimed = claim(ctx.destination, ctx.claim)
    assert :already_claimed = claim(ctx.retiring, ctx.claim)
  end

  test "destination duplicates short circuit and retiring duplicates keep the destination claim",
       ctx do
    assert :claimed = claim(ctx.destination, ctx.claim)
    assert :already_claimed = claim(ctx.pair, ctx.claim)
    assert :claimed = claim(ctx.retiring, ctx.claim)

    prior = %{ctx.claim | key: "prior"}
    assert :claimed = claim(ctx.retiring, prior)
    assert :already_claimed = claim(ctx.pair, prior)
    assert :already_claimed = claim(ctx.destination, prior)
  end

  test "unavailable stores fail closed and a destination write remains spent", ctx do
    GenServer.stop(ctx.retiring.ref)
    assert {:error, %Error{reason: :store_unavailable}} = claim(ctx.pair, ctx.claim)
    assert :already_claimed = claim(ctx.destination, ctx.claim)

    GenServer.stop(ctx.destination.ref)
    assert {:error, %Error{reason: :store_unavailable}} = claim(ctx.pair, ctx.claim)
  end

  test "a full retiring store fails closed", ctx do
    {:ok, small} = ETS.start_link(max_entries: 1)
    small = ETS.store(small)
    assert :claimed = claim(small, %{ctx.claim | key: "occupant"})
    assert {:ok, pair} = Pair.store(ctx.destination, small)
    assert {:error, %Error{reason: :store_full}} = claim(pair, ctx.claim)
    assert :already_claimed = claim(ctx.destination, ctx.claim)
  end

  test "sweep combines counts at the exclusive end, including after one store fails", ctx do
    assert :claimed = claim(ctx.pair, ctx.claim)
    assert {:ok, 0} = Pair.sweep(ctx.pair.ref, 1_999, context(1_000))
    assert {:ok, 2} = Pair.sweep(ctx.pair.ref, 2_000, context(1_000))
    assert {:error, %Error{reason: :store_failed}} = claim(ctx.pair, ctx.claim)
    assert :claimed = claim(ctx.pair, %{ctx.claim | retain_until: 2_001})

    GenServer.stop(ctx.destination.ref)
    assert {:error, :unavailable} = Pair.sweep(ctx.pair.ref, 2_000, context(1_000))
    assert {:ok, 0} = ETS.sweep(ctx.retiring.ref, 2_000)
  end

  test "invalid pairs, malformed operations and expired budgets refuse", ctx do
    for {left, right} <- [
          {ctx.destination, ctx.destination},
          {ctx.pair, ctx.retiring},
          {ctx.destination, ctx.pair},
          {nil, ctx.retiring}
        ] do
      assert {:error, %Error{reason: :invalid_store}} = Pair.store(left, right)
    end

    assert {:error, :failure} = Pair.claim(ctx.pair.ref, nil, context(1_000))
    assert {:error, :failure} = Pair.sweep(ctx.pair.ref, -1, context(1_000))
    assert {:error, :timeout} = Pair.claim(ctx.pair.ref, ctx.claim, context(-1))
    assert {:error, :timeout} = Pair.sweep(ctx.pair.ref, 2_000, context(-1))
    assert :claimed = claim(ctx.destination, ctx.claim)
  end

  test "malformed contexts refuse before either store is called", ctx do
    assert :claimed = claim(ctx.pair, ctx.claim)
    other = %{ctx.claim | key: "other"}
    valid = context(1_000)

    for invalid <- [%Context{}, %{valid | owner: nil}, %{valid | deadline: :invalid}] do
      assert {:error, :failure} = Pair.claim(ctx.pair.ref, other, invalid)
      assert {:error, :failure} = Pair.sweep(ctx.pair.ref, 2_000, invalid)
    end

    for store <- [ctx.destination, ctx.retiring] do
      assert :already_claimed = claim(store, ctx.claim)
      assert :claimed = claim(store, other)
    end
  end

  test "expiry between writes leaves the first claim spent", ctx do
    late = controlled(ctx.destination, :late)
    {:ok, pair} = Pair.store(late, ctx.retiring)

    assert {:error, :timeout} = Pair.claim(pair.ref, ctx.claim, context(100))
    assert :already_claimed = claim(ctx.destination, ctx.claim)
    assert :claimed = claim(ctx.retiring, ctx.claim)
  end

  test "late final claim and sweep replies cannot report success", ctx do
    destination = controlled(ctx.destination, :immediate)
    retiring = controlled(ctx.retiring, :late)
    assert {:error, %Error{reason: :invalid_store}} = Pair.store(ctx.destination, retiring)
    assert {:ok, pair} = Pair.store(destination, retiring)

    assert {:error, :timeout} = Pair.claim(pair.ref, ctx.claim, context(100))
    assert :already_claimed = claim(ctx.destination, ctx.claim)
    assert :already_claimed = claim(ctx.retiring, ctx.claim)

    assert {:error, :timeout} = Pair.sweep(pair.ref, 2_000, context(100))

    for store <- [ctx.destination, ctx.retiring] do
      assert {:error, %Error{reason: :store_failed}} = claim(store, ctx.claim)
      assert :claimed = claim(store, %{ctx.claim | retain_until: 2_001})
    end
  end

  test "direct claims and sweeps cancel a blocked adapter inside the deadline", ctx do
    retiring = controlled(ctx.retiring, {:blocked, self()})
    assert {:ok, pair} = Pair.store(controlled(ctx.destination, :immediate), retiring)

    assert_bounded_timeout(fn -> Pair.claim(pair.ref, ctx.claim, context(150)) end)
    assert_received {:blocked, claim_worker}
    refute Process.alive?(claim_worker)
    assert :already_claimed = claim(ctx.destination, ctx.claim)
    assert :claimed = claim(ctx.retiring, ctx.claim)

    assert_bounded_timeout(fn -> Pair.sweep(pair.ref, 2_000, context(150)) end)
    assert_received {:blocked, sweep_worker}
    refute Process.alive?(sweep_worker)
    assert {:error, %Error{reason: :store_failed}} = claim(ctx.destination, ctx.claim)
    assert :claimed = claim(ctx.destination, %{ctx.claim | retain_until: 2_001})
    assert :already_claimed = claim(ctx.retiring, ctx.claim)
  end

  test "direct operations bound synchronous telemetry and preserve completed writes", ctx do
    event = [:request_seal, :replay, :pair]
    id = make_ref()

    handler = fn
      _, _, %{operation: operation, position: :retiring}, observer ->
        send(observer, {:telemetry_blocked, operation, self()})

        receive do
          :continue -> :ok
        end

      _, _, _, _ ->
        :ok
    end

    :ok = :telemetry.attach(id, event, handler, self())
    on_exit(fn -> :telemetry.detach(id) end)

    assert_bounded_timeout(fn -> Pair.claim(ctx.pair.ref, ctx.claim, context(150)) end)
    assert_received {:telemetry_blocked, :claim, claim_worker}
    refute Process.alive?(claim_worker)
    assert :already_claimed = claim(ctx.destination, ctx.claim)
    assert :already_claimed = claim(ctx.retiring, ctx.claim)

    assert_bounded_timeout(fn -> Pair.sweep(ctx.pair.ref, 2_000, context(150)) end)
    assert_received {:telemetry_blocked, :sweep, sweep_worker}
    refute Process.alive?(sweep_worker)

    for store <- [ctx.destination, ctx.retiring] do
      assert {:error, %Error{reason: :store_failed}} = claim(store, ctx.claim)
      assert :claimed = claim(store, %{ctx.claim | retain_until: 2_001})
    end
  end

  defp assert_bounded_timeout(operation) do
    task =
      Task.async(fn ->
        started = System.monotonic_time(:millisecond)
        result = operation.()
        {result, System.monotonic_time(:millisecond) - started}
      end)

    assert {{:error, :timeout}, elapsed} = Task.await(task, 1_500)
    assert elapsed < 1_000
  end

  defp controlled(store, mode), do: %{store | adapter: ControlledETS, ref: {store.ref, mode}}

  defp claim(store, claim), do: Replay.claim(store, claim, timeout: 1_000)

  defp context(ms),
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + ms}
end
