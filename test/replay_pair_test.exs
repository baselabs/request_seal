defmodule RequestSeal.ReplayPairTest do
  use ExUnit.Case, async: true

  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay
  alias RequestSeal.Replay.{Claim, ETS, Error, Pair}

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

  test "destination duplicates short circuit and retiring duplicates keep the destination claim", ctx do
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
    assert :claimed = claim(ctx.pair, ctx.claim)

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

  defp claim(store, claim), do: Replay.claim(store, claim, timeout: 1_000)

  defp context(ms),
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + ms}
end
