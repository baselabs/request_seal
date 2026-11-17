defmodule RequestSeal.JWEOpenBootstrapTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.JWE.{Bounds, Guard}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime
  @moduletag timeout: 600_000

  defp arguments(s) do
    Enum.find_value(s.events, fn
      {:spawn, _, _, Guard, :run, args, _} -> args
      _ -> nil
    end)
  end
  defp inputs(s) do
    for {:trace_ts, pid, :send, message, _, stamp} <- s.messages,
      pid == s.caller, is_tuple(message), tuple_size(message) > 1,
      elem(message, 1) in [:policy, :item, :input], do: {message, stamp}
  end

  test "input stop flag bounds remaining bootstrap sends at the cap" do
    Runtime.with_peer(fn ->
      s = Runtime.launch(10_000, :resolvers, near_cap: true,
        policy: %{timeout: 300_000, algorithms: ["invalid"]})
      try do
        s = Runtime.collect_until(s, &(arguments(&1) != nil))
        [_, _, _, flag | _] = arguments(s)
        s = Runtime.collect_until(s, fn _ -> :atomics.get(flag, 1) == 1 end)
        observed = Bounds.now()
        s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
        after_stop = for {{_, :item, _, _, _, _}, stamp} <- inputs(s),
          :erlang.convert_time_unit(stamp, :native, :microsecond) >= observed, do: stamp
        assert length(after_stop) <= 1, "caller must read the input stop flag"
        assert {:error, %{reason: :invalid_policy}} = s.return
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "single policy carries no expected and keeps both word bounds" do
    {handle, _} = Runtime.real_key()
    padding = List.duplicate(0, 1_850)
    callback = fn _ ->
      Process.put(:policy_environment, padding)
      {:ok, %{algorithm: "A256KW", key: handle}}
    end
    s = Runtime.launch(1, :resolvers, single: true, near_cap: true,
      policy: %{key_resolver: callback})
    try do
      s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
      messages = inputs(s)
      policy = Enum.find_value(messages, fn
        {{_, :policy, value}, _} -> value
        _ -> nil
      end)
      assert policy != nil, "single policy must not carry expected"
      refute Map.has_key?(policy.protected, :expected), "single policy must not carry expected"
      assert Enum.all?(messages, fn {message, _} ->
        :erts_debug.flat_size(message) <= Bounds.policy_words() + 32
      end), "bootstrap messages must be bounded"
      assert {:ok, _} = s.return
    after
      Runtime.cleanup(s)
      RequestSeal.Custody.release(handle)
    end
  end

  test "bounded bootstrap at cap retains small item decisions" do
    Runtime.with_peer(fn ->
      s = Runtime.launch(10_000, :resolvers, near_cap: true,
        policy: %{timeout: 300_000, key_resolver: fn _ -> :error end})
      try do
        s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
        assert {:ok, results} = s.return
        assert length(results) == 10_000
        assert Enum.all?(results, &match?({:error, %{reason: :unknown_key}}, &1)),
          "near cap expected must preserve small item outcomes"
        assert Enum.all?(inputs(s), fn {message, _} ->
          :erts_debug.flat_size(message) <= Bounds.item_words() + 32
        end), "bootstrap messages must be bounded"
      after
        Runtime.cleanup(s)
      end
    end)
  end
  test "oversized expected is marked before copying or UTF-8 work" do
    expected = %{"x" => :binary.copy("x", 64_000_000)}
    s = Runtime.launch(1, :resolvers, items: [%{token: "", expected: expected}])
    try do
      s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
      item = Enum.find_value(inputs(s), fn
        {{_, :item, 0, :exact, "", value}, _} -> value
        _ -> nil
      end)
      assert item == :oversized, "expected binary bytes must be bounded before copying"
      assert {:ok, [{:error, %{reason: :invalid_policy}}]} = s.return
    after
      Runtime.cleanup(s)
    end
  end

  test "three ms bounded bootstrap accepts cardinality and sends at most one item after D" do
    Runtime.with_peer(fn ->
      :erlang.trace_pattern({Guard, :stop_at, 2}, [{:_, [], [{:return_trace}]}], [:local])
      try do
        short_bootstrap(20)
      after
        :erlang.trace_pattern({Guard, :stop_at, 2}, false, [:local])
      end
    end)
  end

  defp short_bootstrap(0), do: flunk("no cardinality accepted within the 3 ms placement")
  defp short_bootstrap(attempts) do
    s = Runtime.launch(10_000, :resolvers, near_cap: true,
      policy: %{timeout: 3, resolve_timeout: 1, unwrap_timeout: 1})
    result = try do
      result = Runtime.collect_return(s, Bounds.now() + 1_000_000) |> Runtime.delivered()
      [_, _, _, flag, _, _, d | _] = arguments(result)
      if :atomics.get(flag, 2) == 10_000 do
        assert {:ok, entries} = result.return
        assert length(entries) == 10_000, "D must preserve accepted cardinality"
        assert Enum.all?(entries, &match?({:error, %{reason: :deadline_exceeded, layer: :crypto}}, &1))
        late = for {{_, :item, _, _, _, _}, stamp} <- inputs(result),
          :erlang.convert_time_unit(stamp, :native, :microsecond) >= d, do: stamp
        assert length(late) <= 1, "bootstrap must checkpoint before each item"
        assert Enum.any?(result.events, fn
          {:trace_ts, pid, :return_from, {Guard, :stop_at, 2}, at, _} ->
            pid == result.guard and at == d + Bounds.teardown(10_000)
          _ -> false
        end), "accepted cardinality must size the guard bound before preflight ok"
        :ok
      else
        :retry
      end
    after
      Runtime.cleanup(s)
    end
    if result == :retry, do: short_bootstrap(attempts - 1), else: result
  end
end
