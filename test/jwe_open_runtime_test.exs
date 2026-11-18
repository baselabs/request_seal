defmodule RequestSeal.JWEOpenRuntimeTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.JWE.Bounds
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime

  test "end timestamps precede delayed observation for ordinary and sensitive children" do
    Runtime.with_peer(fn ->
      s = Runtime.start(1, :resolvers, trace_input: false, trace_messages: false)

      try do
        s = Runtime.quiet(s)
        {:flags, flags} = :erlang.trace_info(s.guard, :flags)
        refute :receive in flags
        {:flags, flags} = :erlang.trace_info(s.coordinator, :flags)
        refute :send in flags
        refute :receive in flags
        Process.exit(s.caller, :kill)
        Runtime.await(fn -> Enum.all?(Map.keys(s.pids), &(not Process.alive?(&1))) end)
        Process.sleep(30)
        dequeue_at = Bounds.now()
        result = Runtime.collect_ends(s)
        assert result.remaining == 0
        assert map_size(result.ends) == map_size(result.pids)

        for {:end, pid, at, _} <- result.events do
          assert at < dequeue_at, "observer backlog must not become process lifetime"
          assert Map.has_key?(result.pids, pid)
        end

        assert Enum.any?(result.events, &match?({:end, pid, _, _} when pid == s.guard, &1))
        resolver = hd(s.resolvers)
        assert Enum.any?(result.events, &match?({:end, ^resolver, _, _}, &1))
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "the caller stamps its return before the observer collects it" do
    Runtime.with_peer(fn ->
      s = Runtime.start(1, :resolvers)

      try do
        Enum.each(s.resolvers, &send(&1, :continue))
        Runtime.await(fn -> not Process.alive?(s.caller) end)
        dequeue_at = Bounds.now()
        result = Runtime.collect_return(s)
        assert {:ok, [{:ok, %{plaintext: "payload"}}]} = result.return
        assert result.return_at < dequeue_at
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "an unended birth consumes the collection cap without claiming an end" do
    Runtime.with_peer(fn ->
      s = Runtime.start(1, :resolvers)

      try do
        result = Runtime.collect_ends(s, Bounds.now() + 1_000)
        assert result.remaining > 0
        refute is_map_key(result.ends, hd(s.resolvers))
      after
        Runtime.cleanup(s)
      end
    end)
  end
end
