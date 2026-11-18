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

  test "cleanup joins the end observer and destroys its trace session" do
    Runtime.with_peer(fn ->
      s = Runtime.start(1, :resolvers)
      tracer = s.end_tracer
      assert Process.alive?(tracer)
      Runtime.cleanup(s)
      refute Process.alive?(tracer)

      assert_raise ArgumentError, fn ->
        :trace.process(s.end_session, self(), true, [:receive])
      end

      for pid <- Map.keys(s.pids) ++ [s.caller], do: refute(Process.alive?(pid))
    end)
  end

  test "failed placement releases the key processes and end trace session" do
    Runtime.with_peer(fn ->
      baseline = MapSet.new(Process.list())
      sessions = :trace.session_info(:all)

      assert_raise CaseClauseError, fn ->
        Runtime.start(1, :invalid_topology)
      end

      assert :trace.session_info(:all) == sessions
      assert MapSet.new(Process.list()) == baseline
    end)
  end

  test "placement collectors cannot extend their cap with queued events" do
    Runtime.with_peer(fn ->
      s = Runtime.start(1, :resolvers)

      try do
        send(self(), :queued_event)
        assert_raise RuntimeError, ~r/placement\/end markers missing/, fn ->
          Runtime.collect_until(s, fn _ -> false end, 0)
        end

        assert :queued_event in elem(Process.info(self(), :messages), 1)

        assert_raise RuntimeError, "placement event missing", fn ->
          Runtime.receive_event(s, fn _ -> false end, Bounds.now())
        end

        assert_received :queued_event
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
