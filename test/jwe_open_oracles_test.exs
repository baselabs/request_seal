defmodule RequestSeal.JWEOpenOraclesTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.JWE.{Bounds, Coordinator, Guard, Open}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime
  @moduletag timeout: 600_000

  defp trace_guard do
    for function <- [:check, :kill, :receive_one, :finish] do
      arity = if function == :kill, do: 3, else: 1
      :erlang.trace_pattern({Guard, function, arity},
        [{:_, [], [{:message, {:process_dump}}, {:return_trace}]}], [:local])
    end
  end
  defp untrace_guard do
    for function <- [:check, :kill, :receive_one, :finish] do
      :erlang.trace_pattern({Guard, function, if(function == :kill, do: 3, else: 1)}, false, [:local])
    end
  end
  defp reductions(dump) do
    case Regex.run(~r/Reductions:\s*(\d+)/i, to_string(dump)) do
      [_, n] -> String.to_integer(n)
      _ -> flunk("guard reduction dump unavailable")
    end
  end
  defp guard_calls(events, pid, function) do
    for {:trace_ts, ^pid, :call, {Guard, ^function, _}, dump, _} <- Enum.reverse(events), do: reductions(dump)
  end

  test "oracle 1 constant guard reaction before kill with queued notices" do
    Runtime.with_peer(fn ->
      trace_guard()
      try do
        samples = for n <- [1, 10_000], topology <- [:resolvers, :queued] do
          s = Runtime.start(n, topology)
          :erlang.trace(s.guard, true, [:call])
          if topology != :queued, do: :erlang.suspend_process(s.guard)
          :erlang.trace_pattern({Guard, :kill, 3}, true, [:call_count])
          before_trigger = Runtime.info(s.guard, :reductions)
          try do
            result = Runtime.trigger(%{s | topology: :queued}, :caller)
            checks = guard_calls(result.events, s.guard, :check)
            kills = guard_calls(result.events, s.guard, :kill)
            receives = guard_calls(result.events, s.guard, :receive_one)
            assert :erlang.trace_info({Guard, :kill, 3}, :call_count) == {:call_count, 1},
              "one trigger causes exactly one kill"
            :erlang.trace_pattern({Guard, :kill, 3}, false, [:call_count])
            assert kills != [] and receives != [], "reaction interval must include a kill"
            before_kill = List.last(Enum.filter(checks, &(&1 <= hd(kills))))
            after_kill = Enum.find(receives, &(&1 >= hd(kills)))
            assert is_integer(before_kill) and is_integer(after_kill)
            {n, topology, after_kill - before_trigger}
          after
            Runtime.cleanup(s)
          end
        end
        for topology <- [:resolvers, :queued] do
          [{_, _, a}, {_, _, b}] = Enum.filter(samples, &(elem(&1, 1) == topology))
          assert a == b, "guard reaction must be constant before kill"
        end
      after
        untrace_guard()
      end
    end)
  end

  test "oracle 2 complete topology and linear teardown in isolated peer" do
    Runtime.with_peer(fn ->
      trace_guard()
      for topology <- [:resolvers, :queued, :custody] do
        samples = for n <- [1, 1_000, 10_000] do
          s = Runtime.start(n, topology)
          :erlang.trace(s.guard, true, [:call])
          try do
            result = Runtime.trigger(s, :caller)
            finishes = guard_calls(result.events, s.guard, :finish)
            kills = guard_calls(result.events, s.guard, :kill)
            assert finishes != [] and kills != [], "guard reductions need both endpoints"
            guard_work = hd(finishes) - hd(kills)
            assert Enum.all?(result.pids, fn {_, role} -> role != :other end),
              "every created process must have a registered role"
            assert result.peak <= n + 35, "maximum alive topology is n + 35"
            assert map_size(result.pids) <= 2 * n + 35, "lifetime topology is 2n + 35"
            assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1))), "every created process needs an end marker"
            assert Enum.all?(result.refs, fn {_, ended} -> ended end), "every created process needs an end marker"
            {:measurement, _, _, _, vm} = hd(result.events)
            {n, vm, guard_work}
          after
            Runtime.cleanup(s)
          end
        end
        [{1, base, guard_base} | _] = samples
        for {n, work, guard_work} <- tl(samples) do
          assert work - base <= 256 * (n - 1), "VM teardown must fit a + 256n"
          assert guard_work - guard_base <= 32 * (n - 1), "guard teardown must fit a + 32n"
        end
      end
      untrace_guard()
    end)
  end

  test "oracle 3 guard coordinator and caller queues have bounded terms" do
    Runtime.with_peer(fn ->
      s = Runtime.launch(10_000, :resolvers, near_cap: true, policy: %{key_resolver: fn _ -> :error end})
      try do
        result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
        received = for {:trace_ts, pid, :receive, msg, _} <- result.messages,
          pid in [result.guard, result.coordinator], do: msg
        sent = for {:trace_ts, pid, :send, msg, _, _} <- result.messages,
          pid == s.caller and is_tuple(msg) and tuple_size(msg) > 1 and
          elem(msg, 1) in [:policy, :item, :input], do: msg
        assert received != [] and sent != [], "queue oracle must observe real messages"
        assert Enum.all?(received, &(:erts_debug.flat_size(&1) <= 128)), "library control queue must be constant size"
        assert Enum.all?(sent, &(:erts_debug.flat_size(&1) <= Bounds.item_words() + 32)), "bootstrap messages must be bounded"
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "oracle 4 guard heap stays constant with queued notices after GC" do
    Runtime.with_peer(fn ->
      sizes = for n <- [1, 10_000] do
        s = Runtime.start(n, :custody)
        true = :erlang.suspend_process(s.guard)
        Enum.each(s.custody, &Process.exit(&1, :kill))
        Runtime.await(fn -> Runtime.info(s.guard, :message_queue_len) >= n end)
        try do
          # GC of a suspended target is supported and does not turn sensitivity off.
          true = :erlang.garbage_collect(s.guard)
          size = Runtime.info(s.guard, :total_heap_size)
          assert Runtime.info(s.guard, :message_queue_data) == :off_heap, "guard mailbox must be off heap"
          size
        after
          result = Runtime.trigger(%{s | topology: :queued}, :caller)
          assert Enum.all?(result.refs, fn {_, ended} -> ended end)
          Runtime.cleanup(s)
        end
      end
      assert Enum.uniq(sizes) |> length() == 1, "guard heap must be constant at the cap"
    end)
  end

  test "oracle 5 caller wait ends at F plus B before slow handlers" do
    observer = self()
    id = make_ref()
    :telemetry.attach(id, [:request_seal, :jose, :decrypt_many], fn _, _, _, _ ->
      send(observer, {:handler, Bounds.now()})
      Process.sleep(250)
    end, nil)
    :erlang.trace_pattern({Open, :wait_end, 1}, true, [:local])
    s = Runtime.launch(1, :resolvers, policy: %{timeout: 300, resolve_timeout: 200,
      unwrap_timeout: 50, key_resolver: fn _ -> :error end})
    try do
      result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
      [_, _, _, _, _, _, _, f, _] = Enum.find_value(result.events, fn
        {:spawn, _, _, Guard, :run, args, _} -> args
        _ -> nil
      end)
      stamped = Enum.find_value(result.events, fn
        {:trace_ts, pid, :call, {Open, :wait_end, [at]}, _} when pid == s.caller -> at
        _ -> nil
      end)
      handler_at = Enum.find_value(result.events, fn
        {:handler, at} -> at
        _ -> nil
      end)
      assert is_integer(stamped) and stamped <= f + Bounds.teardown(1),
        "caller wait must end before F plus B and handlers"
      assert handler_at >= stamped
      assert Bounds.now() - handler_at >= 250_000
      assert {:ok, [_]} = result.return
    after
      Runtime.cleanup(s)
      :telemetry.detach(id)
      :erlang.trace_pattern({Open, :wait_end, 1}, false, [:local])
    end
  end

  test "caller bound holds with guard suspended" do
    s = Runtime.start(1, :resolvers, policy: %{timeout: 300, resolve_timeout: 200, unwrap_timeout: 50})
    :erlang.trace_pattern({Open, :wait_end, 1}, [{:_, [], [{:return_trace}]}], [:local])
    :erlang.trace(s.caller, true, [:call])
    true = :erlang.suspend_process(s.guard)
    try do
      s = Runtime.collect_return(s, Bounds.now() + 1_000_000)
      assert {:error, %{reason: :deadline_exceeded}} = s.return, "caller wait must be bounded with guard suspended"
      [_, _, _, _, _, _, _, f, _] = Enum.find_value(s.events, fn
        {:spawn, _, _, Guard, :run, args, _} -> args
        _ -> nil
      end)
      assert Enum.any?(s.events, fn
        {:trace_ts, _, :call, {Open, :wait_end, [at]}, _} -> at <= f + Bounds.teardown(1)
        _ -> false
      end), "wait end must be stamped before cleanup"
    after
      :erlang.trace_pattern({Open, :wait_end, 1}, false, [:local])
      Runtime.cleanup(s)
    end
  end

  test "notices freed at P3 and resolver custody phases do not overlap" do
    Runtime.with_peer(fn ->
      s = Runtime.start(10_000, :custody)
      try do
        assert Enum.all?(s.resolvers, &(not Process.alive?(&1))), "P3 requires every resolver end marker"
        tables = :erlang.system_info(:ets_count) - s.baseline_tables
        assert tables <= s.n + 3, "resolver notices must be freed before P3"
        assert s.peak <= s.n + 35, "maximum alive topology is n + 35"
      after
        Runtime.trigger(s, :caller)
        Runtime.cleanup(s)
      end
    end)
  end
  test "R12-1 callback exit reasons never enter library queues" do
    Runtime.with_peer(fn ->
      s = Runtime.start(1, :resolvers)
      try do
        reason = {:caller_failure, List.duplicate(<<0>>, 1_000_000)}
        Process.exit(hd(s.resolvers), reason)
        s = Runtime.collect_until(s, fn current -> Enum.any?(current.messages, fn
          {:trace_ts, pid, :receive, {_, :ended, {:resolver, 0}}, _} -> pid == current.coordinator
          _ -> false
        end) end)
        s = Runtime.trigger(s, :caller)
        for {:trace_ts, pid, :receive, message, _} <- s.messages,
            pid in [s.guard, s.coordinator] do
          assert :erts_debug.flat_size(message) <= 128,
            "caller reason must not enter a library queue"
        end
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "19 every coordinator expiry and dead worker pass is linear" do
    Runtime.with_peer(fn ->
      for {function, topology} <- [{:expire_r, :resolvers}, {:expire_u, :custody},
                                   {:deadline, :resolvers}, {:worker_down, :resolvers}] do
        arity = if function == :worker_down, do: 3, else: 1
        :erlang.trace_pattern({Coordinator, function, arity},
          [{:_, [], [{:message, {:process_dump}}]}], [:local])
        :erlang.trace_pattern({Coordinator, :loop, 1},
          [{:_, [], [{:message, {:process_dump}}]}], [:local])
        :erlang.trace_pattern({Coordinator, :finish, 1},
          [{:_, [], [{:message, {:process_dump}}]}], [:local])
        try do
          samples = for n <- [1, 1_000, 10_000] do
            s = Runtime.start(n, topology, policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 2_000})
            :erlang.trace(s.coordinator, true, [:call, :arity])
            try do
              if function == :expire_u do
                for {pid, :worker} <- s.pids, do: :erlang.suspend_process(pid)
              end
              if function == :deadline, do: hold_until_d(s)
              if function == :worker_down do
                {pid, _} = Enum.find(s.pids, fn {_, role} -> role == :worker end)
                Process.exit(pid, :kill)
              end
              observed = Runtime.collect_until(s, fn current -> pass_interval(current.events, function) != nil end)
              work = pass_interval(observed.events, function)
              {n, work}
            after
              Runtime.cleanup(s)
            end
          end
          [{1, base} | rest] = samples
          for {n, work} <- rest do
            assert work - base <= 512 * (n - 1), "coordinator passes must fit a + 512n"
          end
        after
          :erlang.trace_pattern({Coordinator, function, arity}, false, [:local])
          :erlang.trace_pattern({Coordinator, :loop, 1}, false, [:local])
          :erlang.trace_pattern({Coordinator, :finish, 1}, false, [:local])
        end
      end
    end)
  end

  defp pass_interval(events, function) do
    events |> Enum.reverse() |> Enum.reduce({nil, nil}, fn
      {:trace_ts, _, :call, {Coordinator, ^function, _}, dump, _}, {nil, _} -> {reductions(dump), nil}
      {:trace_ts, _, :call, {Coordinator, next, _}, dump, _}, {start, nil}
          when is_integer(start) and next in [:loop, :finish] ->
        {start, reductions(dump) - start}
      _, acc -> acc
    end) |> elem(1)
  end

  test "29 caller death during D settlement and reply sends ends every child" do
    Runtime.with_peer(fn ->
      for function <- [:fill_deadline, :settled_messages, :group_messages, :reply] do
        arity = if function in [:reply, :group_messages], do: 2, else: 3
        :erlang.trace_pattern({Coordinator, function, arity}, true, [:local])
        s = Runtime.start(10_000, :resolvers, policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 2_000})
        :erlang.trace(s.coordinator, true, [:call, :arity])
        try do
          hold_until_d(s)
          s = Runtime.collect_until(s, fn current -> Enum.any?(current.events, fn
            {:trace_ts, _, :call, {Coordinator, ^function, _}, _} -> true
            _ -> false
          end) end)
          result = Runtime.trigger(s, :caller)
          assert Enum.all?(result.refs, fn {_, ended} -> ended end), "terminal steps must end every created process"
          assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
        after
          :erlang.trace_pattern({Coordinator, function, arity}, false, [:local])
          Runtime.cleanup(s)
        end
      end
    end)
  end

  defp hold_until_d(s) do
    d = Enum.find_value(s.events, fn
      {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
      _ -> nil
    end)
    true = :erlang.suspend_process(s.coordinator)
    Process.sleep(Bounds.remaining(d))
    :erlang.resume_process(s.coordinator)
  end

  test "R12-4 D at cap sweeps even on replied end" do
    Runtime.with_peer(fn ->
      s = Runtime.start(10_000, :resolvers,
        policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 2_000})
      try do
        hold_until_d(s)
        result = Runtime.collect_until(s, & &1.guard_ended) |> Runtime.delivered()
        assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1))),
          "D reply must still sweep every child"
        assert Enum.all?(result.refs, fn {_, ended} -> ended end),
          "D reply must still sweep every child"
        result = Runtime.collect_return(result, Bounds.now() + 1_000_000)
        assert {:ok, entries} = result.return
        assert length(entries) == 10_000
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "notice delete call precedes each ended forward in production" do
    Runtime.with_peer(fn ->
      :erlang.trace_pattern({:ets, :delete, 1}, true, [])
      s = Runtime.start(1_000, :custody)
      try do
        {_pending, count} = s.events |> Enum.reverse() |> Enum.reduce({%{}, 0}, fn
          {:received, pid, {:'ETS-TRANSFER', tid, _, {_, :slot, slot}}}, {pending, n} when pid == s.guard ->
            {Map.put(pending, slot, {tid, false}), n}
          {:trace_ts, pid, :call, {:ets, :delete, [tid]}, _}, {pending, n} when pid == s.guard ->
            {Map.new(pending, fn {slot, {table, deleted}} -> {slot, {table, deleted or table == tid}} end), n}
          {:trace_ts, pid, :send, {_, :ended, slot}, _, _}, {pending, n} when pid == s.guard ->
            assert match?({_, true}, pending[slot]), "notice deletion must precede ended forward"
            {Map.delete(pending, slot), n + 1}
          _, state -> state
        end)
        assert count == 1_000, "every resolver notice needs an ordered deletion"
      after
        Runtime.trigger(s, :caller)
        Runtime.cleanup(s)
        :erlang.trace_pattern({:ets, :delete, 1}, false, [])
      end
    end)
  end

end
