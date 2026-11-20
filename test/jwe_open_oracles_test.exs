defmodule RequestSeal.JWEOpenOraclesTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.JWE.{Bounds, Coordinator, Guard, Open, Worker}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime
  @moduletag timeout: 600_000

  defp trace_guard(functions) do
    for function <- functions do
      arity = if function == :kill, do: 3, else: 1

      :erlang.trace_pattern(
        {Guard, function, arity},
        [{:_, [], [{:message, {:process_dump}}, {:return_trace}]}],
        [:local]
      )
    end
  end

  defp untrace_guard do
    for function <- [:check, :kill, :receive_one, :finish] do
      :erlang.trace_pattern({Guard, function, if(function == :kill, do: 3, else: 1)}, false, [
        :local
      ])
    end
  end

  defp reductions(dump) do
    case Regex.run(~r/Reductions:\s*(\d+)/i, to_string(dump)) do
      [_, n] -> String.to_integer(n)
      _ -> flunk("guard reduction dump unavailable")
    end
  end

  defp guard_calls(events, pid, function) do
    for {:trace_ts, ^pid, :call, {Guard, ^function, _}, dump, _} <- Enum.reverse(events),
        do: reductions(dump)
  end

  test "oracle 1 constant guard reaction before kill with queued notices" do
    Runtime.with_peer(fn ->
      samples =
        for n <- [1, 10_000], topology <- [:resolvers, :queued] do
          s = Runtime.start(n, topology, trace_input: false)
          if topology != :queued, do: :erlang.suspend_process(s.guard)

          try do
            assert Runtime.info(s.guard, :current_function) == {Guard, :receive_one, 1},
                   "reaction must start from the same blocked receive"

            # Join caller death before resuming the guard. Otherwise it may
            # legitimately process any number of notices before the trigger.
            Process.exit(s.caller, :kill)

            s =
              Runtime.collect_event(s, fn
                {:DOWN, ref, :process, pid, _} -> ref == s.monitor and pid == s.caller
                _ -> false
              end)

            notice =
              Enum.find_value(s.events, fn
                {:received, pid, {:"ETS-TRANSFER", table, _, {_, :caller}}}
                when pid == s.caller ->
                  table

                _ ->
                  nil
              end)

            assert :ets.info(notice, :owner) == s.guard,
                   "reaction must begin after the caller notice owner flip"

            trace_guard([:kill])
            # This entry follows kill's return, before another dequeue or
            # owner read. Matching the state excludes the later sweep.
            :erlang.trace_pattern(
              {Guard, :receive_one, 1},
              [
                {[%{cause: :caller_gone, ended_at: nil}], [], [{:message, {:process_dump}}]}
              ],
              [:local]
            )

            :erlang.trace(s.guard, true, [:call])

            :erlang.trace_pattern(
              {Guard, :kill, 3},
              [{:_, [], [{:message, {:process_dump}}, {:return_trace}]}],
              [:local, :call_count]
            )

            before_trigger = Runtime.info(s.guard, :reductions)
            result = Runtime.trigger(%{s | topology: :queued}, :d)
            kills = guard_calls(result.events, s.guard, :kill)
            receives = guard_calls(result.events, s.guard, :receive_one)

            assert :erlang.trace_info({Guard, :kill, 3}, :call_count) == {:call_count, 1},
                   "one trigger causes exactly one kill"

            :erlang.trace_pattern({Guard, :kill, 3}, false, [:call_count])
            assert kills != [], "reaction interval must include a kill"
            after_kill = Enum.find(receives, &(&1 >= hd(kills)))
            assert is_integer(after_kill), "reaction must end before the sweep"
            {n, topology, after_kill - before_trigger}
          after
            :erlang.trace_pattern({Guard, :kill, 3}, false, [:call_count])
            untrace_guard()
            Runtime.cleanup(s)
          end
        end

      for topology <- [:resolvers, :queued] do
        [{_, _, a}, {_, _, b}] = Enum.filter(samples, &(elem(&1, 1) == topology))
        assert a == b, "guard reaction must be constant before kill"
      end
    end)
  end

  test "oracle 2 complete topology and linear teardown in isolated peer" do
    Runtime.with_peer(fn ->
      for topology <- [:resolvers, :queued, :custody] do
        samples =
          for n <- [1, 1_000, 10_000] do
            s = Runtime.start(n, topology, trace_input: false)
            # Setup has already reached P2/P3. Only the two measured endpoints
            # need dumps; dumping every check while 10,000 notices are queued
            # would measure the tracer's work as part of the topology.
            trace_guard([:kill, :finish])
            :erlang.trace(s.guard, true, [:call])

            try do
              result = Runtime.trigger(s, :caller)

              assert result.guard_ended and not Process.alive?(result.guard),
                     "VM teardown must fit a + 256n: guard incomplete at the collection hang cap"

              finishes = guard_calls(result.events, s.guard, :finish)
              kills = guard_calls(result.events, s.guard, :kill)
              assert finishes != [] and kills != [], "guard reductions need both endpoints"
              guard_work = hd(finishes) - hd(kills)

              assert Enum.all?(result.pids, fn {_, role} -> role != :other end),
                     "every created process must have a registered role"

              assert result.peak <= n + 35, "maximum alive topology is n + 35"
              assert map_size(result.pids) <= 2 * n + 35, "lifetime topology is 2n + 35"

              assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1))),
                     "every created process needs an end marker"

              assert Enum.all?(result.refs, fn {_, ended} -> ended end),
                     "every created process needs an end marker"

              {:measurement, _, _, _, vm} = hd(result.events)
              {n, vm, guard_work}
            after
              untrace_guard()
              Runtime.cleanup(s)
            end
          end

        [{1, base, guard_base} | _] = samples

        for {n, work, guard_work} <- tl(samples) do
          assert work - base <= 256 * (n - 1), "VM teardown must fit a + 256n"

          assert guard_work - guard_base <= 32 * (n - 1),
                 "guard teardown must fit a + 32n: #{inspect({topology, samples})}"
        end
      end
    end)
  end

  test "oracle 3 guard coordinator and caller queues have bounded terms" do
    Runtime.with_peer(fn ->
      s =
        Runtime.launch(10_000, :resolvers,
          near_cap: true,
          policy: %{key_resolver: fn _ -> :error end}
        )

      try do
        result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

        received =
          for {:trace_ts, pid, :receive, msg, _} <- result.messages,
              pid in [result.guard, result.coordinator],
              do: msg

        sent =
          for {:trace_ts, pid, :send, msg, _, _} <- result.messages,
              pid == s.caller and is_tuple(msg) and tuple_size(msg) > 1 and
                elem(msg, 1) in [:policy, :item, :input],
              do: msg

        assert received != [] and sent != [], "queue oracle must observe real messages"

        assert Enum.all?(received, &(:erts_debug.flat_size(&1) <= 128)),
               "library control queue must be constant size"

        assert Enum.all?(sent, &(:erts_debug.flat_size(&1) <= Bounds.item_words() + 32)),
               "bootstrap messages must be bounded"
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "custody U failure batches preserve bounded queues authentication and strict D" do
    Runtime.with_peer(
      fn ->
        # Two ranges of 128 and 129 force full batches and a final partial
        # batch from a real custody placement with all callbacks held past U.
        n = 257
        s = Runtime.start(n, :custody)
        :erlang.trace_pattern({Worker, :aead, 3}, true, [:local, :call_count])
        :erlang.trace_pattern({Coordinator, :result_batch, 2}, true, [:local])

        try do
          result = Runtime.collect_return(s) |> Runtime.delivered()

          batches =
            for {:trace_ts, pid, :receive, {_, :results, controls} = message, _} <-
                  result.messages,
                pid == s.coordinator,
                do: {message, controls}

          assert batches != [], "custody U must observe real failure batches"

          assert Enum.all?(batches, fn {message, controls} ->
                   length(controls) in 1..4 and :erts_debug.flat_size(message) <= 128
                 end),
                 "failure batches must keep the four-control cap and 128-word message bound"

          assert Enum.any?(batches, fn {_, controls} -> length(controls) == 4 end)
          assert Enum.any?(batches, fn {_, controls} -> length(controls) == 1 end)
          controls = Enum.flat_map(batches, &elem(&1, 1))
          assert Enum.sort(Enum.map(controls, &elem(&1, 0))) == Enum.to_list(0..(n - 1))
          assert Enum.all?(controls, &match?({_, :decryption_failed, :crypto, :failed}, &1))

          assert :erlang.trace_info({Worker, :aead, 3}, :call_count) == {:call_count, n},
                 "each undelivered position must run real fallback AEAD before its failure control"

          {state, first} =
            Enum.find_value(Enum.reverse(result.events), fn
              {:trace_ts, _, :call, {Coordinator, :result_batch, [state, [_ | _] = controls]}, _} ->
                {state, controls}

              _ ->
                nil
            end)

          expired = %{state | d: Bounds.now()}

          assert Coordinator.result_batch(expired, first) == expired,
                 "failure batches must reject every result at or after D"

          for phase <- [:unadmitted, :ready] do
            {i, _, _, _} = hd(first)
            position = %{state.positions[i] | phase: phase}
            pending = %{state | positions: Map.put(state.positions, i, position)}
            assert Coordinator.result_batch(pending, [hd(first)]) == pending
          end

          settled = Coordinator.result_batch(%{state | d: Bounds.now() + 1_000_000}, first)
          assert Coordinator.result_batch(settled, first) == settled
          assert settled.settled == state.settled + length(first)
          assert {:ok, results} = result.return
          assert length(results) == n
          assert Enum.all?(results, &match?({:error, %{reason: :decryption_failed}}, &1))
        after
          :erlang.trace_pattern({Worker, :aead, 3}, false, [:local, :call_count])
          :erlang.trace_pattern({Coordinator, :result_batch, 2}, false, [:local])
          Runtime.cleanup(s)
        end
      end,
      2
    )
  end

  test "oracle 4 guard heap stays constant with queued notices after GC" do
    Runtime.with_peer(fn ->
      sizes =
        for n <- [1, 10_000] do
          s = Runtime.start(n, :custody)
          true = :erlang.suspend_process(s.guard)
          Enum.each(s.custody, &Process.exit(&1, :kill))
          Runtime.await(fn -> Runtime.info(s.guard, :message_queue_len) >= n end)

          try do
            # GC of a suspended target is supported and does not turn sensitivity off.
            true = :erlang.garbage_collect(s.guard)
            size = Runtime.info(s.guard, :total_heap_size)

            assert Runtime.info(s.guard, :message_queue_data) == :off_heap,
                   "guard mailbox must be off heap"

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

    :telemetry.attach(
      id,
      [:request_seal, :jose, :decrypt_many],
      fn _, _, _, _ ->
        send(observer, {:handler, Bounds.now()})
        Process.sleep(250)
      end,
      nil
    )

    :erlang.trace_pattern({Open, :wait_end, 1}, true, [:local])

    s =
      Runtime.launch(1, :resolvers,
        policy: %{
          timeout: 300,
          resolve_timeout: 200,
          unwrap_timeout: 50,
          key_resolver: fn _ -> :error end
        }
      )

    try do
      result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

      [_, _, _, _, _, _, _, f, _] =
        Enum.find_value(result.events, fn
          {:spawn, _, _, Guard, :run, args, _} -> args
          _ -> nil
        end)

      stamped =
        Enum.find_value(result.events, fn
          {:trace_ts, pid, :call, {Open, :wait_end, [at]}, _} when pid == s.caller -> at
          _ -> nil
        end)

      handler_at =
        Enum.find_value(result.events, fn
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
    Runtime.with_peer(fn ->
      # Install the boundary trace before launch, not after observing a
      # callback whose entry can be delivered after the caller's deadline.
      :erlang.trace_pattern({Open, :wait_end, 1}, true, [:local])
      :erlang.trace_pattern({Open, :cleanup, 1}, true, [:local])

      :erlang.trace_pattern({:erlang, :send_after, 4}, true, [])

      s =
        Runtime.start(1, :resolvers,
          trace_input: false,
          trace_messages: false,
          policy: %{timeout: 300, resolve_timeout: 200, unwrap_timeout: 50}
        )

      true = :erlang.suspend_process(s.guard)

      try do
        s = Runtime.collect_return(s, Bounds.now() + 1_000_000)

        assert match?({:error, %{reason: :deadline_exceeded}}, s.return),
               "caller wait must be bounded with guard suspended"

        # Fail before a trace barrier when a mutant is still producing traces.
        # The after block stops that producer before draining its finite queue.
        s = Runtime.delivered(s)

        [_, _, _, _, _, _, _, f, _] =
          Enum.find_value(s.events, fn
            {:spawn, _, _, Guard, :run, args, _} -> args
            _ -> nil
          end)

        wakes =
          for {:trace_ts, pid, :call, {:erlang, :send_after, [ms, _, {_, :wait_bound}, _]}, _} <-
                s.events,
              pid == s.caller,
              do: ms * 1_000

        assert wakes != [], "caller must arm its absolute wake before waiting"

        assert Enum.all?(wakes, &(f + Bounds.teardown(1) - &1 > 9_000)),
               "caller wake must leave scheduling margin inside F plus B"

        boundaries =
          for {:trace_ts, pid, :call, {Open, function, args}, _} <- Enum.reverse(s.events),
              pid == s.caller and function in [:wait_end, :cleanup],
              do: {function, args}

        assert match?([{:wait_end, [_]}, {:cleanup, _} | _], boundaries),
               "wait end must be stamped before cleanup"

        [{:wait_end, [at]} | _] = boundaries

        assert at <= f + Bounds.teardown(1),
               "wait end must fit F plus B: #{inspect({at, f + Bounds.teardown(1)})}"
      after
        :erlang.trace_pattern({:erlang, :send_after, 4}, false, [])
        :erlang.trace_pattern({Open, :wait_end, 1}, false, [:local])
        :erlang.trace_pattern({Open, :cleanup, 1}, false, [:local])
        Runtime.cleanup(s)
      end
    end)
  end

  test "notices freed at P3 and resolver custody phases do not overlap" do
    Runtime.with_peer(fn ->
      s = Runtime.start(10_000, :custody)

      try do
        assert Enum.all?(s.resolvers, &(not Process.alive?(&1))),
               "P3 requires every resolver end marker"

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

        s =
          Runtime.collect_until(s, fn current ->
            Enum.any?(current.messages, fn
              {:trace_ts, pid, :receive, {_, :ended, {:resolver, 0}}, _} ->
                pid == current.coordinator

              _ ->
                false
            end)
          end)

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
      for {function, topology} <- [
            {:expire_r, :resolvers},
            {:expire_u, :custody},
            {:deadline, :resolvers},
            {:worker_down, :resolvers}
          ] do
        arity = if function == :worker_down, do: 3, else: 1

        try do
          samples =
            for n <- [1, 1_000, 10_000] do
              s =
                Runtime.start(n, topology,
                  policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 2_000}
                )

              :erlang.trace(s.coordinator, true, [:call, :arity])

              :erlang.trace_pattern(
                {Coordinator, function, arity},
                [{:_, [], [{:message, {:process_dump}}]}],
                [:local]
              )

              :erlang.trace_pattern(
                {Coordinator, :loop, 1},
                [{:_, [], [{:message, {:process_dump}}]}],
                [:local]
              )

              :erlang.trace_pattern(
                {Coordinator, :finish, 1},
                [{:_, [], [{:message, {:process_dump}}]}],
                [:local]
              )

              try do
                if function == :expire_u do
                  for {pid, :worker} <- s.pids, do: :erlang.suspend_process(pid)
                end

                if function == :deadline, do: hold_until_d(s)

                if function == :worker_down do
                  {pid, _} = Enum.find(s.pids, fn {_, role} -> role == :worker end)
                  Process.exit(pid, :kill)
                end

                work = pass_interval(s, function, nil, Bounds.now() + 30_000_000)
                {n, work}
              after
                :erlang.trace_pattern({Coordinator, function, arity}, false, [:local])
                :erlang.trace_pattern({Coordinator, :loop, 1}, false, [:local])
                :erlang.trace_pattern({Coordinator, :finish, 1}, false, [:local])
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

  defp pass_interval(s, function, start, at) do
    if Bounds.now() >= at do
      flunk("coordinator passes must fit a + 512n: incomplete #{function} at the hang cap")
    else
      receive do
        event ->
          current = Runtime.observe(s, event)

          case event do
            {:trace_ts, _, :call, {Coordinator, ^function, _}, dump, _} when start == nil ->
              pass_interval(current, function, reductions(dump), at)

            {:trace_ts, _, :call, {Coordinator, next, _}, dump, _}
            when is_integer(start) and next in [:loop, :finish] ->
              reductions(dump) - start

            _ ->
              pass_interval(current, function, start, at)
          end
      after
        Bounds.remaining(at) ->
          flunk("coordinator passes must fit a + 512n: incomplete #{function} at the hang cap")
      end
    end
  end

  test "29 caller death during D settlement and reply sends ends every child" do
    Runtime.with_peer(fn ->
      for function <- [:fill_deadline, :settled_messages, :group_messages, :reply] do
        arity =
          case function do
            :fill_deadline -> 3
            :settled_messages -> 5
            :group_messages -> 3
            :reply -> 2
          end

        :erlang.trace_pattern({Coordinator, function, arity}, true, [:local])

        s =
          Runtime.start(10_000, :resolvers,
            policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 2_000}
          )

        :erlang.trace(s.coordinator, true, [:call, :arity])

        try do
          hold_until_d(s)

          s =
            Runtime.collect_until(s, fn current ->
              Enum.any?(current.events, fn
                {:trace_ts, _, :call, {Coordinator, ^function, _}, _} -> true
                _ -> false
              end)
            end)

          result = Runtime.trigger(s, :caller)

          assert Enum.all?(result.refs, fn {_, ended} -> ended end),
                 "terminal steps must end every created process"

          assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
        after
          :erlang.trace_pattern({Coordinator, function, arity}, false, [:local])
          Runtime.cleanup(s)
        end
      end
    end)
  end

  defp hold_until_d(s) do
    d =
      Enum.find_value(s.events, fn
        {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
        _ -> nil
      end)

    true = :erlang.suspend_process(s.coordinator)
    Process.sleep(Bounds.remaining(d))
    :erlang.resume_process(s.coordinator)
  end

  test "R12-4 D at cap sweeps even on replied end" do
    Runtime.with_peer(fn ->
      s =
        Runtime.start(10_000, :resolvers,
          policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 2_000}
        )

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
        {_pending, count} =
          s.events
          |> Enum.reverse()
          |> Enum.reduce({%{}, 0}, fn
            {:received, pid, {:"ETS-TRANSFER", tid, _, {_, :slot, slot}}}, {pending, n}
            when pid == s.guard ->
              {Map.put(pending, slot, {tid, false}), n}

            {:trace_ts, pid, :call, {:ets, :delete, [tid]}, _}, {pending, n}
            when pid == s.guard ->
              {Map.new(pending, fn {slot, {table, deleted}} ->
                 {slot, {table, deleted or table == tid}}
               end), n}

            {:trace_ts, pid, :send, {_, :ended, slot}, _, _}, {pending, n} when pid == s.guard ->
              assert match?({_, true}, pending[slot]),
                     "notice deletion must precede ended forward"

              {Map.delete(pending, slot), n + 1}

            _, state ->
              state
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
