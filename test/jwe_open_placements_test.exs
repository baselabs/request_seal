defmodule RequestSeal.JWEOpenPlacementsTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Coordinator, Guard}
  alias RequestSeal.Test.{JWEOpenRuntime, JWETeardownGate}
  alias JWEOpenRuntime, as: Runtime
  @after_compile Runtime
  @moduletag timeout: 600_000
  @receive_timeout 5_000

  defp arguments(s) do
    Enum.find_value(s.events, fn
      {:spawn, _, _, Guard, :run, args, _} -> args
      _ -> nil
    end)
  end

  defp end_reason(s, target) do
    Enum.find_value(s.events, fn
      {:end, ^target, _, reason} -> reason
      _ -> nil
    end)
  end

  defp complete(s) do
    Runtime.collect_until(s, & &1.guard_ended)
    |> Runtime.delivered()
    |> Runtime.collect_ends()
    |> Runtime.delivered()
  end

  defp all_ended(s) do
    assert Enum.all?(Map.keys(s.pids), &(not Process.alive?(&1))),
           "every created process needs an end marker"

    assert Enum.all?(s.refs, fn {_, ended} -> ended end),
           "every created process needs an end marker"
  end

  test "anchors cover caller F D replied and coordinator crash exactly once" do
    Runtime.with_peer(fn ->
      :erlang.trace_pattern({Guard, :stop_at, 2}, [{:_, [], [{:return_trace}]}], [:local])
      :erlang.trace_pattern({Guard, :kill, 3}, true, [:local])
      :erlang.trace_pattern({Bounds, :now, 0}, [{:_, [], [{:return_trace}]}], [:local])

      try do
        for trigger <- [:caller, :f, :d, :replied, :coordinator] do
          s =
            Runtime.start(1, :resolvers,
              policy: %{timeout: 1_000, resolve_timeout: 600, unwrap_timeout: 100}
            )

          try do
            [_, _, _, _, _, _, d, f, _] = arguments(s)

            case trigger do
              at when at in [:f, :d] ->
                true = :erlang.suspend_process(s.coordinator)
                Process.sleep(Bounds.remaining(if(at == :f, do: f, else: d)))
                if at == :d, do: :erlang.resume_process(s.coordinator)

              :replied ->
                Enum.each(s.resolvers, &send(&1, :continue))

              _ ->
                :ok
            end

            result = Runtime.trigger(s, if(trigger == :replied, do: :d, else: trigger))
            chronological = Enum.reverse(result.events)

            stops =
              for {:trace_ts, pid, :call, {Guard, :stop_at, [anchor, n]}, _} <- chronological,
                  pid == s.guard,
                  do: {anchor, n}

            assert [{anchor, 1}] = stops, "stop_at must be computed exactly once"

            assert Enum.any?(chronological, fn
                     {:trace_ts, pid, :return_from, {Guard, :stop_at, 2}, at, _} ->
                       pid == s.guard and at == anchor + Bounds.teardown(1)

                     _ ->
                       false
                   end),
                   "stop_at must use the accepted cardinality"

            case trigger do
              :d ->
                assert anchor == d, "D must remain the teardown anchor"

              :f ->
                assert anchor == f, "F must remain the teardown anchor"

              :caller ->
                assert Enum.any?(chronological, fn
                         {:trace_ts, pid, :call, {Guard, :kill, [_, :caller_gone, ^anchor]}, _} ->
                           pid == s.guard

                         _ ->
                           false
                       end),
                       "caller anchor is the guard observation"

              _ ->
                before_stop =
                  Enum.take_while(chronological, fn
                    {:trace_ts, pid, :call, {Guard, :stop_at, _}, _} -> pid != s.guard
                    _ -> true
                  end)

                now =
                  Enum.find_value(Enum.reverse(before_stop), fn
                    {:trace_ts, pid, :return_from, {Bounds, :now, 0}, now, _}
                    when pid == s.guard ->
                      now

                    _ ->
                      nil
                  end)

                assert anchor == min(now, d), "owner flip anchor must be min(now D)"
            end

            all_ended(result)
          after
            Runtime.cleanup(s)
          end
        end
      after
        :erlang.trace_pattern({Guard, :stop_at, 2}, false, [:local])
        :erlang.trace_pattern({Guard, :kill, 3}, false, [:local])
        :erlang.trace_pattern({Bounds, :now, 0}, false, [:local])
      end
    end)
  end

  # Discard unverified races. The observer uses only the shipped call/procs
  # traces, suspension and owner reads; no production hook or sensitivity change.
  defp placed(attempts, fun), do: placed(attempts, fun, nil)

  defp placed(0, _, last),
    do: flunk("no verified production placement after 40 attempts: #{inspect(last)}")

  defp placed(attempts, fun, last) do
    case fun.() do
      :retry -> placed(attempts - 1, fun, last)
      {:retry, reason} -> placed(attempts - 1, fun, reason)
      result -> result
    end
  end

  defp pause(pid) do
    try do
      :erlang.suspend_process(pid)
    catch
      _, _ -> false
    end
  end

  defp ended(s, target) do
    Runtime.collect_event(s, fn
      {:end, pid, _, _} -> pid == target
      {:DOWN, _, :process, pid, _} -> pid == target
      _ -> false
    end)
  end

  defp sweep(s) do
    s =
      Runtime.collect_event(s, fn
        {:trace_ts, pid, :call, {Guard, :sweep, _}, _} -> pid == s.guard
        _ -> false
      end)

    if pause(s.guard) do
      # A queued call trace alone does not prove the guard is still sweeping.
      # OTP can be in a fold helper rather than the callback at suspension.
      stack = Runtime.info(s.guard, :current_stacktrace) || []

      if Enum.any?(stack, &match?({Guard, :sweep, 3, _}, &1)) or
           (Enum.any?(stack, &match?({:ets, :foldl, 3, _}, &1)) and
              Enum.any?(stack, &match?({Guard, :check, 1, _}, &1))) do
        {:ok, Runtime.delivered(s)}
      else
        :erlang.resume_process(s.guard)
        :retry
      end
    else
      :retry
    end
  end

  test "9b second triggers retain the first anchor and reason during sweep" do
    Runtime.with_peer(
      fn ->
        old = Process.flag(:priority, :max)
        :erlang.trace_pattern({Guard, :sweep, 3}, true, [:local])
        :erlang.trace_pattern({Guard, :stop_at, 2}, [{:_, [], [{:return_trace}]}], [:local])
        :erlang.trace_pattern({Guard, :kill, 3}, true, [:local])

        try do
          for first <- [:caller, :d] do
            placed(40, fn ->
              s =
                Runtime.start(1_000, :resolvers,
                  trace_input: false,
                  hold_caller: true,
                  policy: %{timeout: 700, resolve_timeout: 500, unwrap_timeout: 100}
                )

              try do
                [_, _, _, _, _, _, d, f, _] = arguments(s)

                true = :erlang.suspend_process(s.guard)
                true = :erlang.suspend_process(s.coordinator)

                s =
                  if first == :caller do
                    # The coordinator still owns the registry when caller
                    # death is observed, so the first cause really is caller.
                    assert :ets.info(Runtime.registry(s), :owner) == s.coordinator
                    Process.exit(s.caller, :kill)
                    ended(s, s.caller)
                  else
                    s = Runtime.until(s, d)
                    :erlang.resume_process(s.coordinator)
                    s = ended(s, s.coordinator)
                    registry = Runtime.registry(s)
                    assert :ets.info(registry, :owner) == s.guard
                    assert :ets.lookup(registry, :outcome) == [{:outcome, :replied}]
                    s
                  end

                :erlang.resume_process(s.guard)

                case sweep(s) do
                  {:ok, s} ->
                    s =
                      if first == :caller do
                        Runtime.until(s, f)
                      else
                        Process.exit(s.caller, :kill)
                        ended(s, s.caller)
                      end

                    :erlang.resume_process(s.guard)
                    result = complete(s)

                    stops =
                      for {:trace_ts, pid, :return_from, {Guard, :stop_at, 2}, at, _} <-
                            result.events,
                          pid == s.guard,
                          do: at

                    assert length(stops) == 1, "second trigger must not reset stop_at"

                    kills =
                      for {:trace_ts, pid, :call, {Guard, :kill, _}, _} <- result.events,
                          pid == s.guard,
                          do: pid

                    assert length(kills) == if(first == :caller, do: 1, else: 0),
                           "second trigger must not reopen causes"

                    assert end_reason(result, s.guard) ==
                             if(first == :caller, do: :normal, else: :replied)

                    all_ended(result)

                  :retry ->
                    :retry
                end
              after
                Runtime.cleanup(s)
              end
            end)
          end
        after
          Process.flag(:priority, old)

          for {f, a} <- [sweep: 3, stop_at: 2, kill: 3],
              do: :erlang.trace_pattern({Guard, f, a}, false, [:local])
        end
      end,
      1
    )
  end

  test "causes close after replied even when F or caller death arrives during sweep" do
    Runtime.with_peer(
      fn ->
        old = Process.flag(:priority, :max)
        :erlang.trace_pattern({Guard, :sweep, 3}, true, [:local])
        :erlang.trace_pattern({Guard, :kill, 3}, true, [:local])

        try do
          for second <- [:f, :caller] do
            placed(40, fn ->
              s =
                Runtime.start(10_000, :resolvers,
                  trace_input: false,
                  hold_caller: true,
                  policy: %{timeout: 2_000, resolve_timeout: 1_500, unwrap_timeout: 100}
                )

              try do
                [_, _, _, _, _, _, _, f, _] = arguments(s)
                true = :erlang.suspend_process(s.guard)
                # Hold the end notices while the real coordinator completes
                # its deadline reply. Verify the row/owner boundary before sweeping;
                # callback throughput is not the placement being tested.
                s = ended(s, s.coordinator)
                registry = Runtime.registry(s)
                assert :ets.info(registry, :owner) == s.guard
                assert :ets.lookup(registry, :outcome) == [{:outcome, :replied}]
                :erlang.resume_process(s.guard)

                case sweep(s) do
                  {:ok, s} ->
                    s =
                      if second == :f do
                        Runtime.until(s, f)
                      else
                        Process.exit(s.caller, :kill)
                        ended(s, s.caller)
                      end

                    :erlang.resume_process(s.guard)
                    result = complete(s)

                    assert end_reason(result, s.guard) == :replied,
                           "causes must close after replied"

                    refute Enum.any?(result.events, fn
                             {:trace_ts, _, :call, {Guard, :kill, _}, _} -> true
                             _ -> false
                           end),
                           "causes must close after replied"

                    if second == :f do
                      result = Runtime.collect_return(result, f + Bounds.teardown(10_000))
                      assert match?({:ok, _}, result.return), "post reply F must retain the reply"
                    end

                    all_ended(result)

                  :retry ->
                    :retry
                end
              after
                Runtime.cleanup(s)
              end
            end)
          end
        after
          Process.flag(:priority, old)
          :erlang.trace_pattern({Guard, :sweep, 3}, false, [:local])
          :erlang.trace_pattern({Guard, :kill, 3}, false, [:local])
        end
      end,
      1
    )
  end

  test "outcome row precedes reply and F preserves a completed reply" do
    # A trace notification cannot suspend a process between two adjacent BIFs.
    # Prove the exact boundary in the shipped BEAM, then place F on each side
    # of the reply using the real process tree.
    forms = RequestSeal.Test.JWEOpenAnalyzer.forms(Coordinator)
    {:function, _, :reply, 2, body} = Enum.find(forms, &match?({:function, _, :reply, 2, _}, &1))

    markers =
      for call <- RequestSeal.Test.JWEOpenAnalyzer.calls(body),
          marker = reply_marker(call),
          marker != nil,
          do: marker

    assert markers == [:outcome, :reply], "outcome row must precede reply"

    Runtime.with_peer(fn ->
      for replied <- [false, true] do
        s =
          Runtime.start(1, :resolvers,
            hold_caller: true,
            policy: %{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}
          )

        try do
          [_, _, _, _, _, _, _, f, _] = arguments(s)

          result =
            if replied do
              Enum.each(s.resolvers, &send(&1, :continue))
              result = Runtime.collect_until(s, &(&1.return != nil)) |> complete()
              Process.sleep(Bounds.remaining(f))
              result
            else
              true = :erlang.suspend_process(s.coordinator)
              Runtime.collect_return(s, f + Bounds.teardown(1) + 10_000) |> complete()
            end

          if replied do
            assert end_reason(result, s.guard) == :replied, "outcome row must survive F"
            assert match?({:ok, [{:ok, _}]}, result.return), "sent reply must survive F"
          else
            assert end_reason(result, s.guard) == :deadline

            assert match?({:error, %{reason: :deadline_exceeded}}, result.return),
                   "missing reply must end by F plus B"
          end

          all_ended(result)
        after
          Runtime.cleanup(s)
        end
      end
    end)
  end

  defp reply_marker(
         {:call, _, {:remote, _, {:atom, _, :ets}, {:atom, _, :insert}},
          [_, {:tuple, _, [{:atom, _, :outcome}, {:atom, _, :replied}]}]}
       ),
       do: :outcome

  defp reply_marker(
         {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :send}},
          [_, {:tuple, _, [_, {:atom, _, :reply} | _]}]}
       ),
       do: :reply

  defp reply_marker(_), do: nil

  test "10 birth links cover coordinator death and registration failure" do
    Runtime.with_peer(fn ->
      for point <- [:registry, :registration] do
        tag = make_ref()
        flag = :atomics.new(2, [])
        notice = :ets.new(:birth_caller, [:private])
        registry = :ets.new(:birth_registry, [:protected])
        d = Bounds.now() + 1_000_000
        args = [tag, self(), self(), notice, self(), flag, :batch, d - 100_000, d, 50_000]
        {pid, ref} = spawn_monitor(Coordinator, :run, args)
        :erlang.trace(pid, true, [:procs, :set_on_spawn, {:tracer, self()}])

        try do
          Runtime.await(fn -> Runtime.info(pid, :status) == :waiting end)
          assert Runtime.info(pid, :links) == []

          if point == :registry do
            Process.exit(pid, :kill)
            assert_receive {:DOWN, ^ref, :process, ^pid, :killed}, @receive_timeout
            refute_receive {:trace, ^pid, :spawn, _, _}, 0
          else
            # Fault at the real registration operation: the test retains write
            # ownership, so ETS refuses the first insert after the real spawn.
            # The preflight is linked at birth and must die without a slot row.
            send(pid, {:"ETS-TRANSFER", registry, self(), {tag, :registry}})
            assert_receive {:trace, ^pid, :spawn, child, {_, :run, _}}, @receive_timeout
            child_ref = Process.monitor(child)
            assert_receive {:DOWN, ^ref, :process, ^pid, :internal_failure}, @receive_timeout
            assert_receive {:DOWN, ^child_ref, :process, ^child, _}, @receive_timeout
            assert :ets.tab2list(registry) == []
            refute Process.alive?(child), "birth link must cover failed registration"
          end
        after
          Process.exit(pid, :kill)
          Process.demonitor(ref, [:flush])
          :ets.delete(registry)
          :ets.delete(notice)
        end
      end
    end)
  end

  test "S5c D during one scheduler row handoff cooperates with N results" do
    forms = RequestSeal.Test.JWEOpenAnalyzer.forms(RequestSeal.JOSE.JWE.Preflight)

    sends =
      for {:function, _, :send_rows, _, body} <- forms,
          {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :send}}, [_, envelope]} <-
            RequestSeal.Test.JWEOpenAnalyzer.calls(body),
          do: envelope

    assert match?([{:tuple, _, [_, {:atom, _, :row}, _, _]}], sends),
           "handoff must exit by D plus K_pf: every send must copy one bounded row"

    Runtime.with_peer(
      fn ->
        sample = JWETeardownGate.handoff_sample()
        assert sample.exit <= Bounds.preflight(), "handoff must exit by D plus K_pf"

        assert sample.elapsed <= Bounds.teardown(10_000),
               "handoff must end every process by D plus B"
      end,
      1
    )
  end

  test "D during every largest byte unit cooperates without changing sensitivity" do
    Runtime.with_peer(
      fn ->
        for unit <- [:token_scan, :expected, :name] do
          sample = JWETeardownGate.byte_sample(unit)
          assert sample.exit <= Bounds.preflight(), "byte unit must exit by D plus K_pf"
        end
      end,
      2
    )
  end

  test "23 codec work stays in sensitive roles and caller death ends every child" do
    calls =
      RequestSeal.Test.JWEOpenAnalyzer.forms(Coordinator)
      |> RequestSeal.Test.JWEOpenAnalyzer.calls()

    refute Enum.any?(calls, fn
             {:call, _, {:remote, _, {:atom, _, Codec}, _}, _} -> true
             _ -> false
           end),
           "codec work belongs in preflight or range worker"

    Runtime.with_peer(
      fn ->
        for scenario <- [:prefix, :tree, :object, :nested_object] do
          placed(40, fn ->
            options =
              case scenario do
                :prefix ->
                  [
                    items:
                      List.duplicate(
                        %{token: String.duplicate(" ", 4_096) <> ".b.c.d.e", expected: %{}},
                        1_000
                      )
                  ]

                :tree ->
                  [near_cap: true]

                :object ->
                  [
                    plaintext:
                      :erlang.iolist_to_binary(
                        :json.encode(%{
                          "x" => List.duplicate(%{"y" => List.duplicate(0, 64)}, 64)
                        })
                      ),
                    policy: %{content: :object}
                  ]

                :nested_object ->
                  [
                    plaintext:
                      "{\"x\":{\"a\":{\"b\":{\"c\":\"" <> :binary.copy("x", 16_384) <> "\"}}}}",
                    policy: %{content: :object}
                  ]
              end

            s =
              if scenario in [:object, :nested_object],
                do: Runtime.start(1_000, :resolvers, options),
                else: Runtime.launch(1_000, :resolvers, options)

            try do
              s = Runtime.collect_until(s, &(&1.preflight != nil))

              targets =
                if scenario in [:object, :nested_object] do
                  Enum.each(s.resolvers, &send(&1, :continue))
                  for {pid, :worker} <- s.pids, do: pid
                else
                  [s.preflight]
                end

              functions =
                case scenario do
                  :prefix -> [:json_serialization?]
                  :tree -> [:tree, :tree_pairs, :tree_list]
                  _ -> [:object, :tree, :depth, :utf8?]
                end

              if pause_codec(targets, functions, Bounds.now() + 1_000_000) do
                result = Runtime.trigger(s, :caller)
                all_ended(result)

                refute Enum.any?(result.events, fn
                         {:trace_ts, pid, :call, _, _} -> pid in targets
                         _ -> false
                       end),
                       "codec proof must keep production sensitivity"
              else
                {:retry, {scenario, Enum.map(targets, &Runtime.info(&1, :current_function))}}
              end
            after
              Runtime.cleanup(s)
            end
          end)
        end
      end,
      2
    )
  end

  defp pause_codec(targets, functions, until) do
    candidate =
      Enum.find(targets, fn pid ->
        case Runtime.info(pid, :current_function) do
          {Codec, f, _} -> f in functions
          _ -> false
        end
      end)

    cond do
      candidate != nil and pause(candidate) ->
        case Runtime.info(candidate, :current_function) do
          {Codec, f, _} ->
            if f in functions do
              true
            else
              :erlang.resume_process(candidate)
              pause_codec(targets, functions, until)
            end

          _ ->
            :erlang.resume_process(candidate)
            pause_codec(targets, functions, until)
        end

      Bounds.now() >= until ->
        false

      true ->
        pause_codec(targets, functions, until)
    end
  end
end
