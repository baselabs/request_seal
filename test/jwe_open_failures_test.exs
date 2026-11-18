defmodule RequestSeal.JWEOpenFailuresTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  alias RequestSeal.{Custody, JOSE.JWE, KeyHandle}
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Guard, Open, Preflight, Resolver}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime
  @moduletag timeout: 600_000

  test "open library crashes clear the received notice before returning" do
    Runtime.with_peer(fn -> bootstrap_crash(20) end, 1)
  end

  defp bootstrap_crash(0), do: flunk("bootstrap crash placement exhausted")

  defp bootstrap_crash(attempts) do
    s =
      Runtime.launch(1, :resolvers,
        hold_caller: true,
        policy: %{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}
      )

    s = Runtime.collect_until(s, &(&1.guard != nil))

    result =
      try do
        [tag | _] = guard_arguments(s)
        invalid_pid = {:invalid_destination}
        # Fault injection at the library's bootstrap receive, with real processes.
        send(s.caller, {tag, :preflight, invalid_pid})
        s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

        consumed =
          Enum.any?(s.events, fn
            {:received, pid, {^tag, :preflight, ^invalid_pid}} -> pid == s.caller
            _ -> false
          end)

        if consumed and match?({:error, _}, s.return) do
          assert {:error, %{reason: :internal_failure, layer: :internal}} = s.return,
                 "open crashes must report internal failure"

          assert Process.alive?(s.caller)
          assert_notices_gone(s)
          guard_ref = Process.monitor(s.guard)
          guard = s.guard

          assert_receive {:DOWN, ^guard_ref, :process, ^guard, _},
                         50,
                         "open crash must await guard DOWN before returning"

          assert Enum.all?(Map.keys(s.pids), &(not Process.alive?(&1))),
                 "open crash must join every library and caller-code child"

          :ok
        else
          :retry
        end
      after
        Runtime.cleanup(s)
      end

    if result == :retry, do: bootstrap_crash(attempts - 1)
  end

  test "open result assembly crashes preserve internal failure after real custody" do
    handler = "jwe-assembly-events"
    observer = self()

    :ok =
      :telemetry.attach_many(
        handler,
        [
          [:request_seal, :jose, :content_authentication],
          [:request_seal, :custody, :unwrap],
          [:request_seal, :jose, :decrypt_many]
        ],
        fn event, _, _, _ -> send(observer, {:assembly_event, event}) end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    s = Runtime.start(1, :resolvers, hold_caller: true)

    try do
      [tag | _] = guard_arguments(s)
      # Corrupt a library control after admission; all cryptography stays real.
      send(s.caller, {tag, :group, :invalid_duration, 1})
      Enum.each(s.resolvers, &send(&1, :continue))
      s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

      assert match?({:error, %{reason: :internal_failure, layer: :internal}}, s.return),
             "open crashes must report internal failure"

      refute Enum.any?(s.events, &match?({:assembly_event, _}, &1)),
             "telemetry preparation failure must publish no events"

      refute_receive {:assembly_event, _},
                     0,
                     "telemetry preparation failure must publish no events"

      assert_notices_gone(s)

      assert Enum.all?(Map.keys(s.pids), &(not Process.alive?(&1))),
             "open crash must join every library and caller-code child"
    after
      Runtime.cleanup(s)
    end
  end

  defp guard_arguments(s) do
    Enum.find_value(s.events, fn
      {:spawn, _, _, Guard, :run, args, _} -> args
      _ -> nil
    end)
  end

  defp assert_notices_gone(s) do
    notices =
      for {:received, pid, {:"ETS-TRANSFER", tid, _, {_, :caller}}} <- s.events,
          pid == s.caller,
          do: tid

    assert notices != [], "open must have received its caller notice"

    assert Enum.all?(notices, &(:ets.info(&1) == :undefined)),
           "open crash must delete the received caller notice"
  end

  test "preflight crashes escape without a validation verdict" do
    assert capture_log(fn ->
             tag = make_ref()
             flag = :atomics.new(2, [])

             {pid, ref} =
               spawn_monitor(Preflight, :run, [tag, self(), flag, :batch, :invalid_clock])

             try do
               assert_receive {:DOWN, ^ref, :process, ^pid, reason}
               refute reason == :normal, "preflight crashes must exit non-normally"

               assert reason == :internal_failure,
                      "preflight validation crash must use a closed exit"

               refute_receive {^tag, :preflight, {:outer, _, _}}, 0
             after
               Process.exit(pid, :kill)
               Process.demonitor(ref, [:flush])
             end
           end) == "",
           "preflight validation crash must not log"
  end

  test "preflight crashes return internal failure with no surviving notice or child" do
    Runtime.with_peer(fn -> preflight_crash(20) end, 1)
  end

  defp preflight_crash(0), do: flunk("preflight crash placement exhausted")

  defp preflight_crash(attempts) do
    s =
      Runtime.launch(1, :resolvers,
        hold_caller: true,
        policy: %{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}
      )

    s = Runtime.collect_until(s, &(&1.preflight != nil))

    result =
      try do
        [tag | _] = guard_arguments(s)
        send(s.preflight, {tag, :worker, -1, 0, 0, {:invalid_destination}})
        s = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

        if match?({:error, _}, s.return) do
          assert {:error, %{reason: :internal_failure, layer: :internal}} = s.return,
                 "preflight crashes must report internal failure"

          assert_notices_gone(s)

          assert Enum.all?(Map.keys(s.pids), &(not Process.alive?(&1))),
                 "preflight crash must join every library and caller-code child"

          :ok
        else
          :retry
        end
      after
        Runtime.cleanup(s)
      end

    if result == :retry, do: preflight_crash(attempts - 1)
  end

  test "preflight crash after ok is internal failure and tears down all registered roles" do
    assert capture_log(fn ->
             {handle, token} = Runtime.real_key()
             tag = make_ref()
             address = :erlang.alias()
             flag = :atomics.new(2, [])
             d = Bounds.now() + 1_000_000

             {guard, monitor} =
               :erlang.spawn_opt(
                 Guard,
                 :run,
                 [
                   tag,
                   self(),
                   address,
                   flag,
                   :batch,
                   d - 500_000,
                   d,
                   d + Bounds.finalization(),
                   100_000
                 ],
                 [:monitor, {:message_queue_data, :off_heap}]
               )

             assert_receive {:"ETS-TRANSFER", notice, ^guard, {^tag, :caller}}
             assert_receive {^tag, :preflight, pf}
             pf_ref = Process.monitor(pf)

             try do
               # Queued before input_end, so handoff encounters the invalid destination
               # only after real policy, cardinality and item validation have succeeded.
               send(pf, {tag, :worker, -1, 0, 0, {:invalid_destination}})
               send(pf, {tag, :policy, Runtime.policy(handle)})
               send(pf, {tag, :count, 1})
               send(pf, {tag, :item, 0, :exact, token, %{}})
               send(pf, {tag, :input_end})
               assert_receive {^tag, :reply, {:outer, :internal_failure, :internal}, 1, 0}, 2_000
               assert_receive {:DOWN, ^pf_ref, :process, ^pf, reason}
               refute reason == :normal, "preflight handoff crashes must exit non-normally"

               assert reason == :internal_failure,
                      "preflight handoff crash must use a closed exit"

               assert_receive {:DOWN, ^monitor, :process, ^guard, :replied}, 2_000
               assert :ets.info(notice, :owner) == self()
             after
               Process.exit(guard, :kill)
               :erlang.unalias(address)
               Process.demonitor(monitor, [:flush])
               Process.demonitor(pf_ref, [:flush])
               if :ets.info(notice, :owner) == self(), do: :ets.delete(notice)
               Custody.release(handle)
             end

             assert :ets.info(notice) == :undefined
           end) == "",
           "preflight handoff crash must not log"
  end

  test "D drain keeps a preflight crash internal after accepted cardinality" do
    {handle, token} = Runtime.real_key()
    tag = make_ref()
    address = :erlang.alias()
    flag = :atomics.new(2, [])
    d = Bounds.now() + 200_000

    {guard, ref} =
      :erlang.spawn_opt(
        Guard,
        :run,
        [tag, self(), address, flag, :batch, d - 100_000, d, d + Bounds.finalization(), 10_000],
        [:monitor, {:message_queue_data, :off_heap}]
      )

    assert_receive {:"ETS-TRANSFER", notice, ^guard, {^tag, :caller}}
    assert_receive {^tag, :preflight, pf}

    registry =
      Enum.find(:ets.all(), fn tid ->
        :ets.info(tid, :name) == :registry and :ets.info(tid, :heir) == guard
      end)

    coordinator = :ets.info(registry, :owner)
    pf_ref = Process.monitor(pf)

    try do
      true = :erlang.suspend_process(coordinator)
      send(pf, {tag, :worker, -1, 0, 0, {:invalid_destination}})
      send(pf, {tag, :workers_done})
      send(pf, {tag, :policy, Runtime.policy(handle)})
      send(pf, {tag, :count, 1})
      send(pf, {tag, :item, 0, :exact, token, %{}})
      send(pf, {tag, :input_end})
      assert_receive {:DOWN, ^pf_ref, :process, ^pf, reason}
      refute reason == :normal
      Process.sleep(Bounds.remaining(d))
      :erlang.resume_process(coordinator)

      assert_receive {:DOWN, ^ref, :process, ^guard, :internal_failure},
                     2_000,
                     "D drain must retain internal failure"

      refute_receive {^tag, :reply, :ok, _, _}, 0
      refute Process.alive?(coordinator)
      refute Process.alive?(pf)
    after
      try do
        :erlang.resume_process(coordinator)
      catch
        :error, :badarg -> :ok
      end

      Process.exit(guard, :kill)
      :erlang.unalias(address)
      Process.demonitor(ref, [:flush])
      Process.demonitor(pf_ref, [:flush])
      if :ets.info(notice, :owner) == self(), do: :ets.delete(notice)
      Custody.release(handle)
    end
  end

  test "an empty cardinality waits for the final preflight handoff" do
    {handle, _} = Runtime.real_key()
    tag = make_ref()
    address = :erlang.alias()
    flag = :atomics.new(2, [])
    d = Bounds.now() + 1_000_000

    {guard, ref} =
      :erlang.spawn_opt(
        Guard,
        :run,
        [tag, self(), address, flag, :batch, d - 500_000, d, d + Bounds.finalization(), 10_000],
        [:monitor, {:message_queue_data, :off_heap}]
      )

    assert_receive {:"ETS-TRANSFER", notice, ^guard, {^tag, :caller}}
    assert_receive {^tag, :preflight, pf}

    try do
      send(pf, {tag, :policy, Runtime.policy(handle)})
      send(pf, {tag, :count, 0})
      refute_receive {^tag, :reply, _, _, _}, 20, "cardinality alone must not complete preflight"
      send(pf, {tag, :input_end})
      assert_receive {^tag, :reply, :ok, 0, 0}, 2_000
      assert_receive {:DOWN, ^ref, :process, ^guard, :replied}, 2_000
    after
      Process.exit(guard, :kill)
      :erlang.unalias(address)
      Process.demonitor(ref, [:flush])
      if :ets.info(notice, :owner) == self(), do: :ets.delete(notice)
      Custody.release(handle)
    end
  end

  test "codec validation catches do not disguise broken library state" do
    {handle, token} = Runtime.real_key()

    try do
      assert {:ok, parts} = Codec.split(token)
      assert_raise KeyError, fn -> Codec.admit({:ok, parts}, %{}, %{}) end
      assert_raise BadMapError, fn -> Codec.parties(:invalid_state) end
      assert_raise ArgumentError, fn -> Codec.expected(%{"x" => 1}, :invalid_state) end

      for expected <- [%{7 => "x"}, %{"x" => [1 | :improper]}] do
        assert {:error, %{reason: :invalid_policy}} = Codec.expected(expected, [])
      end

      for bytes <- ["{", "{?}", ~S({"x":"\uD800"}), ~S({"x":1e9999})] do
        assert {:error, %{reason: :invalid_header}} = Codec.object(bytes, 16_384)
      end

      for bytes <- ["=", "A", "a+", "a/", "AA ", <<255>>] do
        assert catch_throw(Codec.decode(bytes)) == {:jose_error, :invalid_base64, :input}
      end

      assert Codec.decode("AQ") == <<1>>
    after
      Custody.release(handle)
    end
  end

  test "resolver normalization crashes escape the caller callback boundary" do
    assert capture_log(fn ->
             tag = make_ref()
             notice = :ets.new(:test_caller_notice, [:private])
             slot = {:resolver, 0}

             {pid, ref} =
               spawn_monitor(Resolver, :run, [
                 tag,
                 0,
                 self(),
                 Bounds.now() + 1_000_000,
                 self(),
                 slot,
                 self(),
                 notice
               ])

             child_notice = :ets.new(:test_child_notice, [:private])

             try do
               :ets.give_away(child_notice, pid, {tag, :slot, slot})
               send(pid, {tag, :request, %{}, fn _ -> :error end})
               assert_receive {:DOWN, ^ref, :process, ^pid, reason}, 2_000

               assert reason == :internal_failure,
                      "resolver normalization crash must use a closed exit"

               refute_receive {^tag, :answer, _, _}, 0
             after
               ended = Process.monitor(pid)
               Process.exit(pid, :kill)

               receive do
                 {:DOWN, ^ended, :process, ^pid, _} -> :ok
               end

               Process.demonitor(ref, [:flush])
               :ets.delete(notice)
               if :ets.info(child_notice, :owner) == self(), do: :ets.delete(child_notice)
             end

             assert :ets.info(child_notice) == :undefined
           end) == "",
           "resolver normalization crash must not log"
  end

  test "a guard starting past F never transfers a caller notice" do
    tag = make_ref()
    address = :erlang.alias()
    flag = :atomics.new(2, [])
    past = Bounds.now() - 1_000_000

    {pid, ref} =
      :erlang.spawn_opt(
        Guard,
        :run,
        [tag, self(), address, flag, :batch, past, past, past, 1_000],
        [:monitor]
      )

    try do
      # A forbidden handoff lets the already-expired coordinator race F. Check
      # the transfer first so either exit reason exposes that same violation.
      assert_receive {:DOWN, ^ref, :process, ^pid, reason}

      refute_receive {:"ETS-TRANSFER", _, ^pid, {^tag, :caller}},
                     0,
                     "past F the guard must retain and delete its notice"

      assert reason == :deadline
    after
      :erlang.unalias(address)
      Process.exit(pid, :kill)
      Process.demonitor(ref, [:flush])

      receive do
        {:"ETS-TRANSFER", tid, ^pid, {^tag, :caller}} -> :ets.delete(tid)
      after
        0 -> :ok
      end
    end
  end

  test "final intake retries every early deadline wait" do
    # Inspect the actual compiled receive: every timeout must recurse rather
    # than return Codec.unit/2's non-tuple before the absolute deadline.
    forms = RequestSeal.Test.JWEOpenAnalyzer.forms(Preflight)

    [{:function, _, :intake, 10, clauses}] =
      Enum.filter(forms, fn
        {:function, _, :intake, 10, _} -> true
        _ -> false
      end)

    assert Enum.any?(clauses, fn {:clause, _, _, _, body} -> looping_intake?(body) end),
           "final intake must loop after an early timeout"

    assert Bounds.milliseconds(1) == 1
    assert Bounds.milliseconds(-1) == 0
    assert Open.wait_end(0) == 0
  end

  test "malformed resolver handles are refused before R" do
    for handle <- [
          %{__struct__: KeyHandle},
          %{__struct__: KeyHandle, algorithm: {:jwe, "A256KW"}},
          %{__struct__: KeyHandle, capabilities: [:unwrap]}
        ] do
      tag = make_ref()
      notice = :ets.new(:malformed_caller, [:private])
      slot = {:resolver, 0}
      table = :ets.new(:malformed_child, [:private])

      {pid, ref} =
        spawn_monitor(Resolver, :run, [
          tag,
          0,
          self(),
          Bounds.now() + 5_000_000,
          self(),
          slot,
          self(),
          notice
        ])

      try do
        :ets.give_away(table, pid, {tag, :slot, slot})

        send(
          pid,
          {tag, :request, %{algorithm: "A256KW"},
           fn _ ->
             {:ok, %{algorithm: "A256KW", key: handle}}
           end}
        )

        assert_receive {^tag, :answer, 0, :key_resolver_failed},
                       500,
                       "malformed resolver handle must be refused promptly"
      after
        Process.exit(pid, :kill)
        assert_receive {:DOWN, ^ref, :process, ^pid, _}
        :ets.delete(notice)
      end

      assert :ets.info(table) == :undefined
    end
  end

  test "worker internal crashes retain their classification through the coordinator" do
    for topology <- [:resolvers, :custody] do
      s = Runtime.start(1, topology)

      try do
        [tag | _] = guard_arguments(s)
        {worker, :worker} = Enum.find(s.pids, fn {_, role} -> role == :worker end)
        # A broken library destination raises inside the real worker entry.
        send(worker, {tag, :resolver, 0, {:invalid_destination}})
        result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

        assert match?(
                 {:ok, [{:error, %{reason: :internal_failure, layer: :internal}}]},
                 result.return
               ),
               "worker internal crash must remain an internal failure"

        assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
      after
        Runtime.cleanup(s)
      end
    end
  end

  test "notice timeout joins the guard and deletes a transfer after the timeout" do
    observer = self()
    tag = make_ref()

    {caller, caller_ref} =
      spawn_monitor(fn ->
        receive do
          {:guard, guard} ->
            # The zero receive is the expired receive branch. Keep it latched so
            # the guard's already-approved give_away occurs after that timeout.
            receive do
              :never -> flunk("unexpected timeout message")
            after
              0 -> :ok
            end

            send(observer, :notice_timed_out)

            receive do
              :cleanup -> :ok
            end

            answer = Open.expire_notice(guard, tag)

            receive do
              {:"ETS-TRANSFER", _, ^guard, {^tag, :caller}} -> send(observer, :stray_transfer)
            after
              0 -> :ok
            end

            send(observer, {:notice_timeout_answer, answer, Process.alive?(guard)})

            receive do
              :stop -> :ok
            end
        end
      end)

    {guard, guard_ref} =
      spawn_monitor(fn ->
        table = :ets.new(:late_notice, [:private])
        # This is the guard's pre-transfer check, before the caller times out.
        f = Bounds.now() + 1_000_000
        true = Bounds.now() < f
        send(observer, {:notice_checked, self(), table})

        receive do
          :transfer -> :ok
        end

        :ets.give_away(table, caller, {tag, :caller})
        send(observer, :notice_transferred)

        receive do
          :stop -> :ok
        end
      end)

    try do
      assert_receive {:notice_checked, ^guard, table}
      send(caller, {:guard, guard})
      assert_receive :notice_timed_out
      send(guard, :transfer)
      assert_receive :notice_transferred
      assert :ets.info(table, :owner) == caller
      send(caller, :cleanup)

      assert_receive {:notice_timeout_answer,
                      {:error, %{reason: :deadline_exceeded, layer: :crypto}}, false},
                     1_000,
                     "notice timeout must join the guard before returning"

      assert_receive {:DOWN, ^guard_ref, :process, ^guard, :killed}
      refute_receive :stray_transfer, 0, "notice timeout must drain the late transfer"
      assert :ets.info(table) == :undefined, "notice timeout must delete the late notice"
      send(caller, :stop)
      assert_receive {:DOWN, ^caller_ref, :process, ^caller, :normal}
      source = File.read!("lib/request_seal/jose/jwe/open.ex")

      assert source =~ "else: expire_notice(s.guard, s.tag)",
             "the expired notice receive must cancel and drain the guard"
    after
      for pid <- [caller, guard] do
        ref = Process.monitor(pid)
        Process.exit(pid, :kill)

        receive do
          {:DOWN, ^ref, :process, ^pid, _} -> :ok
        end
      end

      Process.demonitor(caller_ref, [:flush])
      Process.demonitor(guard_ref, [:flush])
    end
  end

  test "raising telemetry handlers preserve the full successful outcome" do
    {handle, token} = Runtime.real_key()
    observer = self()

    events = [
      [:request_seal, :jose, :content_authentication],
      [:request_seal, :custody, :unwrap],
      [:request_seal, :jose, :decrypt_many]
    ]

    :ok =
      :telemetry.attach_many(
        "jwe-outcome-observer",
        events,
        fn event, measurements, metadata, _ ->
          send(observer, {:outcome_event, event, measurements, metadata})
        end,
        nil
      )

    :ok =
      :telemetry.attach(
        "jwe-raising-handler",
        hd(events),
        fn _, _, _, _ -> raise "handler failure" end,
        nil
      )

    try do
      capture_log(fn ->
        assert {:ok, [{:ok, %{plaintext: "payload"}}]} =
                 JWE.decrypt_many([%{token: token, expected: %{}}], Runtime.policy(handle)),
               "raising telemetry handler must preserve the successful result"
      end)

      for event <- events do
        assert_receive {:outcome_event, ^event, _, _},
                       500,
                       "raising telemetry handler must not truncate outcome events"
      end

      refute_receive {:outcome_event, _, _, _}, 0
    after
      :telemetry.detach("jwe-raising-handler")
      :telemetry.detach("jwe-outcome-observer")
      Custody.release(handle)
    end
  end

  defp looping_intake?(nodes) when is_list(nodes), do: Enum.any?(nodes, &looping_intake?/1)

  defp looping_intake?({:receive, _, _, _, after_body}) do
    Enum.any?(after_body, fn
      {:call, _, {:atom, _, :intake}, [_, _, _, _, _, {:var, _, n}, {:var, _, n}, _, _, _]} ->
        true

      _ ->
        false
    end)
  end

  defp looping_intake?(node) when is_tuple(node),
    do: node |> Tuple.to_list() |> looping_intake?()

  defp looping_intake?(_), do: false
end
