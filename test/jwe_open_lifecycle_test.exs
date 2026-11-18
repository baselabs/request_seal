defmodule RequestSeal.JWEOpenLifecycleTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Custody, JOSE.JWE}
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Coordinator, Guard, Resolver, Unwrap}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime
  @moduletag timeout: 600_000

  defp controlled(timeout \\ 100_000, mode \\ :batch, resolve_before \\ 10_000) do
    {handle, _} = Runtime.real_key()
    tag = make_ref()
    address = :erlang.alias()
    flag = :atomics.new(2, [])
    d = Bounds.now() + timeout

    {guard, monitor} =
      :erlang.spawn_opt(
        Guard,
        :run,
        [
          tag,
          self(),
          address,
          flag,
          mode,
          d - resolve_before,
          d,
          d + Bounds.finalization(),
          1_000
        ],
        [:monitor, {:message_queue_data, :off_heap}]
      )

    assert_receive {:"ETS-TRANSFER", notice, ^guard, {^tag, :caller}}
    assert_receive {^tag, :preflight, pf}

    registry =
      Enum.find(:ets.all(), fn table ->
        :ets.info(table, :name) == :registry and :ets.info(table, :heir) == guard
      end)

    coordinator = :ets.info(registry, :owner)

    %{
      registry: registry,
      coordinator: coordinator,
      tag: tag,
      address: address,
      flag: flag,
      d: d,
      guard: guard,
      monitor: monitor,
      notice: notice,
      preflight: pf,
      handle: handle
    }
  end

  defp dispose(s) do
    Process.exit(s.guard, :kill)
    :erlang.unalias(s.address)
    Process.demonitor(s.monitor, [:flush])
    if :ets.info(s.notice, :owner) == self(), do: :ets.delete(s.notice)
    Custody.release(s.handle)

    receive do
      _ -> dispose_messages()
    after
      0 -> :ok
    end
  end

  defp dispose_messages do
    receive do
      _ -> dispose_messages()
    after
      0 -> :ok
    end
  end

  test "cardinality accepted before preflight ok during item intake" do
    s = controlled()
    tag = s.tag

    try do
      send(s.preflight, {tag, :policy, Runtime.policy(s.handle)})
      send(s.preflight, {tag, :count, 10_000})
      Runtime.await(fn -> :atomics.get(s.flag, 2) == 10_000 end)

      assert :atomics.get(s.flag, 2) == 10_000,
             "accepted cardinality must be written at acceptance"

      assert_receive {^tag, :reply, :ok, 10_000, 0}
      assert_receive {:DOWN, ref, :process, guard, :replied}
      assert ref == s.monitor and guard == s.guard
      results = drain_settled(tag, [])
      assert length(results) == 10_000, "D drain must preserve accepted cardinality"
      assert Enum.all?(results, &match?({:deadline_exceeded, :crypto}, &1))
    after
      dispose(s)
    end
  end

  defp drain_settled(tag, acc) do
    receive do
      {^tag, :settled, _, reason, layer, _} -> drain_settled(tag, [{reason, layer} | acc])
    after
      0 -> acc
    end
  end

  test "R12-7 queued stamped cardinality is accepted in the D drain" do
    s = controlled()
    tag = s.tag

    try do
      send(s.preflight, {tag, :policy, Runtime.policy(s.handle)})
      true = :erlang.suspend_process(s.coordinator)
      send(s.preflight, {tag, :count, 2})
      # The report's timestamp and send share a checkpoint. A delayed receiver
      # must decide by that stamp rather than its own dequeue time.
      Runtime.await(fn -> Runtime.info(s.coordinator, :message_queue_len) >= 1 end)
      Process.sleep(Bounds.remaining(s.d) + 1)
      :erlang.resume_process(s.coordinator)

      assert_receive {^tag, :reply, :ok, 2, 0},
                     1_000,
                     "D drain must preserve accepted cardinality"

      assert length(drain_settled(tag, [])) == 2, "D drain must preserve accepted cardinality"
    after
      dispose(s)
    end
  end

  test "preflight cooperates at its next checkpoint at D" do
    s = controlled()
    tag = s.tag
    pf_ref = Process.monitor(s.preflight)

    try do
      send(s.preflight, {tag, :policy, Runtime.policy(s.handle)})
      send(s.preflight, {tag, :count, 1})

      assert_receive {:DOWN, ^pf_ref, :process, _, :normal},
                     1_000,
                     "preflight must cooperate at D"

      assert :atomics.get(s.flag, 1) == 1, "preflight must cooperate at D"
      assert_receive {^tag, :reply, :ok, 1, 0}
    after
      Process.demonitor(pf_ref, [:flush])
      dispose(s)
    end
  end

  test "zero start gate refuses caller death and expired R before callback" do
    {handle, _} = Runtime.real_key()

    try do
      for cause <- [:caller, :r] do
        tag = make_ref()
        slot = {:resolver, 0}
        notice = :ets.new(:zero_start_caller, [:private])
        child_notice = :ets.new(:zero_start_child, [:private])
        observer = self()

        owner =
          if cause == :caller do
            spawn(fn ->
              receive do
                {:"ETS-TRANSFER", _, _, :zero_start} -> send(observer, :caller_owns_notice)
              end

              receive do
                :stop -> :ok
              end
            end)
          else
            self()
          end

        if cause == :caller do
          :ets.setopts(notice, {:heir, self(), :zero_start})
          :ets.give_away(notice, owner, :zero_start)
          assert_receive :caller_owns_notice
        end

        r = if cause == :r, do: Bounds.now() - 1, else: Bounds.now() + 1_000_000
        pid = spawn(Resolver, :run, [tag, 0, self(), r, self(), slot, owner, notice])
        ref = Process.monitor(pid)

        try do
          :ets.give_away(child_notice, pid, {tag, :slot, slot})
          Runtime.await(fn -> Runtime.info(pid, :status) == :waiting end)
          true = :erlang.suspend_process(pid)

          send(
            pid,
            {tag, :request, %{algorithm: "A256KW"},
             fn _ ->
               send(observer, :callback_started)
               {:ok, %{algorithm: "A256KW", key: handle}}
             end}
          )

          assert Runtime.info(pid, :message_queue_len) >= 1

          if cause == :caller do
            owner_ref = Process.monitor(owner)
            Process.exit(owner, :kill)
            assert_receive {:DOWN, ^owner_ref, :process, ^owner, _}
            assert_receive {:"ETS-TRANSFER", ^notice, ^owner, :zero_start}
          end

          :erlang.resume_process(pid)
          refute_receive :callback_started, 20, "callback must not start past its zero start gate"
          assert_receive {:DOWN, ^ref, :process, ^pid, :normal}
        after
          if owner != self(), do: Process.exit(owner, :kill)
          Process.exit(pid, :kill)
          Process.demonitor(ref, [:flush])
          :ets.delete(notice)
        end
      end
    after
      Custody.release(handle)
    end
  end

  test "R12-8 down after contribution does not complete another contributor" do
    {handle, token} = Runtime.real_key()
    tag = make_ref()
    slot = {:custody, 0}
    notice = :ets.new(:contributor_caller, [:private])
    table = :ets.new(:contributor_child, [:private])
    pid = spawn(Unwrap, :run, [tag, 0, Bounds.now() + 2_000_000, 2, self(), slot, self(), notice])
    ref = Process.monitor(pid)

    try do
      :ets.give_away(table, pid, {tag, :slot, slot})
      send(pid, {tag, :contribution, 0, 0, handle, [], self()})
      send(pid, {tag, :contributor_down, 0})
      refute_receive {^tag, :unwrap_summary, _, _}, 20, "contributor and down must share one key"
      send(pid, {tag, :contributor_down, 1})
      assert_receive {^tag, :unwrap_summary, 0, _}
      assert is_binary(token)
    after
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}
      :ets.delete(notice)
      Custody.release(handle)
    end
  end

  for {name, topology} <- [
        {"9a caller death in resolver phase", :resolvers},
        {"9a caller death with queued notices", :queued},
        {"9a caller death in custody phase", :custody}
      ] do
    test name do
      Runtime.with_peer(fn ->
        s = Runtime.start(1_000, unquote(topology))

        try do
          result = Runtime.trigger(s, :caller)

          assert Enum.all?(result.refs, fn {_, ended} -> ended end),
                 "every created process needs an end marker"

          assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
        after
          Runtime.cleanup(s)
        end
      end)
    end
  end

  test "10 coordinator death without reply sweeps registered children" do
    s = Runtime.start(10, :resolvers)

    try do
      result = Runtime.trigger(s, :coordinator)

      assert Enum.all?(result.refs, fn {_, ended} -> ended end),
             "registry sweep must cover all slot kinds"

      assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
    after
      Runtime.cleanup(s)
    end
  end

  test "late resolution never reaches content authentication" do
    {handle, token} = Runtime.real_key()
    observer = self()

    p =
      Runtime.policy(handle, %{
        timeout: 100,
        resolve_timeout: 10,
        unwrap_timeout: 10,
        key_resolver: fn _ ->
          send(observer, {:late_resolver, self()})
          Process.sleep(50)
          {:ok, %{algorithm: "A256KW", key: handle}}
        end
      })

    try do
      assert {:ok, [{:error, %{reason: :key_resolver_failed}}]} =
               JWE.decrypt_many([%{token: token, expected: %{}}], p),
             "resolution gate must reject late answers"
    after
      Custody.release(handle)
    end
  end

  test "review9 admission precedence and review10 cardinality" do
    {handle, token} = Runtime.real_key()
    p = Runtime.policy(handle)

    try do
      assert {:ok, []} = JWE.decrypt_many([], p)
      assert {:error, %{reason: :invalid_serialization}} = JWE.decrypt_many([1 | 2], p)
      assert {:error, %{reason: :limit}} = JWE.decrypt_many([1, 2 | :bad], %{p | max_tokens: 1})

      assert {:ok,
              [{:error, %{reason: :invalid_policy}}, {:error, %{reason: :invalid_serialization}}]} =
               JWE.decrypt_many([%{token: token, expected: %{"alg" => 1}}, :bad], p)
    after
      Custody.release(handle)
    end
  end

  test "digest preserves exact handle equality across processes" do
    {handle, _} = Runtime.real_key()

    try do
      observer = self()

      for _ <- 1..2 do
        spawn(fn ->
          send(
            observer,
            {:digest, :crypto.hash(:sha256, :erlang.term_to_binary(handle, [:deterministic]))}
          )
        end)
      end

      assert_receive {:digest, one}
      assert_receive {:digest, two}
      assert one == two
    after
      Custody.release(handle)
    end
  end

  test "16 and 24 strict admission boundary and 18 late result gate" do
    assert Bounds.before?(99, 100)
    refute Bounds.before?(100, 100), "admission must be strictly before R"
    refute Bounds.before?(101, 100)

    for phase <- [:unadmitted, :ready] do
      refute Coordinator.result_phase?(phase), "result gate must reject unresolved positions"
    end

    for phase <- [:resolved, :refused, :width], do: assert(Coordinator.result_phase?(phase))
  end

  test "24 exhaustive base64 rejection and 2049 canonical round trips" do
    for n <- 0..2_048 do
      bytes = :binary.copy(<<rem(n, 256)>>, n)
      assert Codec.decode(Base.url_encode64(bytes, padding: false)) == bytes
    end

    for byte <- 0..255,
        byte not in ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" do
      assert catch_throw(Codec.decode(<<byte>>)) == {:jose_error, :invalid_base64, :input}
    end
  end

  test "anchors use D and accepted n exactly once at the coordinator flip" do
    s = controlled()
    tag = s.tag
    :erlang.trace_pattern({Guard, :stop_at, 2}, [{:_, [], [{:return_trace}]}], [:local])
    :erlang.trace(s.guard, true, [:call, {:tracer, self()}])

    try do
      send(s.preflight, {tag, :policy, Runtime.policy(s.handle)})
      send(s.preflight, {tag, :count, 10_000})
      assert_receive {:trace, guard, :return_from, {Guard, :stop_at, 2}, stop_at}, 1_000
      assert guard == s.guard
      assert stop_at == s.d + Bounds.teardown(10_000), "D must remain the teardown anchor"
      assert_receive {:DOWN, _, :process, _, :replied}

      refute_receive {:trace, _, :return_from, {Guard, :stop_at, 2}, _},
                     20,
                     "stop_at must be computed exactly once"
    after
      :erlang.trace_pattern({Guard, :stop_at, 2}, false, [:local])
      dispose(s)
    end
  end

  test "causes close and outcome row wins with transfer and EXIT still queued" do
    s = controlled()
    tag = s.tag

    try do
      true = :erlang.suspend_process(s.guard)
      send(s.preflight, {tag, :policy, Runtime.policy(s.handle)})
      send(s.preflight, {tag, :count, 0})
      send(s.preflight, {tag, :input_end})
      assert_receive {^tag, :reply, :ok, 0, 0}
      Runtime.await(fn -> :ets.info(s.registry, :owner) == s.guard end)

      assert :ets.lookup(s.registry, :outcome) == [{:outcome, :replied}],
             "outcome row must precede reply"

      Process.sleep(Bounds.remaining(s.d + Bounds.finalization() + Bounds.teardown(0)) + 1)
      :erlang.resume_process(s.guard)

      assert_receive {:DOWN, _, :process, _, :replied},
                     1_000,
                     "causes close at the owner flip and reason comes from outcome row"
    after
      dispose(s)
    end
  end

  test "registry is the guards own table and forged transfer is ignored" do
    s = Runtime.start(10, :resolvers)
    :erlang.trace_pattern({Guard, :check, 1}, true, [:local])

    try do
      [tag | _] =
        Enum.find_value(s.events, fn
          {:spawn, _, _, Guard, :run, args, _} -> args
          _ -> nil
        end)

      {forger, ref} =
        spawn_monitor(fn ->
          :ets.new(:forged_registry, [:protected, {:heir, s.guard, {tag, :registry}}])
        end)

      assert_receive {:DOWN, ^ref, :process, ^forger, :normal}

      s =
        Runtime.collect_until(s, fn current ->
          Enum.any?(current.events, fn
            {:received, pid, {:"ETS-TRANSFER", _, ^forger, {^tag, :registry}}} ->
              pid == current.guard

            _ ->
              false
          end)
        end)

      s =
        Runtime.collect_until(s, fn current ->
          current.events
          |> Enum.take_while(fn
            {:received, pid, {:"ETS-TRANSFER", _, ^forger, {^tag, :registry}}} ->
              pid != current.guard

            _ ->
              true
          end)
          |> Enum.any?(fn
            {:trace_ts, pid, :call, {Guard, :check, [_]}, _} -> pid == current.guard
            _ -> false
          end)
        end)

      checked =
        Enum.find_value(s.events, fn
          {:trace_ts, pid, :call, {Guard, :check, [state]}, _} when pid == s.guard -> state
          _ -> nil
        end)

      assert checked != nil and :ets.info(checked.registry, :name) == :registry,
             "guard must sweep its own registry after a forged transfer"

      result = Runtime.trigger(s, :caller)

      assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1))),
             "guard must sweep its own registry after a forged transfer"
    after
      :erlang.trace_pattern({Guard, :check, 1}, false, [:local])
      Runtime.cleanup(s)
    end
  end

  test "17 R during bootstrap preserves every accepted position" do
    s = controlled(500_000, :batch, 300_000)
    tag = s.tag

    try do
      send(s.preflight, {tag, :policy, Runtime.policy(s.handle)})
      send(s.preflight, {tag, :count, 2})
      Runtime.await(fn -> :atomics.get(s.flag, 2) == 2 end)
      Process.sleep(Bounds.remaining(s.d - 299_000))
      # Wake the shipped loop after R while preflight still awaits its items.
      # Without this dequeue the broken R branch can sleep until D unobserved.
      send(s.coordinator, {tag, :cardinality, 2, Bounds.now()})

      refute_receive {^tag, :reply, _, _, _},
                     100,
                     "R must not return before bootstrap ends"

      assert_receive {^tag, :reply, :ok, 2, 0}, 1_000, "R must not return before bootstrap ends"
      assert length(drain_settled(tag, [])) == 2
    after
      dispose(s)
    end
  end

  test "blocked resolvers held across R through U end within the original U bound" do
    Runtime.with_peer(fn ->
      n = Bounds.max_tokens()

      s =
        Runtime.start(n, :resolvers,
          trace_input: false,
          near_cap: true,
          policy: %{timeout: 15_000, resolve_timeout: 10_000, unwrap_timeout: 1_000}
        )

      try do
        [_, _, _, _, _, r, d, _, unwrap] =
          Enum.find_value(s.events, fn
            {:spawn, _, _, Guard, :run, args, _} -> args
            _ -> nil
          end)

        u = r + unwrap
        assert Bounds.now() < r, "all blocked resolvers must be placed before R"
        true = :erlang.suspend_process(s.coordinator)
        assert Enum.all?(s.resolvers, &Process.alive?/1)
        s = Runtime.until(s, u)
        true = :erlang.resume_process(s.coordinator)
        result = Runtime.collect_ends(s, u + Bounds.teardown(n))

        assert result.remaining == 0,
               "blocked resolvers must end within B(n) after U rather than wait for D"

        assert Bounds.now() < d, "teardown must not wait for D"
        assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
        result = Runtime.collect_return(result, u + Bounds.teardown(n)) |> Runtime.delivered()
        assert {:ok, results} = result.return
        assert length(results) == n

        assert Enum.all?(
                 results,
                 &match?({:error, %{reason: :key_resolver_failed, layer: :key}}, &1)
               ),
               "R must retain the resolver failure cell when the coordinator resumes after U"

        refute Enum.any?(result.pids, fn {_, role} -> role == :custody end)
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "an early resolution barrier keeps U when its notices arrive after R" do
    Runtime.with_peer(fn ->
      s =
        Runtime.start(1, :queued,
          policy: %{timeout: 1_000, resolve_timeout: 500, unwrap_timeout: 50}
        )

      try do
        [_, _, _, _, _, r | _] =
          Enum.find_value(s.events, fn
            {:spawn, _, _, Guard, :run, args, _} -> args
            _ -> nil
          end)

        # Resolution is accepted before R, while its real end notice remains
        # queued at the guard. Joining that notice cannot grant a fresh U.
        s =
          Runtime.collect_until(s, fn current ->
            Enum.any?(current.messages, fn
              {:trace_ts, pid, :receive, {_, :resolved, 0, {:ok, _}}, _} ->
                pid == current.coordinator

              _ ->
                false
            end)
          end)

        Process.sleep(Bounds.remaining(r + 1_000))
        :erlang.resume_process(s.guard)
        result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()

        assert match?({:ok, [{:error, %{reason: :decryption_failed}}]}, result.return),
               "joining late notices must not extend U"

        refute Enum.any?(result.pids, fn {_, role} -> role == :custody end),
               "expired U must start no custody process"
      after
        Runtime.cleanup(s)
      end
    end)
  end

  test "21 R12-7 terminal map retains input key and crypto layers" do
    assert Coordinator.expiry(:r, :unadmitted) == {:deadline_exceeded, :input, nil},
           "R admission must retain the input cell"

    assert Coordinator.expiry(:r, :ready) == {:key_resolver_failed, :key, nil}

    for phase <- [:unadmitted, :ready, :resolved, :refused, :width] do
      assert Coordinator.expiry(:d, phase) == {:deadline_exceeded, :crypto, nil}
    end
  end

  test "review11 256th cell and R12-7 single late cardinality keep the outer deadline" do
    for mode <- [:single, :batch] do
      s = controlled(100_000, mode)
      tag = s.tag

      try do
        p = Runtime.policy(s.handle)

        p =
          if mode == :single,
            do: Map.drop(p, [:max_tokens, :max_total_input, :max_total_plaintext]),
            else: p

        send(s.preflight, {tag, :policy, p})
        Runtime.await(fn -> Runtime.info(s.preflight, :status) == :waiting end)
        true = :erlang.suspend_process(s.preflight)
        send(s.preflight, {tag, :count, if(mode == :single, do: 1, else: 256)})
        assert Runtime.info(s.preflight, :message_queue_len) >= 1
        Process.sleep(Bounds.remaining(s.d))
        :erlang.resume_process(s.preflight)

        assert_receive {^tag, :reply, {:outer, :deadline_exceeded, :crypto}, nil, 0},
                       1_000,
                       "late cardinality must retain the outer deadline"

        assert :atomics.get(s.flag, 2) == 0
        assert_receive {:DOWN, _, :process, _, :replied}, 1_000
      after
        dispose(s)
      end
    end
  end

  test "R and D terminal cells agree through single and batch open" do
    for mode <- [:single, :batch], clock <- [:r, :d] do
      s =
        Runtime.start(1, :resolvers,
          single: mode == :single,
          policy: %{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}
        )

      try do
        if clock == :d do
          true = :erlang.suspend_process(s.coordinator)

          d =
            Enum.find_value(s.events, fn
              {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d | _], _} -> d
              _ -> nil
            end)

          Process.sleep(Bounds.remaining(d))
          :erlang.resume_process(s.coordinator)
        end

        result = Runtime.collect_until(s, &(&1.return != nil)) |> Runtime.delivered()
        outcome = if mode == :single, do: result.return, else: elem(result.return, 1) |> hd()

        if clock == :r do
          assert {:error, %{reason: :key_resolver_failed, layer: :key}} = outcome
        else
          assert {:error, %{reason: :deadline_exceeded, layer: :crypto}} = outcome
        end

        assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1)))
      after
        Runtime.cleanup(s)
      end
    end
  end

  test "zero start custody gate refuses caller death and U before callback" do
    {handle, _} = Runtime.real_key()
    observer = self()
    original = handle.ref

    observed = %{
      handle
      | ref: fn ->
          send(observer, :custody_callback_started)
          original.()
        end
    }

    try do
      for cause <- [:caller, :u] do
        tag = make_ref()
        notice = :ets.new(:custody_gate_caller, [:private, {:heir, self(), :custody_caller}])
        table = :ets.new(:custody_gate_child, [:private])

        owner =
          if cause == :caller do
            spawn(fn ->
              receive do
                {:"ETS-TRANSFER", _, _, :custody_caller} -> send(observer, :custody_caller_owns)
              end

              receive do
                :stop -> :ok
              end
            end)
          else
            self()
          end

        if cause == :caller do
          :ets.give_away(notice, owner, :custody_caller)
          assert_receive :custody_caller_owns
        end

        u = Bounds.now() + 100_000
        pid = spawn(Unwrap, :run, [tag, 0, u, 1, self(), {:custody, 0}, owner, notice])
        ref = Process.monitor(pid)

        try do
          :ets.give_away(table, pid, {tag, :slot, {:custody, 0}})
          Runtime.await(fn -> Runtime.info(pid, :status) == :waiting end)
          true = :erlang.suspend_process(pid)
          send(pid, {tag, :contribution, 0, 0, observed, [], self()})
          assert Runtime.info(pid, :message_queue_len) >= 1

          if cause == :caller do
            owner_ref = Process.monitor(owner)
            Process.exit(owner, :kill)
            assert_receive {:DOWN, ^owner_ref, :process, ^owner, _}
            assert_receive {:"ETS-TRANSFER", ^notice, ^owner, :custody_caller}
          else
            Process.sleep(Bounds.remaining(u))
          end

          :erlang.resume_process(pid)

          # Sensitive processes suppress call tracing. The shipped summary is
          # sent only after entering the guarded custody block, even when the
          # downstream Custody boundary also refuses a dead owner or expired U.
          refute_receive {^tag, :unwrap_summary, 0, _},
                         100,
                         "custody callback must not start past its gate"

          refute_receive :custody_callback_started,
                         20,
                         "custody callback must not start past its gate"

          assert_receive {:DOWN, ^ref, :process, ^pid, :normal}
        after
          Process.exit(pid, :kill)
          if owner != self(), do: Process.exit(owner, :kill)
          Process.demonitor(ref, [:flush])
          if :ets.info(notice, :owner) == self(), do: :ets.delete(notice)
        end
      end
    after
      Custody.release(handle)
    end
  end

  test "zero start placed after each gate runs and is then cancelled" do
    for topology <- [:resolvers, :custody] do
      s = Runtime.start(1, topology)

      try do
        assert s.resolvers != []
        if topology == :custody, do: assert(s.custody != [])
        result = Runtime.trigger(s, :caller)

        assert Enum.all?(result.refs, fn {_, ended} -> ended end),
               "callback past gate must still be cancelled"
      after
        Runtime.cleanup(s)
      end
    end
  end

  test "worker death kills its live resolvers before R" do
    s = Runtime.start(10, :resolvers)

    try do
      # The coordinator must cancel these itself, before the guard's sweep.
      true = :erlang.suspend_process(s.guard)

      {:spawn, _, worker, _, _, [_, _, _, _, lo, hi | _], _} =
        Enum.find(s.events, fn
          {:spawn, _, _, RequestSeal.JOSE.JWE.Worker, :run, _, _} -> true
          _ -> false
        end)

      owned =
        for {:spawn, _, pid, Resolver, :run, [_, i | _], _} <- s.events,
            i >= lo and i <= hi,
            do: pid

      assert owned != []
      Process.exit(worker, :kill)
      until = Bounds.now() + 1_000_000
      await_dead(owned, until)

      assert Enum.all?(owned, &(not Process.alive?(&1))),
             "worker death must kill its resolvers before R"
    after
      Runtime.cleanup(s)
    end
  end

  defp await_dead(pids, until) do
    if Enum.any?(pids, &Process.alive?/1) and Bounds.now() < until do
      Process.sleep(1)
      await_dead(pids, until)
    end
  end
end
