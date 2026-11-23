defmodule RequestSeal.Test.JWETeardownGate do
  @moduledoc false
  import ExUnit.Assertions
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Coordinator, Guard, Open, Worker}
  alias RequestSeal.Test.HostConditions
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  alias RequestSeal.Test.JWEWorkerDiagnostics
  @samples 5
  @host_attempts 30
  @placement_attempts 20
  @cap 10_000
  @cpu_window_us 20_000

  def run do
    scenarios =
      for {name, trigger} <- [{"S1", :caller}, {"S4", :f}, {"S5", :d}, {"S7", :u}],
          topology <- [:resolvers, :queued, :custody] do
        samples =
          for _ <- 1..@samples do
            host_sample(fn -> sample(trigger, topology) end, :online)
          end

        %{
          scenario: "#{name}/#{topology}",
          times_us: Enum.map(samples, & &1.elapsed),
          loads: Enum.map(samples, & &1.load),
          steals: Enum.map(samples, & &1.steal),
          host_conditions: Enum.map(samples, & &1.host_conditions),
          placements: Enum.map(samples, & &1.placement),
          diagnostics: Enum.map(samples, & &1.diagnostics)
        }
      end

    handoffs =
      for _ <- 1..@samples do
        host_sample(fn -> handoff(@placement_attempts) end, 1)
      end

    byte_scenarios =
      for unit <- [:token_scan, :expected, :name] do
        samples =
          for _ <- 1..@samples do
            host_sample(fn -> byte_deadline(unit, @placement_attempts) end, 2)
          end

        %{
          scenario: "D/#{unit}",
          times_us: Enum.map(samples, & &1.elapsed),
          loads: Enum.map(samples, & &1.load),
          steals: Enum.map(samples, & &1.steal),
          host_conditions: Enum.map(samples, & &1.host_conditions),
          placements: Enum.map(samples, & &1.placement),
          preflight_exit_us: Enum.map(samples, & &1.exit),
          diagnostics: Enum.map(samples, & &1.diagnostics)
        }
      end

    {measured_units, observer_queue, setup} = units()
    # Preserve five exit upper bounds, including every cooperative placement.
    exits =
      for i <- 0..(@samples - 1) do
        candidates =
          [Enum.at(measured_units.preflight_exit, i), Enum.at(handoffs, i)] ++
            Enum.map(byte_scenarios, fn row ->
              %{
                exit: Enum.at(row.preflight_exit_us, i),
                load: Enum.at(row.loads, i),
                steal: Enum.at(row.steals, i),
                host_conditions: Enum.at(row.host_conditions, i)
              }
            end)

        candidate = Enum.max_by(candidates, &Map.get(&1, :time, Map.get(&1, :exit)))
        Map.put(candidate, :time, Map.get(candidate, :time, Map.get(candidate, :exit)))
      end

    measured_units = Map.put(measured_units, :preflight_exit, exits)

    units =
      Map.new(measured_units, fn {name, samples} ->
        {name, Enum.map(samples, & &1.time)}
      end)

    longest =
      units
      |> Map.drop([:final_report, :preflight_exit, :aead])
      |> Map.values()
      |> List.flatten()
      |> Enum.max()

    exit = Enum.max(units.preflight_exit)
    derived = longest + Enum.max(units.final_report) + exit

    scenarios =
      scenarios ++
        byte_scenarios ++
        [
          %{
            scenario: "S5c",
            times_us: Enum.map(handoffs, & &1.elapsed),
            loads: Enum.map(handoffs, & &1.load),
            steals: Enum.map(handoffs, & &1.steal),
            host_conditions: Enum.map(handoffs, & &1.host_conditions),
            placements: Enum.map(handoffs, & &1.placement),
            diagnostics: Enum.map(handoffs, & &1.diagnostics)
          }
        ]

    scenarios =
      Enum.map(scenarios, &Map.put(&1, :headroom, Enum.max(&1.times_us) / Bounds.teardown(@cap)))

    %{
      scenarios: scenarios,
      units_us: units,
      unit_setup: setup,
      units_details:
        Map.new(measured_units, fn {name, samples} ->
          {name, Enum.map(samples, &Map.get(&1, :details, %{}))}
        end),
      units_loads:
        Map.new(measured_units, fn {name, samples} ->
          {name, Enum.map(samples, & &1.load)}
        end),
      units_steals:
        Map.new(measured_units, fn {name, samples} ->
          {name, Enum.map(samples, & &1.steal)}
        end),
      units_host_conditions:
        Map.new(measured_units, fn {name, samples} ->
          {name, Enum.map(samples, & &1.host_conditions)}
        end),
      derived_k_pf_us: derived,
      headroom: %{derived_k_pf: derived / Bounds.preflight()},
      derivation: %{
        longest_unit_us: longest,
        final_report_us: Enum.max(units.final_report),
        exit_upper_bound_us: exit
      },
      s5c_exit_us: Enum.map(handoffs, & &1.exit),
      constants: %{
        n: @cap,
        b_us: Bounds.teardown(@cap),
        k_pf_us: Bounds.preflight(),
        host_attempts: @host_attempts,
        placement_attempts: @placement_attempts,
        cpu_window_min_us: @cpu_window_us,
        collection_cap_us: Runtime.collection_cap()
      },
      host: host(),
      final_report_observer_queue: observer_queue
    }
  end

  def host do
    %{
      schedulers_online: System.schedulers_online(),
      logical_cpus: HostConditions.logical_cpus(),
      cpu_model: cpu_model(File.read!("/proc/cpuinfo")),
      otp: List.to_string(:erlang.system_info(:otp_release)),
      elixir: System.version()
    }
  end

  def cpu_model(text) do
    Enum.find_value(String.split(text, "\n"), "unknown", fn line ->
      case String.split(line, ":", parts: 2) do
        [key, value] ->
          if String.trim(key) in ["model name", "Hardware", "Processor"],
            do: String.trim(value)

        _ ->
          nil
      end
    end)
  end

  defp host_sample(fun, schedulers \\ :local) do
    sample =
      case schedulers do
        :local -> fn -> observe_host_sample(fun) end
        _ -> fn -> Runtime.with_peer(fn -> observe_host_sample(fun) end, schedulers) end
      end

    host_sample(sample, @host_attempts, [])
  end

  defp host_sample(_, 0, seen),
    do: raise("host condition exhausted: #{inspect(Enum.reverse(seen), limit: :infinity)}")

  defp host_sample(sample, attempts, seen) do
    {result, observation} = sample.()
    seen = [observation | seen]

    if observation.admitted do
      Map.merge(result, %{
        load: observation.load,
        steal: observation.steal,
        host_conditions: Enum.reverse(seen)
      })
    else
      Process.sleep(1_000)
      host_sample(sample, attempts - 1, seen)
    end
  end

  defp observe_host_sample(fun) do
    cpus = HostConditions.logical_cpus()
    loadavg = File.read!("/proc/loadavg") |> String.trim()
    [first | _] = String.split(loadavg)
    load = String.to_float(first)
    cpu_before = HostConditions.cpu_stat()
    process_before = HostConditions.process_snapshot(:before)
    window = Bounds.now()
    result = fun.()
    # CPU accounting uses ticks. Extend only the observation window, outside
    # every timed unit, so a sub-tick unit still has a measurable denominator.
    wait_until(window + @cpu_window_us)
    process_after = HostConditions.process_snapshot(:after)
    cpu_after = HostConditions.cpu_stat()

    observation =
      cpu_before
      |> HostConditions.metrics(cpu_after, process_before, process_after, cpus)
      |> Map.merge(%{
        load: load,
        loadavg: loadavg,
        cpu_before: cpu_before,
        cpu_after: cpu_after,
        process_before: process_before,
        process_after: process_after,
        schedulers_online: System.schedulers_online()
      })

    {result, observation}
  end

  # Verify lanes call this same driver, including its trace pattern, policy,
  # near-cap inputs, placement, timestamped ends and independent collection cap.
  def sample(trigger, topology) do
    :erlang.trace_pattern({Coordinator, :resolution_end, 2}, [{:_, [], [{:return_trace}]}], [
      :local
    ])

    :erlang.trace_pattern({Open, :wait_end, 1}, true, [:local])

    phases = [expire_u: 1, expire_workers: 3, worker_down: 3, reply: 2, finish: 1]

    for {function, arity} <- phases do
      :erlang.trace_pattern({Coordinator, function, arity}, true, [:local])
    end

    for {function, arity} <- [kill: 3, stop_at: 2, finish: 1] do
      :erlang.trace_pattern({Guard, function, arity}, true, [:local])
    end

    :erlang.trace_pattern({:ets, :foldl, 3}, [{:_, [], [{:return_trace}]}], [:local])
    :erlang.trace_pattern({Guard, :sweep_registry, 1}, [{:_, [], [{:return_trace}]}], [:local])

    s =
      Runtime.start(@cap, topology,
        trace_input: false,
        trace_messages: false,
        near_cap: true,
        policy: %{timeout: 30_000, resolve_timeout: 20_000, unwrap_timeout: 5_000}
      )

    worker_diagnostics = JWEWorkerDiagnostics.start(s)

    try do
      {_, _, _, _, _, _, args, _} =
        Enum.find(s.events, fn
          {:spawn, _, _, Guard, :run, _, _} -> true
          _ -> false
        end)
        |> normalize_spawn()

      [tag, _caller, _address, _flag, _mode, _r, d, f, unwrap] = args
      :erlang.trace(s.guard, true, [:arity])
      s = Runtime.quiet(s)
      setup = library_snapshot(s)

      {anchor, s, placement} =
        case trigger do
          :caller ->
            {Bounds.now(), s, "#{topology}: caller notice owner flip"}

          :f ->
            true = :erlang.suspend_process(s.coordinator)
            s = Runtime.until(s, f)
            {f, s, "#{topology}: coordinator suspended through F"}

          :d ->
            true = :erlang.suspend_process(s.coordinator)
            s = Runtime.until(s, d)
            send(s.coordinator, {tag, :wake})
            :erlang.resume_process(s.coordinator)
            {d, s, "#{topology}: D before resuming coordinator"}

          :u ->
            # U is reachable after R'. Starting from blocked resolvers requires
            # completing resolution; queued notices retain P3 until their join.
            case topology do
              :resolvers ->
                [_, _, _, _, _, r | _] = args
                assert Bounds.now() < r, "all blocked resolvers must be placed before R"
                true = :erlang.suspend_process(s.coordinator)
                assert Enum.all?(s.resolvers, &Process.alive?/1)
                at = r + unwrap
                s = Runtime.until(s, at)

                # Debug suspension pauses receive timers since OTP 28 and
                # PID-addressed BIF timers since OTP 29, including abs: true.
                # Ordinary descheduling leaves the due wake queued. Restore
                # that event before resume; do not grant a fresh phase clock.
                # https://www.erlang.org/doc/apps/erts/erlang.html#suspend_process/2
                send(s.coordinator, {tag, :wake})
                :erlang.resume_process(s.coordinator)
                {at, s, "P2: coordinator held across R through U; resolvers blocked"}

              :queued ->
                s =
                  Runtime.collect_event(s, fn
                    {:trace_ts, _, :return_from, {Coordinator, :resolution_end, 2}, _, _} -> true
                    _ -> false
                  end)

                at = resolution_stamp(s) + unwrap
                s = Runtime.until(s, at)
                {at, s, "P2 end: resolver notices queued at guard through U"}

              :custody ->
                at = member_u(s)
                s = Runtime.until(s, at)
                {at, s, "P3: custody callbacks blocked through U"}
            end
        end

      {anchor, result} =
        if trigger == :caller do
          # Reduction oracles use Runtime.trigger/2. Their VM-wide statistics
          # barrier is setup, never caller-death announcement or teardown work.
          # The queued topology holds the guard suspended until the trigger,
          # exactly as Runtime.trigger/2 and finish/1 release it.
          at = Bounds.now()
          Process.exit(s.caller, :kill)
          {at, finish(s)}
        else
          {anchor, finish(s)}
        end

      result = if result.remaining == 0, do: Runtime.delivered(result), else: result

      {result, failures} =
        if trigger == :u and topology == :resolvers do
          result = Runtime.collect_return(result) |> Runtime.delivered()

          failures =
            checks(fn ->
              assert is_integer(result.return_at) and result.return_at < d,
                     "teardown must not wait for D"

              # The public bound is wait-end, before cleanup and handlers.
              # This peer has no handlers; retain its return stamp as well.
              wait_end =
                Enum.find_value(result.events, fn
                  {:trace_ts, pid, :call, {Open, :wait_end, [at]}, _}
                  when pid == s.caller ->
                    at

                  _ ->
                    nil
                end)

              assert is_integer(wait_end) and wait_end <= f + Bounds.teardown(@cap),
                     "caller wait must end by F plus B"

              assert wait_end <= result.return_at
              assert result.return_at <= f + Bounds.teardown(@cap)
              assert {:ok, results} = result.return
              assert length(results) == @cap

              assert Enum.all?(
                       results,
                       &match?({:error, %{reason: :key_resolver_failed, layer: :key}}, &1)
                     ),
                     "R must retain the resolver failure cell when the coordinator resumes after U"

              refute Enum.any?(result.pids, fn {_, role} -> role == :custody end)
            end)

          {result, failures}
        else
          {result, []}
        end

      measured = measurement(result, anchor, placement, failures)

      measured
      |> put_in([:diagnostics, :library_before_trigger], setup)
      |> put_in(
        [:diagnostics, :workers],
        JWEWorkerDiagnostics.collect(worker_diagnostics, if(trigger == :u, do: anchor, else: nil))
      )
    after
      Runtime.cleanup(s)
      :erlang.trace_pattern({Coordinator, :resolution_end, 2}, false, [:local])
      :erlang.trace_pattern({Open, :wait_end, 1}, false, [:local])

      for {function, arity} <- phases do
        :erlang.trace_pattern({Coordinator, function, arity}, false, [:local])
      end

      for {function, arity} <- [kill: 3, stop_at: 2, finish: 1] do
        :erlang.trace_pattern({Guard, function, arity}, false, [:local])
      end

      :erlang.trace_pattern({:ets, :foldl, 3}, false, [:local])
      :erlang.trace_pattern({Guard, :sweep_registry, 1}, false, [:local])
    end
  end

  defp resolution_stamp(s) do
    Enum.find_value(s.events, fn
      {:trace_ts, _, :return_from, {Coordinator, :resolution_end, 2}, at, _} -> at
      _ -> nil
    end)
  end

  defp normalize_spawn({:spawn, a, b, c, d, e, f}), do: {:spawn, a, b, c, d, nil, e, f}

  defp member_u(s) do
    case Enum.find_value(s.messages, fn
           {:trace_ts, _, :send, {_, :member, _, _, _, u, _}, _, _} -> u
           _ -> nil
         end) do
      nil -> raise "gate: custody placement has no member deadline"
      u -> u
    end
  end

  defp live_roles(s) do
    s.pids
    |> Enum.filter(fn {pid, _} -> Process.alive?(pid) end)
    |> Enum.map(fn {pid, role} ->
      %{role: role, function: inspect(Runtime.info(pid, :current_function))}
    end)
  end

  defp checks(fun) do
    fun.()
    []
  rescue
    error in ExUnit.AssertionError -> [Exception.message(error)]
  end

  defp library_snapshot(s) do
    for {pid, role} <- [{s.caller, :caller} | Map.to_list(s.pids)],
        role in [:caller, :guard, :coordinator, :worker],
        do: %{
          role: role,
          pid: inspect(pid),
          reductions: Runtime.info(pid, :reductions),
          memory: Runtime.info(pid, :memory),
          queue: Runtime.info(pid, :message_queue_len)
        }
  end

  defp measurement(s, anchor, placement, failures) do
    ended = for {:end, _, at, _} <- s.events, do: at
    missing = for {pid, role} <- s.pids, not is_map_key(s.ends, pid), do: role
    live = live_roles(s)
    complete = s.remaining == 0 and missing == [] and live == []
    last = Enum.max(ended, fn -> anchor end)
    last = if complete, do: last, else: max(last, Bounds.now())

    ends =
      for {:end, pid, at, reason} <- s.events,
          do: %{role: s.pids[pid], end_us: at - anchor, reason: end_reason(reason)}

    late = Enum.filter(ends, &(&1.end_us > Bounds.teardown(@cap)))

    role_ends =
      ends
      |> Enum.group_by(&{&1.role, &1.reason})
      |> Enum.map(fn {{role, reason}, rows} ->
        times = Enum.map(rows, & &1.end_us)

        %{
          role: role,
          reason: reason,
          count: length(rows),
          first_us: Enum.min(times),
          last_us: Enum.max(times)
        }
      end)

    phases =
      for {:trace_ts, pid, :call, {Coordinator, function, arity}, at} <- s.events,
          pid == s.coordinator and is_integer(arity),
          function in [:expire_u, :expire_workers, :worker_down, :reply, :finish],
          do: %{
            phase: function,
            at_us: :erlang.convert_time_unit(at, :native, :microsecond) - anchor
          }

    guard_phases =
      for {:trace_ts, pid, :call, {Guard, function, arity}, at} <- s.events,
          pid == s.guard and is_integer(arity),
          function in [:kill, :stop_at, :finish],
          do: %{
            phase: function,
            at_us: :erlang.convert_time_unit(at, :native, :microsecond) - anchor
          }

    sweeps =
      for {:trace_ts, pid, :return_from, {module, function, _}, awaiting, at} <- s.events,
          pid == s.guard and is_integer(awaiting),
          {module, function} in [{:ets, :foldl}, {Guard, :sweep_registry}],
          do: %{
            at_us: :erlang.convert_time_unit(at, :native, :microsecond) - anchor,
            awaiting: awaiting
          }

    observations =
      for {:end_observed, pid, at, dequeued, queue} <- s.events,
          do: %{
            role: s.pids[pid],
            end_us: at - anchor,
            observer_dequeue_us: dequeued - anchor,
            observer_lag_us: dequeued - at,
            receiver_queue: queue
          }

    receiver_ends =
      observations
      |> Enum.group_by(& &1.role)
      |> Enum.map(fn {role, rows} ->
        %{
          role: role,
          count: length(rows),
          first_us: Enum.min_by(rows, & &1.end_us).end_us,
          last: Enum.max_by(rows, & &1.end_us),
          max_observer_lag_us: Enum.max_by(rows, & &1.observer_lag_us).observer_lag_us,
          max_receiver_queue: Enum.max_by(rows, & &1.receiver_queue).receiver_queue
        }
      end)

    caller_exit =
      Enum.find_value(s.events, fn
        {:caller_exit, at} -> at - anchor
        _ -> nil
      end)

    %{
      elapsed: last - anchor,
      placement: placement,
      diagnostics: %{
        remaining: s.remaining,
        workers: [],
        missing_end_roles: missing,
        live_roles: live,
        late_roles: late,
        role_ends: role_ends,
        library_ends:
          Enum.filter(ends, &(&1.role in [:guard, :coordinator, :preflight, :worker])),
        coordinator_phases: Enum.reverse(phases),
        guard_phases: Enum.reverse(guard_phases),
        guard_sweeps: Enum.reverse(sweeps),
        birth_roles: Enum.frequencies(Map.values(s.pids)),
        receiver_ends: receiver_ends,
        caller_exit_us: caller_exit || :null,
        return_us: if(is_integer(s.return_at), do: s.return_at - anchor, else: :null),
        failures: failures
      }
    }
  end

  # Caller-code exit payloads never belong in an artifact. Library reasons are
  # closed atoms; keep only those known lifecycle reasons for every role.
  defp end_reason(reason)
       when reason in [:normal, :killed, :replied, :deadline, :internal_failure],
       do: reason

  defp end_reason(_), do: :caller_code_failure

  defp finish(s) do
    if s.topology == :queued, do: :erlang.resume_process(s.guard)
    Runtime.collect_ends(s)
  end

  defp wait_until(at) do
    left = Bounds.remaining(at)

    if left > 0,
      do:
        (
          Process.sleep(min(left, 1_000))
          wait_until(at)
        )
  end

  def handoff_sample, do: handoff(@placement_attempts)
  def byte_sample(unit), do: byte_deadline(unit, @placement_attempts)

  defp handoff(attempts, seen \\ [])

  defp handoff(0, seen),
    do: raise("S5c placement budget exhausted: #{inspect(Enum.reverse(seen))}")

  defp handoff(attempts, seen) do
    s =
      Runtime.launch(@cap, :resolvers,
        trace_input: false,
        trace_messages: false,
        near_cap: true,
        policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 1_000}
      )

    result =
      try do
        s =
          Runtime.collect_until(s, fn s ->
            Enum.any?(s.pids, fn {_, role} -> role == :worker end)
          end)

        if catch_suspend(s.preflight) do
          s =
            Runtime.collect_until(s, fn s ->
              Enum.any?(s.messages, fn
                {:trace_ts, _, :send, {_, :workers_done}, _, _} -> true
                _ -> false
              end)
            end)

          d =
            s.events
            |> Enum.find_value(fn
              {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
              _ -> nil
            end)

          if Runtime.info(s.preflight, :message_queue_len) < 2 or Bounds.now() >= d - 1_000 do
            :retry
          else
            worker_diagnostics = JWEWorkerDiagnostics.start(s)

            s = Runtime.quiet(s) |> Runtime.until(d - 1_000)
            :erlang.resume_process(s.preflight)
            result = finish(s) |> Runtime.delivered()

            result = Runtime.collect_return(result)

            exit_at =
              Enum.find_value(result.events, fn
                {:end, pid, at, :normal} when pid == s.preflight -> at
                _ -> nil
              end)

            handed =
              Enum.any?(result.messages, fn
                {:trace_ts, _, :receive, {_, :handed_off}, _} -> true
                _ -> false
              end)

            if handed do
              {:retry, :handoff_finished_before_d}
            else
              failures =
                checks(fn ->
                  assert is_integer(exit_at),
                         "handoff must exit by D plus K_pf: cooperative exit missing"

                  assert {:ok, results} = result.return,
                         "S5c must return the accepted cardinality"

                  assert length(results) == @cap, "S5c must return the accepted cardinality"

                  assert Enum.all?(
                           results,
                           &match?({:error, %{reason: :deadline_exceeded, layer: :crypto}}, &1)
                         ),
                         "S5c must fill the D crypto cells"
                end)

              placement =
                "one scheduler; workers_done queued; resumed 1 ms before D; " <>
                  "attempt #{@placement_attempts - attempts + 1}/#{@placement_attempts}"

              result
              |> measurement(d, placement, failures)
              |> Map.merge(%{
                exit: max(0, (exit_at || Bounds.now()) - d),
                placement_attempts: @placement_attempts - attempts + 1
              })
            end
            |> case do
              %{diagnostics: _} = sample ->
                put_in(
                  sample,
                  [:diagnostics, :workers],
                  JWEWorkerDiagnostics.collect(worker_diagnostics)
                )

              retry ->
                retry
            end
          end
        else
          :retry
        end
      after
        Runtime.cleanup(s)
      end

    case result do
      :retry -> handoff(attempts - 1, [:placement_unavailable | seen])
      {:retry, reason} -> handoff(attempts - 1, [reason | seen])
      sample -> sample
    end
  end

  defp byte_deadline(unit, attempts, seen \\ [])

  defp byte_deadline(unit, 0, seen),
    do: raise("#{unit} placement budget exhausted: #{inspect(Enum.reverse(seen))}")

  defp byte_deadline(unit, attempts, seen) do
    {expected, token, extra, functions} =
      case unit do
        :token_scan ->
          {%{}, :binary.copy(" ", 1_048_568) <> ".b.c.d.e", %{}, [:separators]}

        :expected ->
          {%{"" => :binary.copy("x", 16_384)}, "", %{}, [:utf8?, :depth, :tree]}

        :name ->
          {%{}, "", %{}, [:utf8?]}
      end

    # Each name must itself be UTF-8; four decimal digits keep exactly 16 KiB.
    extra =
      if unit == :name do
        names =
          for i <- 1..64 do
            :binary.copy("x", 16_380) <> String.pad_leading(Integer.to_string(i), 4, "0")
          end

        %{protected: %{permitted: names}}
      else
        extra
      end

    s =
      Runtime.launch(1, :resolvers,
        trace_input: false,
        trace_messages: false,
        policy: Map.merge(%{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}, extra),
        items: [%{token: token, expected: expected}]
      )

    try do
      s = Runtime.collect_until(s, &(&1.preflight != nil))

      if catch_suspend(s.preflight) do
        # The worker may already have consumed its policy. Resume into the
        # actual unit and verify its retained frame after suspending it there.
        d =
          Enum.find_value(s.events, fn
            {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
            _ -> nil
          end)

        :erlang.resume_process(s.preflight)
        placed = suspend_in_unit(s.preflight, functions, d)

        if placed do
          s = Runtime.quiet(s) |> Runtime.until(d)
          :erlang.resume_process(s.preflight)
          result = finish(s)

          exit_at =
            Enum.find_value(result.events, fn
              {:end, pid, at, :normal} when pid == s.preflight -> at
              _ -> nil
            end)

          failures = checks(fn -> assert exit_at != nil, "byte unit must end cooperatively" end)

          placement =
            "production sensitive preflight suspended inside #{unit} across D; " <>
              "attempt #{@placement_attempts - attempts + 1}/#{@placement_attempts}"

          result
          |> measurement(d, placement, failures)
          |> Map.put(:exit, (exit_at || Bounds.now()) - d)
        else
          :retry
        end
      else
        :retry
      end
    after
      Runtime.cleanup(s)
    end
    |> case do
      :retry -> byte_deadline(unit, attempts - 1, [:unit_not_placed_before_d | seen])
      result -> result
    end
  end

  defp catch_suspend(pid) do
    try do
      :erlang.suspend_process(pid)
    catch
      :error, :badarg -> false
    end
  end

  defp suspend_in_unit(pid, functions, d) do
    cond do
      Bounds.now() >= d ->
        false

      catch_suspend(pid) ->
        if Runtime.in_codec_unit?(pid, functions) do
          true
        else
          :erlang.resume_process(pid)
          suspend_in_unit(pid, functions, d)
        end

      true ->
        false
    end
  end

  def prepare_units do
    # These modules are entered before the production byte-unit checkpoint:
    # Codec.unit/2 and policy precede split, and Worker.run precedes AEAD.
    # Load code only; never invoke a measured operation or discard a sample.
    for module <- [Codec, Worker] do
      loaded = :code.is_loaded(module) != false
      started = Bounds.now()
      {:module, ^module} = :code.ensure_loaded(module)
      %{module: module, loaded_before: loaded, load_us: Bounds.now() - started}
    end
  end

  def units do
    setup = prepare_units()
    flag = :atomics.new(2, [])
    token = :binary.copy(" ", 1_048_568) <> ".b.c.d.e"
    json = :binary.copy(" \t\r\n", 262_143) <> "  {}"
    expected = %{"" => :binary.copy("x", 16_384)}
    names = [:binary.copy("x", 16_384)]
    {handle, _} = Runtime.real_key()
    p = Runtime.policy(handle, %{protected: %{permitted: names}})

    {observer, ref} =
      :erlang.spawn_opt(
        fn ->
          receive do
            :stop -> :ok
          end
        end,
        [:monitor, {:message_queue_data, :off_heap}]
      )

    {:message_queue_data, observer_queue} = Process.info(observer, :message_queue_data)

    try do
      samples = %{
        separator_and_accounting:
          measure(fn ->
            # Both the compact refusal and a JSON candidate can occupy the
            # whole byte unit. Keep the slower production path in each sample.
            compact_at = Bounds.now()
            Codec.split(token)
            compact = Bounds.now() - compact_at
            json_at = Bounds.now()
            Codec.split(json)
            json = Bounds.now() - json_at
            {:measured, max(compact, json), %{compact_us: compact, json_us: json}}
          end),
        expected_validation_and_serialization: measure(fn -> Codec.expected(expected, []) end),
        permitted_name_validation:
          measure(fn ->
            Codec.policy(p, true, flag, Bounds.now() + 1_000_000)
          end),
        final_report: measure(fn -> final_report(observer, token, p) end),
        preflight_exit: for(_ <- 1..@samples, do: host_sample(fn -> exit_unit() end)),
        aead: for(_ <- 1..@samples, do: host_sample(fn -> aead_unit() end))
      }

      {samples, observer_queue, setup}
    after
      stop_unit(observer, ref)
      RequestSeal.Custody.release(handle)
    end
  end

  defp final_report(observer, token, p) do
    tag = make_ref()
    # Production sends rows separately; never benchmark an invented bulk report.
    # Cover its largest row and policy, the cap count and every final control.
    reports = [
      {tag, :cardinality, @cap, Bounds.now()},
      {tag, :preflight, :ok},
      {tag, :row, @cap - 1, {Runtime.near_cap(), Codec.split(token)}},
      {tag, :policy, p},
      {tag, :handed_off},
      {tag, :preflight, :deadline},
      {tag, :preflight, {:outer, :invalid_policy, :input}}
    ]

    longest =
      Enum.map(reports, fn report ->
        started = Bounds.now()
        send(observer, report)
        Bounds.now() - started
      end)
      |> Enum.max()

    {:measured, longest}
  end

  defp measure(fun) do
    for _ <- 1..@samples, do: host_sample(fn -> sensitive_unit(fun) end)
  end

  defp sensitive_unit(fun) do
    observer = self()

    {pid, ref} =
      spawn_monitor(fn ->
        :erlang.process_flag(:sensitive, true)
        :erlang.process_flag(:message_queue_data, :off_heap)
        started = Bounds.now()
        result = fun.()
        elapsed = Bounds.now() - started

        {time, details} =
          case result do
            {:measured, time, details} -> {time, details}
            {:measured, time} -> {time, %{}}
            _ -> {elapsed, %{}}
          end

        send(observer, {:unit_time, self(), time, details})
      end)

    try do
      await_unit(pid, ref)
    after
      stop_unit(pid, ref)
    end
  end

  defp await_unit(pid, ref) do
    receive do
      {:unit_time, ^pid, time, details} ->
        receive do
          {:DOWN, ^ref, :process, ^pid, :normal} -> %{time: time, details: details}
        end

      {:DOWN, ^ref, :process, ^pid, reason} ->
        flunk("unit failed: #{inspect(reason)}")

      _ ->
        await_unit(pid, ref)
    after
      5_000 -> flunk("unit timed out")
    end
  end

  defp exit_unit do
    observer = self()
    end_observer = Runtime.end_observer()

    {pid, ref} =
      spawn_monitor(fn ->
        :erlang.process_flag(:sensitive, true)
        :erlang.process_flag(:message_queue_data, :off_heap)
        send(observer, {:exit_ready, self()})

        receive do
          :exit -> exit(:normal)
        end
      end)

    try do
      receive do
        {:exit_ready, ^pid} -> :ok
      end

      {_, tracer, _} = end_observer
      watch = make_ref()
      send(tracer, {:watch, pid, watch})
      send(tracer, {:barrier, self(), watch})

      receive do
        {:trace_delivered, :all, ^watch} -> :ok
      end

      started = Bounds.now()
      send(pid, :exit)

      receive do
        {:end_observed, ^watch, ^pid, :normal, at, _} ->
          %{time: :erlang.convert_time_unit(at, :native, :microsecond) - started}
      after
        5_000 -> flunk("exit unit timed out")
      end
    after
      stop_unit(pid, ref)
      Runtime.stop_end_observer(end_observer)
    end
  end

  defp stop_unit(pid, ref) do
    ended = Process.monitor(pid)
    Process.exit(pid, :kill)

    receive do
      {:DOWN, ^ended, :process, ^pid, _} -> :ok
    end

    Process.demonitor(ref, [:flush])
  end

  defp aead_unit do
    key = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(12)
    protected = Base.url_encode64(~s({"alg":"dir","enc":"A256GCM"}), padding: false)

    {ct, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        iv,
        :binary.copy("x", 1_048_576),
        protected,
        16,
        true
      )

    token = %{
      enc: "A256GCM",
      iv: iv,
      ct: ct,
      protected: protected,
      tag: tag,
      width_valid: true,
      alg: "dir"
    }

    observer = self()

    {pid, ref} =
      spawn_monitor(fn ->
        :erlang.process_flag(:sensitive, true)
        started = Bounds.now()
        {{:ok, _}, :ok} = Worker.authenticate(token, {:ok, key}, {:ok, key}, %{content: :binary})
        send(observer, {:aead_time, self(), Bounds.now() - started})
      end)

    try do
      elapsed =
        receive do
          {:aead_time, ^pid, us} -> us
          {:DOWN, ^ref, :process, ^pid, reason} -> flunk("AEAD unit failed: #{inspect(reason)}")
        after
          5_000 -> flunk("AEAD unit timed out")
        end

      receive do
        {:DOWN, ^ref, :process, ^pid, :normal} -> %{time: elapsed}
      end
    after
      stop_unit(pid, ref)
    end
  end
end

# Cross-process process_info requests run on the target. Capture worker gauges
# before the trigger and after measurement, never by polling during teardown.
# A pre-trigger U snapshot carries its offset; exited workers have no end gauge.
# GC totals use a VM-wide interval, never an invented per-worker attribution.
defmodule RequestSeal.Test.JWEWorkerDiagnostics do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.Bounds

  def start(s) do
    u =
      Enum.find_value(s.messages, fn
        {:trace_ts, _, :send, {_, :member, _, _, _, u, _}, _, _} -> u
        _ -> nil
      end)

    vm = vm_gc()
    workers = for {pid, :worker} <- s.pids, into: %{}, do: {pid, snapshot(pid)}
    %{workers: workers, u: u, vm: vm}
  end

  def collect(s, u \\ nil) do
    u = u || s.u
    vm = vm_gc()

    for {pid, initial} <- s.workers do
      ended = snapshot(pid)
      observed = Bounds.now()
      at_u = if initial != nil and is_integer(u) and initial.sampled_us <= u, do: initial

      %{
        worker: inspect(pid),
        u_us: u || :null,
        at_u: at_u || :null,
        u_snapshot: :before_trigger,
        u_snapshot_offset_us: if(at_u != nil, do: at_u.sampled_us - u, else: :null),
        before_trigger: initial || :null,
        at_end: ended || :null,
        end_snapshot: :after_teardown,
        end_observed_us: observed,
        end_snapshot_age_us: if(ended != nil, do: observed - ended.sampled_us, else: :null),
        gc_scope: :vm_shared_interval,
        gc_count_delta: vm.count - s.vm.count,
        gc_words_reclaimed_delta: vm.words - s.vm.words
      }
    end
  end

  defp snapshot(pid) do
    case Process.info(pid, [:heap_size, :total_heap_size, :reductions]) do
      nil ->
        nil

      info ->
        gc =
          try do
            case Process.info(pid, :garbage_collection_info) do
              {:garbage_collection_info, values} ->
                for {key, value} <- values, is_integer(value), into: %{}, do: {key, value}

              nil ->
                %{}
            end
          catch
            :error, :badarg -> %{}
          end

        %{
          sampled_us: Bounds.now(),
          heap_words: Keyword.fetch!(info, :heap_size),
          total_heap_words: Keyword.fetch!(info, :total_heap_size),
          reductions: Keyword.fetch!(info, :reductions),
          garbage_collection_info: gc
        }
    end
  end

  defp vm_gc do
    {count, words, _} = :erlang.statistics(:garbage_collection)
    %{count: count, words: words}
  end
end
