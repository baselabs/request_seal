defmodule RequestSeal.Test.JWETeardownGate do
  @moduledoc false
  import ExUnit.Assertions
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Coordinator, Guard, Worker}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @samples 5
  @load_attempts 30
  @placement_attempts 20
  @cap 10_000
  @cpu_window_us 20_000

  def run do
    scenarios =
      for {name, trigger} <- [{"S1", :caller}, {"S4", :f}, {"S5", :d}, {"S7", :u}],
          topology <- [:resolvers, :queued, :custody] do
        samples =
          for _ <- 1..@samples do
            host_sample(fn -> Runtime.with_peer(fn -> sample(trigger, topology) end) end)
          end

        %{
          scenario: "#{name}/#{topology}",
          times_us: Enum.map(samples, & &1.elapsed),
          loads: Enum.map(samples, & &1.load),
          steals: Enum.map(samples, & &1.steal),
          host_conditions: Enum.map(samples, & &1.host_conditions),
          placements: Enum.map(samples, & &1.placement)
        }
      end

    handoffs =
      for _ <- 1..@samples do
        host_sample(fn -> Runtime.with_peer(fn -> handoff(@placement_attempts) end, 1) end, 1)
      end

    byte_scenarios =
      for unit <- [:token_scan, :expected, :name] do
        samples =
          for _ <- 1..@samples do
            host_sample(
              fn ->
                Runtime.with_peer(fn -> byte_deadline(unit, @placement_attempts) end, 2)
              end,
              2
            )
          end

        %{
          scenario: "D/#{unit}",
          times_us: Enum.map(samples, & &1.elapsed),
          loads: Enum.map(samples, & &1.load),
          steals: Enum.map(samples, & &1.steal),
          host_conditions: Enum.map(samples, & &1.host_conditions),
          placements: Enum.map(samples, & &1.placement),
          preflight_exit_us: Enum.map(samples, & &1.exit)
        }
      end

    {measured_units, observer_queue} = units()
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
            placements: Enum.map(handoffs, & &1.placement)
          }
        ]

    scenarios =
      Enum.map(scenarios, &Map.put(&1, :headroom, Enum.max(&1.times_us) / Bounds.teardown(@cap)))

    %{
      scenarios: scenarios,
      units_us: units,
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
        load_attempts: @load_attempts,
        placement_attempts: @placement_attempts,
        cpu_window_min_us: @cpu_window_us
      },
      host: host(),
      final_report_observer_queue: observer_queue
    }
  end

  def host do
    logical =
      case :erlang.system_info(:logical_processors) do
        n when is_integer(n) and n > 0 -> n
        _ -> host_cpus()
      end

    %{
      schedulers_online: System.schedulers_online(),
      logical_cpus: logical,
      admission_cpus: host_cpus(),
      cpu_model: cpu_model(File.read!("/proc/cpuinfo")),
      otp: List.to_string(:erlang.system_info(:otp_release)),
      elixir: System.version()
    }
  end

  def host_cpus do
    case :erlang.system_info(:logical_processors_available) do
      n when is_integer(n) and n > 0 -> n
      _ -> System.schedulers_online()
    end
  end

  def steal_percent(before, after_cpu) do
    start = cpu_times(before)
    stop = cpu_times(after_cpu)
    elapsed = stop.total - start.total
    stolen = stop.steal - start.steal
    if elapsed > 0 and stolen >= 0 and stolen <= elapsed, do: 100 * stolen / elapsed, else: nil
  end

  def cpu_times(text) do
    ["cpu" | fields] = text |> String.split("\n") |> hd() |> String.split()
    values = fields |> Enum.take(8) |> Enum.map(&String.to_integer/1)
    true = length(values) == 8
    %{total: Enum.sum(values), steal: Enum.at(values, 7)}
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

  def host_admitted?(result, steal),
    do: result != nil and is_number(steal) and steal >= 0 and steal <= 5

  def host_sample(
        fun,
        online \\ System.schedulers_online(),
        attempts \\ @load_attempts,
        seen \\ []
      )

  def host_sample(_, _, 0, seen),
    do: raise("host condition exhausted: #{inspect(Enum.reverse(seen), limit: :infinity)}")

  def host_sample(fun, online, attempts, seen) do
    cpus = host_cpus()
    loadavg = File.read!("/proc/loadavg") |> String.trim()
    [first | _] = String.split(loadavg)
    load = String.to_float(first)
    before = File.read!("/proc/stat") |> String.split("\n") |> hd()
    window = Bounds.now()
    result = if load <= cpus, do: fun.(), else: nil
    # CPU accounting uses ticks. Extend only the observation window, outside
    # every timed unit, so a sub-tick unit still has a measurable denominator.
    wait_until(window + @cpu_window_us)
    after_cpu = File.read!("/proc/stat") |> String.split("\n") |> hd()
    steal = steal_percent(before, after_cpu)

    observation = %{
      load: load,
      steal: if(steal == nil, do: :null, else: steal),
      loadavg: loadavg,
      cpu_before: before,
      cpu_after: after_cpu,
      schedulers_online: online,
      admission_cpus: cpus
    }

    seen = [observation | seen]

    if host_admitted?(result, steal) do
      Map.merge(result, %{load: load, steal: steal, host_conditions: Enum.reverse(seen)})
    else
      Process.sleep(1_000)
      host_sample(fun, online, attempts - 1, seen)
    end
  end

  defp sample(trigger, topology) do
    :erlang.trace_pattern({Coordinator, :resolution_end, 2}, [{:_, [], [{:return_trace}]}], [
      :local
    ])

    s =
      Runtime.start(@cap, topology,
        trace_input: false,
        near_cap: true,
        policy: %{timeout: 30_000, resolve_timeout: 20_000, unwrap_timeout: 5_000}
      )

    try do
      {_, _, _, _, _, _, args, _} =
        Enum.find(s.events, fn
          {:spawn, _, _, Guard, :run, _, _} -> true
          _ -> false
        end)
        |> normalize_spawn()

      [_tag, _caller, _address, _flag, _mode, _r, d, f, unwrap] = args

      {anchor, s, placement} =
        case trigger do
          :caller ->
            {Bounds.now(), s, "#{topology}: caller notice owner flip"}

          :f ->
            true = :erlang.suspend_process(s.coordinator)
            wait_until(f)
            {f, s, "#{topology}: coordinator suspended through F"}

          :d ->
            true = :erlang.suspend_process(s.coordinator)
            wait_until(d)
            :erlang.resume_process(s.coordinator)
            {d, s, "#{topology}: D before resuming coordinator"}

          :u ->
            # U is reachable after R'. Starting from blocked resolvers requires
            # completing resolution; queued notices retain P3 until their join.
            case topology do
              :resolvers ->
                true = :erlang.suspend_process(s.coordinator)
                [_, _, _, _, _, r | _] = args
                at = r + unwrap
                wait_until(at)
                :erlang.resume_process(s.coordinator)
                {at, s, "P2: coordinator held across R through U; resolvers blocked"}

              :queued ->
                s =
                  Runtime.collect_event(s, fn
                    {:trace_ts, _, :return_from, {Coordinator, :resolution_end, 2}, _, _} -> true
                    _ -> false
                  end)

                at = resolution_stamp(s) + unwrap
                wait_until(at)
                {at, s, "P2 end: resolver notices queued at guard through U"}

              :custody ->
                at = member_u(s)
                wait_until(at)
                {at, s, "P3: custody callbacks blocked through U"}
            end
        end

      result = if trigger == :caller, do: Runtime.trigger(s, :caller), else: finish(s)

      last =
        result.events
        |> Enum.flat_map(fn
          {:end, _, at, _} -> [at]
          _ -> []
        end)
        |> Enum.max()

      assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1))),
             "gate: process survived teardown"

      %{elapsed: last - anchor, placement: placement}
    after
      Runtime.cleanup(s)
      :erlang.trace_pattern({Coordinator, :resolution_end, 2}, false, [:local])
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

  defp finish(s) do
    if s.topology == :queued, do: :erlang.resume_process(s.guard)
    Runtime.collect_until(s, fn s -> s.remaining == 0 end)
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
            wait_until(d - 1_000)
            :erlang.resume_process(s.preflight)
            result = finish(s) |> Runtime.delivered()

            result =
              Runtime.collect_return(
                result,
                d + Bounds.finalization() + Bounds.teardown(@cap)
              )

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
              assert is_integer(exit_at),
                     "handoff must exit by D plus K_pf: cooperative exit missing"

              assert {:ok, results} = result.return, "S5c must return the accepted cardinality"
              assert length(results) == @cap, "S5c must return the accepted cardinality"

              assert Enum.all?(
                       results,
                       &match?({:error, %{reason: :deadline_exceeded, layer: :crypto}}, &1)
                     ),
                     "S5c must fill the D crypto cells"

              end_at =
                result.events
                |> Enum.flat_map(fn
                  {:end, _, at, _} -> [at]
                  _ -> []
                end)
                |> Enum.max()

              %{
                exit: max(0, exit_at - d),
                elapsed: end_at - d,
                placement:
                  "one scheduler; workers_done queued; resumed 1 ms before D; " <>
                    "attempt #{@placement_attempts - attempts + 1}/#{@placement_attempts}",
                placement_attempts: @placement_attempts - attempts + 1
              }
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
          {%{}, :binary.copy(" ", 1_048_568) <> ".b.c.d.e", %{},
           [:json_serialization?, :separators]}

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
        policy: Map.merge(%{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}, extra),
        items: [%{token: token, expected: expected}]
      )

    try do
      s = Runtime.collect_until(s, &(&1.preflight != nil))

      if catch_suspend(s.preflight) do
        # The worker may already have consumed its policy. Resume into the
        # actual unit and verify current_function after suspending it there.
        d =
          Enum.find_value(s.events, fn
            {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
            _ -> nil
          end)

        :erlang.resume_process(s.preflight)
        placed = suspend_in_unit(s.preflight, functions, d)

        if placed do
          wait_until(d)
          :erlang.resume_process(s.preflight)
          result = finish(s)

          last =
            result.events
            |> Enum.flat_map(fn
              {:end, _, at, _} -> [at]
              _ -> []
            end)
            |> Enum.max()

          exit_at =
            Enum.find_value(result.events, fn
              {:end, pid, at, :normal} when pid == s.preflight -> at
              _ -> nil
            end)

          assert exit_at != nil, "byte unit must end cooperatively"

          %{
            elapsed: last - d,
            exit: exit_at - d,
            placement:
              "production sensitive preflight suspended inside #{unit} across D; " <>
                "attempt #{@placement_attempts - attempts + 1}/#{@placement_attempts}"
          }
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
      Bounds.now() >= d or Runtime.info(pid, :current_function) == nil ->
        false

      Runtime.in_codec_unit?(pid, functions) and catch_suspend(pid) ->
        if Runtime.in_codec_unit?(pid, functions) do
          true
        else
          :erlang.resume_process(pid)
          suspend_in_unit(pid, functions, d)
        end

      true ->
        suspend_in_unit(pid, functions, d)
    end
  end

  def units do
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
            {:measured, max(compact, Bounds.now() - json_at)}
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

      {samples, observer_queue}
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

        time =
          case result do
            {:measured, time} -> time
            _ -> elapsed
          end

        send(observer, {:unit_time, self(), time})
      end)

    try do
      await_unit(pid, ref)
    after
      stop_unit(pid, ref)
    end
  end

  defp await_unit(pid, ref) do
    receive do
      {:unit_time, ^pid, time} ->
        receive do
          {:DOWN, ^ref, :process, ^pid, :normal} -> %{time: time}
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

      started = Bounds.now()
      send(pid, :exit)

      receive do
        {:DOWN, ^ref, :process, ^pid, :normal} -> %{time: Bounds.now() - started}
      end
    after
      stop_unit(pid, ref)
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

    {ct, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        iv,
        :binary.copy("x", 1_048_576),
        "",
        16,
        true
      )

    token = %{
      enc: "A256GCM",
      iv: iv,
      ct: ct,
      protected: "",
      tag: tag,
      width_valid: true,
      alg: "dir",
      h: %{}
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
