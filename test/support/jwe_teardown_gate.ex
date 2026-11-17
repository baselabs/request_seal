defmodule RequestSeal.Test.JWETeardownGate do
  @moduledoc false
  import ExUnit.Assertions
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Coordinator, Guard, Worker}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @samples 5
  @load_attempts 30
  @placement_attempts 20
  @cap 10_000

  def run do
    scenarios = for {name, trigger} <- [{"S1", :caller}, {"S4", :f}, {"S5", :d}, {"S7", :u}],
      topology <- [:resolvers, :queued, :custody] do
      samples = for _ <- 1..@samples do
        load = reference_load()
        sample = Runtime.with_peer(fn -> sample(trigger, topology) end)
        Map.put(sample, :load, load)
      end
      %{scenario: "#{name}/#{topology}", times_us: Enum.map(samples, & &1.elapsed),
        loads: Enum.map(samples, & &1.load), placements: Enum.map(samples, & &1.placement)}
    end
    handoffs = for _ <- 1..@samples do
      reference_load()
      Runtime.with_peer(fn -> handoff(@placement_attempts) end, 1)
    end
    byte_scenarios = for unit <- [:token_scan, :expected, :name] do
      samples = for _ <- 1..@samples do
        Runtime.with_peer(fn ->
          load = reference_load()
          Map.put(byte_deadline(unit, @placement_attempts), :load, load)
        end, 2)
      end
      %{scenario: "D/#{unit}", times_us: Enum.map(samples, & &1.elapsed),
        loads: Enum.map(samples, & &1.load), placements: Enum.map(samples, & &1.placement),
        preflight_exit_us: Enum.map(samples, & &1.exit)}
    end
    measured_units = units()
    units = Map.new(measured_units, fn {name, samples} -> {name, Enum.map(samples, & &1.time)} end)
    unit_loads = Map.new(measured_units, fn {name, samples} -> {name, Enum.map(samples, & &1.load)} end)
    longest = units |> Map.drop([:final_report, :preflight_exit, :aead]) |> Map.values() |> List.flatten() |> Enum.max()
    # A full cooperative exit interval is an upper bound on exit alone. Include
    # every byte placement rather than deriving K_pf from the empty exit only.
    exits = units.preflight_exit ++ Enum.map(handoffs, & &1.exit) ++
      Enum.flat_map(byte_scenarios, & &1.preflight_exit_us)
    exit = Enum.max(exits)
    derived = longest + Enum.max(units.final_report) + exit
    %{scenarios: scenarios ++ byte_scenarios ++ [%{scenario: "S5c", times_us: Enum.map(handoffs, & &1.elapsed),
        loads: Enum.map(handoffs, & &1.load), placements: Enum.map(handoffs, & &1.placement)}],
      units_us: units, units_loads: unit_loads, derived_k_pf_us: derived,
      derivation: %{longest_unit_us: longest, final_report_us: Enum.max(units.final_report),
        exit_upper_bound_us: exit}, s5c_exit_us: Enum.map(handoffs, & &1.exit),
      constants: %{n: @cap, b_us: Bounds.teardown(@cap), k_pf_us: Bounds.preflight(),
        load_attempts: @load_attempts, placement_attempts: @placement_attempts,
        schedulers_online: System.schedulers_online(), otp: List.to_string(:erlang.system_info(:otp_release)),
        elixir: System.version()}}
  end

  def reference_load(attempts \\ @load_attempts, seen \\ [])
  def reference_load(0, seen), do: raise("reference load unavailable: #{inspect(Enum.reverse(seen))}")
  def reference_load(attempts, seen) do
    [first | _] = File.read!("/proc/loadavg") |> String.split()
    load = String.to_float(first)
    if load <= System.schedulers_online() do
      load
    else
      Process.sleep(1_000)
      reference_load(attempts - 1, [load | seen])
    end
  end

  defp sample(trigger, topology) do
    :erlang.trace_pattern({Coordinator, :resolution_end, 2}, [{:_, [], [{:return_trace}]}], [:local])
    s = Runtime.start(@cap, topology, near_cap: true,
      policy: %{timeout: 30_000, resolve_timeout: 20_000, unwrap_timeout: 5_000})
    try do
      {_, _, _, _, _, _, args, _} = Enum.find(s.events, fn
        {:spawn, _, _, Guard, :run, _, _} -> true
        _ -> false
      end) |> normalize_spawn()
      [_tag, _caller, _address, _flag, _mode, _r, d, f, unwrap] = args
      {anchor, s, placement} = case trigger do
        :caller -> {Bounds.now(), s, "#{topology}: caller notice owner flip"}
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
              s = Runtime.collect_until(s, fn current -> resolution_stamp(current) != nil end)
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
      last = result.events |> Enum.flat_map(fn
        {:end, _, at, _} -> [at]
        _ -> []
      end) |> Enum.max()
      assert Enum.all?(Map.keys(result.pids), &(not Process.alive?(&1))), "gate: process survived teardown"
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
    if left > 0, do: (Process.sleep(min(left, 1_000)); wait_until(at))
  end

  def handoff_sample, do: handoff(@placement_attempts)
  def byte_sample(unit), do: byte_deadline(unit, @placement_attempts)

  defp handoff(0), do: raise("S5c: no verified one-scheduler placement")
  defp handoff(attempts) do
    load = reference_load()
    s = Runtime.launch(@cap, :resolvers, near_cap: true,
      policy: %{timeout: 10_000, resolve_timeout: 5_000, unwrap_timeout: 1_000})
    result = try do
      s = Runtime.collect_until(s, fn s -> Enum.any?(s.pids, fn {_, role} -> role == :worker end) end)
      if catch_suspend(s.preflight) do
        s = Runtime.collect_until(s, fn s -> Enum.any?(s.messages, fn
          {:trace_ts, _, :send, {_, :workers_done}, _, _} -> true
          _ -> false
        end) end)
        d = s.events |> Enum.find_value(fn
          {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
          _ -> nil
        end)
        if Runtime.info(s.preflight, :message_queue_len) < 2 or Bounds.now() >= d - 1_000 do
          :retry
        else
          wait_until(d - 1_000)
          :erlang.resume_process(s.preflight)
          result = finish(s) |> Runtime.delivered()
          result = Runtime.collect_return(result, d + Bounds.finalization() + Bounds.teardown(@cap))
          exit_at = Enum.find_value(result.events, fn
            {:end, pid, at, :normal} when pid == s.preflight -> at
            _ -> nil
          end)
          handed = Enum.any?(result.messages, fn
            {:trace_ts, _, :receive, {_, :handed_off}, _} -> true
            _ -> false
          end)
          assert not handed, "handoff must exit by D plus K_pf: placement finished before D"
          assert is_integer(exit_at), "handoff must exit by D plus K_pf: cooperative exit missing"
          assert {:ok, results} = result.return, "S5c must return the accepted cardinality"
          assert length(results) == @cap, "S5c must return the accepted cardinality"
          assert Enum.all?(results, &match?({:error, %{reason: :deadline_exceeded, layer: :crypto}}, &1)),
            "S5c must fill the D crypto cells"
          end_at = result.events |> Enum.flat_map(fn
            {:end, _, at, _} -> [at]
            _ -> []
          end) |> Enum.max()
          %{exit: max(0, exit_at - d), elapsed: end_at - d, load: load,
            placement: "one scheduler; workers_done queued; resumed 1 ms before D"}
        end
      else
        :retry
      end
    after
      Runtime.cleanup(s)
    end
    case result do
      :retry -> handoff(attempts - 1)
      sample -> sample
    end
  end

  defp byte_deadline(_, 0), do: raise("byte unit: no verified placement")
  defp byte_deadline(unit, attempts) do
    {expected, token, extra, functions} = case unit do
      :token_scan -> {%{}, :binary.copy(" ", 1_048_568) <> ".b.c.d.e", %{}, [:json_serialization?, :separators]}
      :expected -> {%{"" => :binary.copy("x", 16_384)}, "", %{}, [:utf8?, :depth, :tree]}
      :name -> {%{}, "", %{}, [:utf8?]}
    end
    # Each name must itself be UTF-8; four decimal digits keep exactly 16 KiB.
    extra = if unit == :name do
      %{protected: %{permitted: for(i <- 1..64, do: :binary.copy("x", 16_380) <> String.pad_leading(Integer.to_string(i), 4, "0"))}}
    else
      extra
    end
    s = Runtime.launch(1, :resolvers,
      policy: Map.merge(%{timeout: 500, resolve_timeout: 300, unwrap_timeout: 100}, extra),
      items: [%{token: token, expected: expected}])
    try do
      s = Runtime.collect_until(s, &(&1.preflight != nil))
      if Process.alive?(s.preflight) do
        catch_suspend(s.preflight)
        # The worker may already have consumed its policy. Resume into the
        # actual unit and verify current_function after suspending it there.
        d = Enum.find_value(s.events, fn
          {:spawn, _, _, Guard, :run, [_, _, _, _, _, _, d, _, _], _} -> d
          _ -> nil
        end)
        :erlang.resume_process(s.preflight)
        placed = suspend_in_unit(s.preflight, functions, d)
        if placed do
          wait_until(d)
          :erlang.resume_process(s.preflight)
          result = finish(s)
          last = result.events |> Enum.flat_map(fn {:end, _, at, _} -> [at]; _ -> [] end) |> Enum.max()
          exit_at = Enum.find_value(result.events, fn
            {:end, pid, at, :normal} when pid == s.preflight -> at
            _ -> nil
          end)
          assert exit_at != nil, "byte unit must end cooperatively"
          %{elapsed: last - d, exit: exit_at - d,
            placement: "production sensitive preflight suspended inside #{unit} across D"}
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
      :retry -> byte_deadline(unit, attempts - 1)
      result -> result
    end
  end

  defp catch_suspend(pid) do
    try do :erlang.suspend_process(pid) catch _, _ -> false end
  end
  defp suspend_in_unit(pid, functions, d) do
    if Bounds.now() >= d do
      false
    else
      case Runtime.info(pid, :current_function) do
        {Codec, function, _} when function in [:utf8?, :depth, :tree, :json_serialization?, :separators] ->
          if function in functions and catch_suspend(pid) do
            case Runtime.info(pid, :current_function) do
              {Codec, ^function, _} -> true
              _ -> :erlang.resume_process(pid); suspend_in_unit(pid, functions, d)
            end
          else
            suspend_in_unit(pid, functions, d)
          end
        nil -> false
        _ -> suspend_in_unit(pid, functions, d)
      end
    end
  end

  def units do
    flag = :atomics.new(2, [])
    token = :binary.copy(" ", 1_048_568) <> ".b.c.d.e"
    expected = %{"" => :binary.copy("x", 16_384)}
    names = [:binary.copy("x", 16_384)]
    {handle, _} = Runtime.real_key()
    p = Runtime.policy(handle, %{protected: %{permitted: names}})
    try do
      %{separator_and_accounting: measure(fn -> Codec.split(token) end),
        expected_validation_and_serialization: measure(fn -> Codec.expected(expected, []) end),
        permitted_name_validation: measure(fn -> Codec.policy(p, true, flag, Bounds.now() + 1_000_000) end),
        final_report: measure(fn -> send(self(), :gate_final_report); receive do :gate_final_report -> :ok end end),
        preflight_exit: measure(fn ->
          {pid, ref} = spawn_monitor(fn -> exit(:normal) end)
          receive do {:DOWN, ^ref, :process, ^pid, _} -> :ok end
        end),
        aead: for(_ <- 1..@samples, do: aead_unit())}
    after
      RequestSeal.Custody.release(handle)
    end
  end
  defp measure(fun) do
    for _ <- 1..@samples do
      load = reference_load()
      started = Bounds.now()
      fun.()
      %{time: Bounds.now() - started, load: load}
    end
  end
  defp aead_unit do
    key = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(12)
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, :binary.copy("x", 1_048_576), "", 16, true)
    token = %{enc: "A256GCM", iv: iv, ct: ct, protected: "", tag: tag, width_valid: true,
      alg: "dir", h: %{}}
    load = reference_load()
    observer = self()
    {pid, ref} = spawn_monitor(fn ->
      :erlang.process_flag(:sensitive, true)
      started = Bounds.now()
      {{:ok, _}, :ok} = Worker.authenticate(token, {:ok, key}, {:ok, key}, %{content: :binary})
      send(observer, {:aead_time, self(), Bounds.now() - started})
    end)
    elapsed = receive do
      {:aead_time, ^pid, us} -> us
      {:DOWN, ^ref, :process, ^pid, reason} -> flunk("AEAD unit failed: #{inspect(reason)}")
    after
      5_000 -> Process.exit(pid, :kill); flunk("AEAD unit timed out")
    end
    receive do {:DOWN, ^ref, :process, ^pid, :normal} -> %{time: elapsed, load: load} end
  end
end
