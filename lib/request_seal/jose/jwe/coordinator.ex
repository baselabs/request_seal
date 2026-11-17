defmodule RequestSeal.JOSE.JWE.Coordinator do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.{Bounds, Preflight, Resolver, Unwrap, Worker}

  def run(tag, guard, caller, notice, address, flag, mode, r, d, unwrap) do
    :erlang.process_flag(:trap_exit, true)
    :erlang.process_flag(:message_queue_data, :off_heap)
    reason = try do
      registry = receive do
        {:'ETS-TRANSFER', registry, ^guard, {^tag, :registry}} -> registry
      end
      s = %{tag: tag, guard: guard, caller: caller, notice: notice, address: address,
        flag: flag, mode: mode, r: r, d: d, unwrap: unwrap, registry: registry,
        n: nil, settled: 0, admissions_left: nil, resolutions_left: 0, positions: %{}, workers: %{}, pids: %{}, resolver_pending: 0,
        ended: %{}, groups: %{}, digests: %{}, next_group: 0, rprime: nil,
        u: nil, started_groups: false, expired_r: false, expired_u: false,
        preflight: nil, handed_off: false, preflight_final: false}
      pid = start_child(:preflight, s, 0, 0, 0, 0)
      send(address, {tag, :preflight, pid})
      loop(%{s | preflight: pid})
    catch
      _, _ -> :internal_failure
    end
    finish(reason)
  end

  defp finish(reason), do: exit(reason)

  # All process creation is in this closed role dispatch. Every spawn argument is
  # an atom, bounded integer, pid, reference or table id, never input or a handle.
  defp start_child(kind, s, a, b, c, _e) do
    {slot, pid, role, notice} = case kind do
      :preflight ->
        pid = :erlang.spawn_opt(Preflight, :run, [s.tag, self(), s.flag, s.mode, s.d],
          [:link, {:message_queue_data, :off_heap}])
        {:preflight, pid, :library, nil}
      :worker ->
        pid = :erlang.spawn_opt(Worker, :run, [s.tag, self(), s.address, a, b, c, s.r, s.d, s.mode], [:link])
        {{:worker, a}, pid, :library, nil}
      :resolver ->
        slot = {:resolver, a}
        notice = :ets.new(:child_notice, [:private, {:heir, s.guard, {s.tag, :slot, slot}}])
        pid = :erlang.spawn_opt(Resolver, :run,
          [s.tag, a, b, s.r, self(), slot, s.caller, s.notice], [:link])
        {slot, pid, :caller, notice}
      :custody ->
        slot = {:custody, a}
        notice = :ets.new(:child_notice, [:private, {:heir, s.guard, {s.tag, :slot, slot}}])
        pid = :erlang.spawn_opt(Unwrap, :run,
          [s.tag, a, b, c, self(), slot, s.caller, s.notice], [:link])
        {slot, pid, :caller, notice}
    end
    :ets.insert(s.registry, {slot, pid, role})
    if role == :caller do
      :ets.give_away(notice, pid, {s.tag, :slot, slot})
      :erlang.unlink(pid)
    end
    pid
  end

  defp loop(s) do
    now = Bounds.now()
    cond do
      now >= s.d -> deadline(s)
      s.n != nil and s.settled == s.n and s.handed_off -> reply(s, :ok)
      true ->
        s = if not s.expired_r and now >= s.r and s.handed_off, do: expire_r(s), else: s
        s = barrier(s, now)
        s = if s.rprime != nil and s.resolver_pending == 0 and not s.started_groups,
          do: start_groups(s), else: s
        s = if s.u != nil and not s.expired_u and Bounds.now() >= s.u,
          do: expire_u(s), else: s
        receive_one(s)
    end
  end

  defp receive_one(s) do
    tag = s.tag
    guard = s.guard
    wait = cond do
      s.u != nil and not s.expired_u -> min(s.d, s.u)
      s.handed_off and not s.expired_r and s.rprime == nil -> min(s.d, s.r)
      true -> s.d
    end
    receive do
      {^tag, :cardinality, n, tc} when is_integer(n) and n >= 0 and n <= 10_000 ->
        loop(cardinality(s, n, tc))
      {^tag, :preflight, :ok} ->
        if Bounds.now() < s.d, do: loop(start_workers(s, 0, worker_count(s.n))), else: deadline(s)
      {^tag, :preflight, {:outer, reason, layer}} ->
        if Bounds.now() < s.d, do: reply(%{s | preflight_final: true}, {:outer, reason, layer}), else: deadline(s)
      {^tag, :preflight, :deadline} -> loop(%{s | preflight_final: true})
      {^tag, :handed_off} ->
        :erlang.exit(s.preflight, :kill)
        loop(%{s | handed_off: true, preflight_final: true})
      {^tag, :admitted, i, outcome} -> loop(admitted(s, i, outcome))
      {^tag, :resolved, i, outcome} -> loop(resolved(s, i, outcome))
      {^tag, :result, i, reason, layer, auth} -> loop(result(s, i, reason, layer, auth))
      {^tag, :ended, slot} -> loop(ended(s, slot))
      {^tag, :unwrap_summary, g, kind} -> loop(summary(s, g, kind))
      {:EXIT, ^guard, _} ->
        :ets.foldl(fn row, acc -> kill_registered(row); acc end, :ok, s.registry)
        :internal_failure
      {:EXIT, pid, _atom} ->
        if pid == s.preflight do
          if s.preflight_final, do: loop(%{s | preflight: nil}),
            else: reply(s, {:outer, :internal_failure, :internal})
        else
          loop(worker_down(s, pid))
        end
      _ -> loop(s)
    after
      Bounds.remaining(wait) -> loop(s)
    end
  end

  defp cardinality(%{n: nil} = s, n, tc) when tc < s.d do
    :atomics.put(s.flag, 2, n)
    %{s | n: n, admissions_left: n}
  end
  defp cardinality(s, _, _), do: s
  defp worker_count(0), do: 0
  defp worker_count(n), do: min(32, min(n, :erlang.system_info(:schedulers_online)))

  defp start_workers(s, k, k) do
    send(s.preflight, {s.tag, :workers_done})
    s
  end
  defp start_workers(s, w, k) do
    if Bounds.now() >= s.d do
      s
    else
      lo = div(w * s.n, k)
      hi = div((w + 1) * s.n, k) - 1
      pid = start_child(:worker, s, w, lo, hi, 0)
      send(s.preflight, {s.tag, :worker, w, lo, hi, pid})
      positions = init_positions(lo, hi, w, s.positions)
      s = %{s | workers: :maps.put(w, {pid, lo, hi, true}, s.workers),
        pids: :maps.put(pid, w, s.pids), positions: positions}
      start_workers(s, w + 1, k)
    end
  end

  defp init_positions(i, hi, _, positions) when i > hi, do: positions
  defp init_positions(i, hi, w, positions) do
    position = %{w: w, phase: :unadmitted, result: nil, resolver: nil, group: nil}
    init_positions(i + 1, hi, w, :maps.put(i, position, positions))
  end

  defp admitted(s, i, outcome) do
    case :maps.find(i, s.positions) do
      {:ok, %{phase: :unadmitted, result: nil} = p} ->
        if Bounds.before?(Bounds.now(), s.r) do
          {pid, _, _, alive} = :maps.get(p.w, s.workers)
          case outcome do
            :ready when alive ->
              resolver = start_child(:resolver, s, i, pid, 0, 0)
              send(pid, {s.tag, :resolver, i, resolver})
              put(s, i, %{p | phase: :ready, resolver: resolver}, 1)
            :width_failed -> put(s, i, %{p | phase: :width}, 0)
            {:error, reason, layer} -> put(s, i, %{p | phase: :refused, result: {reason, layer, nil}}, 0)
            _ -> s
          end
        else
          s
        end
      _ -> s
    end
  end

  defp put(s, i, p, pending) do
    old = :maps.get(i, s.positions, %{phase: :unadmitted, result: nil})
    admissions = if old.phase == :unadmitted and p.phase != :unadmitted, do: 1, else: 0
    resolution = cond do
      old.phase != :ready and p.phase == :ready -> 1
      old.phase == :ready and p.phase != :ready -> -1
      true -> 0
    end
    settled = if old.result == nil and p.result != nil, do: 1, else: 0
    %{s | positions: :maps.put(i, p, s.positions),
      resolver_pending: s.resolver_pending + pending,
      admissions_left: s.admissions_left - admissions,
      resolutions_left: s.resolutions_left + resolution, settled: s.settled + settled}
  end

  defp resolved(s, i, outcome) do
    case :maps.find(i, s.positions) do
      {:ok, %{phase: :ready, result: nil} = p} ->
        if Bounds.before?(Bounds.now(), s.r) do
          :erlang.exit(p.resolver, :kill)
          case outcome do
            {:ok, digest} when is_binary(digest) and byte_size(digest) == 32 ->
              {g, s} = group(s, digest, p.w)
              put(s, i, %{p | phase: :resolved, group: g}, 0)
            {:error, reason, layer} -> put(s, i, %{p | phase: :refused, result: {reason, layer, nil}}, 0)
            :refused -> put(s, i, %{p | phase: :refused}, 0)
            _ -> s
          end
        else
          s
        end
      _ -> s
    end
  end

  defp group(s, digest, w) do
    {g, s} = case :maps.find(digest, s.digests) do
      {:ok, g} -> {g, s}
      :error ->
        g = s.next_group
        group = %{members: 0, workers: %{}, pid: nil, started: nil, duration: nil}
        {g, %{s | digests: :maps.put(digest, g, s.digests), groups: :maps.put(g, group, s.groups), next_group: g + 1}}
    end
    group = :maps.get(g, s.groups)
    counts = :maps.put(w, :maps.get(w, group.workers, 0) + 1, group.workers)
    {g, %{s | groups: :maps.put(g, %{group | members: group.members + 1, workers: counts}, s.groups)}}
  end

  def result_phase?(phase), do: phase in [:resolved, :refused, :width]

  defp result(s, i, reason, layer, auth) do
    case :maps.find(i, s.positions) do
      {:ok, %{phase: phase, result: nil} = p} ->
        if result_phase?(phase) and Bounds.now() < s.d, do: put(s, i, %{p | result: {reason, layer, auth}}, 0), else: s
      _ -> s
    end
  end

  defp ended(s, {:resolver, i} = slot) do
    if is_map_key(s.ended, slot) do
      s
    else
      s = %{s | ended: :maps.put(slot, true, s.ended), resolver_pending: s.resolver_pending - 1}
      case :maps.find(i, s.positions) do
        {:ok, %{phase: :ready} = p} -> put(s, i, %{p | resolver: nil}, 0)
        _ -> s
      end
    end
  end
  defp ended(s, {:custody, g}), do: summary(s, g, :error)
  defp ended(s, _), do: s

  defp barrier(%{rprime: nil, admissions_left: 0, resolutions_left: 0, n: n} = s, now)
       when n != nil, do: %{s | rprime: resolution_end(now, s.r), u: min(now, s.r) + s.unwrap}
  defp barrier(s, _), do: s

  def resolution_end(now, r), do: min(now, r)

  def expiry(:r, :unadmitted), do: {:deadline_exceeded, :input, nil}
  def expiry(:r, :ready), do: {:key_resolver_failed, :key, nil}
  def expiry(:d, _phase), do: {:deadline_exceeded, :crypto, nil}

  defp expire_r(s) do
    s = expire_positions(:maps.to_list(s.positions), s)
    %{s | expired_r: true, rprime: s.r, u: s.r + s.unwrap}
  end
  defp expire_positions([], s), do: s
  defp expire_positions([{i, p} | rest], s) do
    s = if p.result == nil do
      case p.phase do
        :unadmitted -> put(s, i, %{p | phase: :refused, result: expiry(:r, :unadmitted)}, 0)
        :ready ->
          if p.resolver != nil, do: :erlang.exit(p.resolver, :kill)
          put(s, i, %{p | phase: :refused, result: expiry(:r, :ready)}, 0)
        _ -> s
      end
    else
      s
    end
    expire_positions(rest, s)
  end

  defp start_groups(s) do
    u = s.rprime + s.unwrap
    s = %{s | u: u, started_groups: true}
    s = start_group_rows(:maps.to_list(s.groups), s)
    send_members(0, s.n, s)
  end
  defp start_group_rows([], s), do: s
  defp start_group_rows([{g, group} | rest], s) do
    s = if Bounds.now() < s.u and Bounds.now() < s.d do
      pid = start_child(:custody, s, g, s.u, map_size(group.workers), 0)
      %{s | groups: :maps.put(g, %{group | pid: pid, started: Bounds.now()}, s.groups)}
    else
      s
    end
    start_group_rows(rest, s)
  end
  defp send_members(n, n, s), do: notify_dead(:maps.to_list(s.groups), s)
  defp send_members(i, n, s) do
    if Bounds.now() < s.d do
      case :maps.find(i, s.positions) do
        {:ok, %{phase: :resolved, group: g, w: w}} ->
          group = :maps.get(g, s.groups)
          {worker, _, _, alive} = :maps.get(w, s.workers)
          if alive,
            do: send(worker, {s.tag, :member, i, g, group.pid, s.u, :maps.get(w, group.workers)})
        _ -> :ok
      end
      send_members(i + 1, n, s)
    else
      s
    end
  end
  defp notify_dead([], s), do: s
  defp notify_dead([{_, group} | rest], s) do
    dead_contributors(:maps.to_list(group.workers), group.pid, s)
    notify_dead(rest, s)
  end
  defp dead_contributors([], _, _), do: :ok
  defp dead_contributors([{w, _} | rest], pid, s) do
    {_, _, _, alive} = :maps.get(w, s.workers)
    if not alive and pid != nil, do: send(pid, {s.tag, :contributor_down, w})
    dead_contributors(rest, pid, s)
  end

  defp summary(s, g, kind) do
    case :maps.find(g, s.groups) do
      {:ok, %{duration: nil} = group} when group.pid != nil ->
        :erlang.exit(group.pid, :kill)
        group_notice(:maps.to_list(group.workers), s, g, kind)
        duration = max(0, Bounds.now() - group.started)
        %{s | groups: :maps.put(g, %{group | duration: duration}, s.groups)}
      _ -> s
    end
  end
  defp group_notice([], _, _, _), do: :ok
  defp group_notice([{w, _} | rest], s, g, kind) do
    {pid, _, _, alive} = :maps.get(w, s.workers)
    if alive, do: send(pid, {s.tag, :group_summary, g, kind})
    group_notice(rest, s, g, kind)
  end
  defp expire_u(s) do
    s = expire_groups(:maps.to_list(s.groups), s)
    %{s | expired_u: true}
  end
  defp expire_groups([], s), do: s
  defp expire_groups([{g, _} | rest], s), do: expire_groups(rest, summary(s, g, :timeout))

  defp worker_down(s, pid) do
    case :maps.find(pid, s.pids) do
      {:ok, w} ->
        {^pid, lo, hi, _} = :maps.get(w, s.workers)
        s = %{s | workers: :maps.put(w, {pid, lo, hi, false}, s.workers)}
        s = dead_positions(lo, hi, s)
        dead_groups(:maps.to_list(s.groups), w, s)
      :error -> s
    end
  end
  defp dead_positions(i, hi, s) when i > hi, do: s
  defp dead_positions(i, hi, s) do
    p = :maps.get(i, s.positions)
    if p.resolver != nil, do: :erlang.exit(p.resolver, :kill)
    s = if p.result == nil and p.phase in [:resolved, :refused, :width],
      do: put(s, i, %{p | result: {:decryption_failed, :crypto, nil}}, 0), else: s
    dead_positions(i + 1, hi, s)
  end
  defp dead_groups([], _, s), do: s
  defp dead_groups([{_, group} | rest], w, s) do
    if group.pid != nil and is_map_key(group.workers, w),
      do: send(group.pid, {s.tag, :contributor_down, w})
    dead_groups(rest, w, s)
  end

  defp deadline(s) do
    s = drain_preflight(s, s.d + Bounds.preflight())
    case s do
      :overrun -> :internal_failure
      :failed -> :internal_failure
      %{n: nil} -> reply(s, {:outer, :deadline_exceeded, :crypto})
      _ -> reply(fill_deadline(0, s.n, s), :ok)
    end
  end
  defp drain_preflight(%{preflight: nil} = s, _), do: s
  defp drain_preflight(s, at) do
    if Bounds.now() >= at do
      :erlang.exit(s.preflight, :kill)
      :overrun
    else
      receive_preflight(s, at)
    end
  end
  defp receive_preflight(s, at) do
    tag = s.tag
    pid = s.preflight
    guard = s.guard
    receive do
      {^tag, :cardinality, n, tc} -> drain_preflight(cardinality(s, n, tc), at)
      {^tag, :preflight, :deadline} -> drain_preflight(%{s | preflight_final: true}, at)
      {^tag, :preflight, {:outer, _, _}} -> drain_preflight(%{s | preflight_final: true}, at)
      {^tag, :handed_off} -> drain_preflight(%{s | preflight_final: true}, at)
      {:EXIT, ^pid, _} -> if s.preflight_final, do: %{s | preflight: nil}, else: :failed
      {:EXIT, ^guard, _} ->
        :ets.foldl(fn row, acc -> kill_registered(row); acc end, :ok, s.registry)
        :overrun
      _ -> drain_preflight(s, at)
    after
      Bounds.remaining(at) -> drain_preflight(s, at)
    end
  end
  defp fill_deadline(n, n, s), do: s
  defp fill_deadline(i, n, s) do
    p = :maps.get(i, s.positions, %{w: 0, phase: :unadmitted, result: nil, resolver: nil, group: nil})
    s = if p.result == nil, do: put(s, i, %{p | result: expiry(:d, p.phase)}, 0), else: s
    fill_deadline(i + 1, n, s)
  end

  defp reply(s, outcome) do
    if outcome == :ok do
      settled_messages(0, s.n, s)
      group_messages(:maps.to_list(s.groups), s)
    end
    :ets.insert(s.registry, {:outcome, :replied})
    send(s.address, {s.tag, :reply, outcome, s.n, s.next_group})
    :replied
  end
  defp settled_messages(n, n, _), do: :ok
  defp settled_messages(i, n, s) do
    p = :maps.get(i, s.positions)
    {reason, layer, auth} = p.result
    send(s.address, {s.tag, :settled, i, reason, layer, auth})
    settled_messages(i + 1, n, s)
  end
  defp group_messages([], _), do: :ok
  defp group_messages([{_, group} | rest], s) do
    duration = if group.duration == nil and group.started != nil,
      do: max(0, Bounds.now() - group.started), else: group.duration
    if duration != nil, do: send(s.address, {s.tag, :group, duration, group.members})
    group_messages(rest, s)
  end
  defp kill_registered({:outcome, _}), do: :ok
  defp kill_registered({_, pid, _}), do: :erlang.exit(pid, :kill)
end
