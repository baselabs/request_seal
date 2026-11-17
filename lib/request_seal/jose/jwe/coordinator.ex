defmodule RequestSeal.JOSE.JWE.Coordinator do
  @moduledoc false
  import :erlang, only: [map_get: 2]
  alias RequestSeal.JOSE.JWE.{Bounds, Preflight, Resolver, Unwrap, Worker}

  def run(tag, guard, caller, notice, address, flag, mode, r, d, unwrap) do
    :erlang.process_flag(:trap_exit, true)
    :erlang.process_flag(:message_queue_data, :off_heap)

    reason =
      try do
        registry =
          receive do
            {:"ETS-TRANSFER", registry, ^guard, {^tag, :registry}} -> registry
          end

        s = %{
          tag: tag,
          guard: guard,
          caller: caller,
          notice: notice,
          address: address,
          flag: flag,
          mode: mode,
          r: r,
          d: d,
          unwrap: unwrap,
          registry: registry,
          n: nil,
          settled: 0,
          admissions_left: nil,
          resolutions_left: 0,
          positions: %{},
          workers: %{},
          pids: %{},
          resolver_pending: 0,
          ended: %{},
          groups: %{},
          digests: %{},
          next_group: 0,
          rprime: nil,
          u: nil,
          started_groups: false,
          expired_r: false,
          expired_u: false,
          preflight: nil,
          handed_off: false,
          preflight_final: false
        }

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
    tag = map_get(:tag, s)
    guard = map_get(:guard, s)
    caller = map_get(:caller, s)
    caller_notice = map_get(:notice, s)
    flag = map_get(:flag, s)
    mode = map_get(:mode, s)
    r = map_get(:r, s)
    d = map_get(:d, s)
    address = map_get(:address, s)

    {slot, pid, role, notice} =
      case kind do
        :preflight ->
          pid =
            :erlang.spawn_opt(Preflight, :run, [tag, self(), flag, mode, d], [
              :link,
              {:message_queue_data, :off_heap}
            ])

          {:preflight, pid, :library, nil}

        :worker ->
          pid =
            :erlang.spawn_opt(
              Worker,
              :run,
              [tag, self(), address, a, b, c, r, d, mode],
              [:link]
            )

          {{:worker, a}, pid, :library, nil}

        :resolver ->
          slot = {:resolver, a}
          notice = :ets.new(:child_notice, [:private, {:heir, guard, {tag, :slot, slot}}])

          pid =
            :erlang.spawn_opt(
              Resolver,
              :run,
              [tag, a, b, r, self(), slot, caller, caller_notice],
              [:link]
            )

          {slot, pid, :caller, notice}

        :custody ->
          slot = {:custody, a}
          notice = :ets.new(:child_notice, [:private, {:heir, guard, {tag, :slot, slot}}])

          pid =
            :erlang.spawn_opt(
              Unwrap,
              :run,
              [tag, a, b, c, self(), slot, caller, caller_notice],
              [:link]
            )

          {slot, pid, :caller, notice}
      end

    :ets.insert(map_get(:registry, s), {slot, pid, role})

    if role == :caller do
      :ets.give_away(notice, pid, {tag, :slot, slot})
      :erlang.unlink(pid)
    end

    pid
  end

  defp loop(s) do
    now = Bounds.now()

    cond do
      now >= map_get(:d, s) ->
        deadline(s)

      map_get(:n, s) != nil and map_get(:settled, s) == map_get(:n, s) and
          map_get(:handed_off, s) ->
        reply(s, :ok)

      true ->
        s =
          if not map_get(:expired_r, s) and now >= map_get(:r, s) and map_get(:handed_off, s),
            do: expire_r(s),
            else: s

        s = barrier(s, now)

        s =
          if map_get(:rprime, s) != nil and map_get(:resolver_pending, s) == 0 and
               not map_get(:started_groups, s),
            do: start_groups(s),
            else: s

        s =
          if map_get(:u, s) != nil and not map_get(:expired_u, s) and
               Bounds.now() >= map_get(:u, s),
            do: expire_u(s),
            else: s

        receive_one(s)
    end
  end

  defp receive_one(s) do
    tag = map_get(:tag, s)
    guard = map_get(:guard, s)

    wait =
      cond do
        map_get(:u, s) != nil and not map_get(:expired_u, s) ->
          min(map_get(:d, s), map_get(:u, s))

        map_get(:handed_off, s) and not map_get(:expired_r, s) and map_get(:rprime, s) == nil ->
          min(map_get(:d, s), map_get(:r, s))

        true ->
          map_get(:d, s)
      end

    receive do
      {^tag, :cardinality, n, tc} when is_integer(n) and n >= 0 and n <= 10_000 ->
        loop(cardinality(s, n, tc))

      {^tag, :preflight, :ok} ->
        if Bounds.now() < map_get(:d, s),
          do: loop(start_workers(s, 0, worker_count(map_get(:n, s)))),
          else: deadline(s)

      {^tag, :preflight, {:outer, reason, layer}} ->
        if Bounds.now() < map_get(:d, s),
          do: reply(%{s | preflight_final: true}, {:outer, reason, layer}),
          else: deadline(s)

      {^tag, :preflight, :deadline} ->
        loop(%{s | preflight_final: true})

      {^tag, :handed_off} ->
        :erlang.exit(map_get(:preflight, s), :kill)
        loop(%{s | handed_off: true, preflight_final: true})

      {^tag, :admitted, i, outcome} ->
        loop(admitted(s, i, outcome))

      {^tag, :resolved, i, outcome} ->
        loop(resolved(s, i, outcome))

      {^tag, :result, i, reason, layer, auth} ->
        loop(result(s, i, reason, layer, auth))

      {^tag, :ended, slot} ->
        loop(ended(s, slot))

      {^tag, :unwrap_summary, g, kind} ->
        loop(summary(s, g, kind))

      {:EXIT, ^guard, _} ->
        :ets.foldl(
          fn row, acc ->
            kill_registered(row)
            acc
          end,
          :ok,
          map_get(:registry, s)
        )

        :internal_failure

      {:EXIT, pid, reason} ->
        if pid == map_get(:preflight, s) do
          if map_get(:preflight_final, s),
            do: loop(%{s | preflight: nil}),
            else: reply(s, {:outer, :internal_failure, :internal})
        else
          loop(worker_down(s, pid, reason))
        end

      _ ->
        loop(s)
    after
      Bounds.remaining(wait) -> loop(s)
    end
  end

  defp cardinality(%{n: nil} = s, n, tc) when tc < map_get(:d, s) do
    :atomics.put(map_get(:flag, s), 2, n)
    %{s | n: n, admissions_left: n}
  end

  defp cardinality(s, _, _), do: s
  defp worker_count(0), do: 0
  defp worker_count(n), do: min(32, min(n, :erlang.system_info(:schedulers_online)))

  defp start_workers(s, k, k) do
    send(map_get(:preflight, s), {map_get(:tag, s), :workers_done})
    s
  end

  defp start_workers(s, w, k) do
    if Bounds.now() >= map_get(:d, s) do
      s
    else
      lo = div(w * map_get(:n, s), k)
      hi = div((w + 1) * map_get(:n, s), k) - 1
      pid = start_child(:worker, s, w, lo, hi, 0)
      send(map_get(:preflight, s), {map_get(:tag, s), :worker, w, lo, hi, pid})
      positions = init_positions(lo, hi, w, map_get(:positions, s))

      s = %{
        s
        | workers: :maps.put(w, {pid, lo, hi, true}, map_get(:workers, s)),
          pids: :maps.put(pid, w, map_get(:pids, s)),
          positions: positions
      }

      start_workers(s, w + 1, k)
    end
  end

  defp init_positions(i, hi, _, positions) when i > hi, do: positions

  defp init_positions(i, hi, w, positions) do
    position = %{w: w, phase: :unadmitted, result: nil, resolver: nil, group: nil}
    init_positions(i + 1, hi, w, :maps.put(i, position, positions))
  end

  defp admitted(s, i, outcome) do
    case :maps.find(i, map_get(:positions, s)) do
      {:ok, %{phase: :unadmitted, result: nil} = p} ->
        if Bounds.before?(Bounds.now(), map_get(:r, s)) do
          {pid, _, _, alive} = :maps.get(map_get(:w, p), map_get(:workers, s))

          case outcome do
            :ready when alive ->
              resolver = start_child(:resolver, s, i, pid, 0, 0)
              send(pid, {map_get(:tag, s), :resolver, i, resolver})
              put(s, i, %{p | phase: :ready, resolver: resolver}, 1)

            :width_failed ->
              put(s, i, %{p | phase: :width}, 0)

            {:error, reason, layer} ->
              put(s, i, %{p | phase: :refused, result: {reason, layer, nil}}, 0)

            _ ->
              s
          end
        else
          s
        end

      _ ->
        s
    end
  end

  defp put(s, i, p, pending) do
    old = :maps.get(i, map_get(:positions, s), %{phase: :unadmitted, result: nil})

    admissions =
      if map_get(:phase, old) == :unadmitted and map_get(:phase, p) != :unadmitted, do: 1, else: 0

    resolution =
      cond do
        map_get(:phase, old) != :ready and map_get(:phase, p) == :ready -> 1
        map_get(:phase, old) == :ready and map_get(:phase, p) != :ready -> -1
        true -> 0
      end

    settled = if map_get(:result, old) == nil and map_get(:result, p) != nil, do: 1, else: 0

    %{
      s
      | positions: :maps.put(i, p, map_get(:positions, s)),
        resolver_pending: map_get(:resolver_pending, s) + pending,
        admissions_left: map_get(:admissions_left, s) - admissions,
        resolutions_left: map_get(:resolutions_left, s) + resolution,
        settled: map_get(:settled, s) + settled
    }
  end

  defp resolved(s, i, outcome) do
    case :maps.find(i, map_get(:positions, s)) do
      {:ok, %{phase: :ready, result: nil} = p} ->
        if Bounds.before?(Bounds.now(), map_get(:r, s)) do
          :erlang.exit(map_get(:resolver, p), :kill)

          case outcome do
            {:ok, digest} when is_binary(digest) and byte_size(digest) == 32 ->
              {g, s} = group(s, digest, map_get(:w, p))
              put(s, i, %{p | phase: :resolved, group: g}, 0)

            {:error, reason, layer} ->
              put(s, i, %{p | phase: :refused, result: {reason, layer, nil}}, 0)

            :refused ->
              put(s, i, %{p | phase: :refused}, 0)

            _ ->
              s
          end
        else
          s
        end

      _ ->
        s
    end
  end

  defp group(s, digest, w) do
    {g, s} =
      case :maps.find(digest, map_get(:digests, s)) do
        {:ok, g} ->
          {g, s}

        :error ->
          g = map_get(:next_group, s)
          group = %{members: 0, workers: %{}, pid: nil, started: nil, duration: nil}

          {g,
           %{
             s
             | digests: :maps.put(digest, g, map_get(:digests, s)),
               groups: :maps.put(g, group, map_get(:groups, s)),
               next_group: g + 1
           }}
      end

    group = :maps.get(g, map_get(:groups, s))
    counts = :maps.put(w, :maps.get(w, map_get(:workers, group), 0) + 1, map_get(:workers, group))

    group = %{group | members: map_get(:members, group) + 1, workers: counts}
    {g, %{s | groups: :maps.put(g, group, map_get(:groups, s))}}
  end

  def result_phase?(phase), do: phase in [:resolved, :refused, :width]

  defp result(s, i, reason, layer, auth) do
    case :maps.find(i, map_get(:positions, s)) do
      {:ok, %{phase: phase, result: nil} = p} ->
        if result_phase?(phase) and Bounds.now() < map_get(:d, s),
          do: put(s, i, %{p | result: {reason, layer, auth}}, 0),
          else: s

      _ ->
        s
    end
  end

  defp ended(s, {:resolver, i} = slot) do
    if is_map_key(map_get(:ended, s), slot) do
      s
    else
      s = %{
        s
        | ended: :maps.put(slot, true, map_get(:ended, s)),
          resolver_pending: map_get(:resolver_pending, s) - 1
      }

      case :maps.find(i, map_get(:positions, s)) do
        {:ok, %{phase: :ready} = p} -> put(s, i, %{p | resolver: nil}, 0)
        _ -> s
      end
    end
  end

  defp ended(s, {:custody, g}), do: summary(s, g, :error)
  defp ended(s, _), do: s

  defp barrier(%{rprime: nil, admissions_left: 0, resolutions_left: 0, n: n} = s, now)
       when n != nil,
       do: %{
         s
         | rprime: resolution_end(now, map_get(:r, s)),
           u: min(now, map_get(:r, s)) + map_get(:unwrap, s)
       }

  defp barrier(s, _), do: s

  def resolution_end(now, r), do: min(now, r)

  def expiry(:r, :unadmitted), do: {:deadline_exceeded, :input, nil}
  def expiry(:r, :ready), do: {:key_resolver_failed, :key, nil}
  def expiry(:d, _phase), do: {:deadline_exceeded, :crypto, nil}

  defp expire_r(s) do
    s = expire_positions(:maps.to_list(map_get(:positions, s)), s)
    %{s | expired_r: true, rprime: map_get(:r, s), u: map_get(:r, s) + map_get(:unwrap, s)}
  end

  defp expire_positions([], s), do: s

  defp expire_positions([{i, p} | rest], s) do
    s =
      if map_get(:result, p) == nil do
        case map_get(:phase, p) do
          :unadmitted ->
            put(s, i, %{p | phase: :refused, result: expiry(:r, :unadmitted)}, 0)

          :ready ->
            if map_get(:resolver, p) != nil, do: :erlang.exit(map_get(:resolver, p), :kill)
            put(s, i, %{p | phase: :refused, result: expiry(:r, :ready)}, 0)

          _ ->
            s
        end
      else
        s
      end

    expire_positions(rest, s)
  end

  defp start_groups(s) do
    u = map_get(:rprime, s) + map_get(:unwrap, s)
    s = %{s | u: u, started_groups: true}
    s = start_group_rows(:maps.to_list(map_get(:groups, s)), s)
    send_members(0, map_get(:n, s), s)
  end

  defp start_group_rows([], s), do: s

  defp start_group_rows([{g, group} | rest], s) do
    s =
      if Bounds.now() < map_get(:u, s) and Bounds.now() < map_get(:d, s) do
        pid = start_child(:custody, s, g, map_get(:u, s), map_size(map_get(:workers, group)), 0)
        group = %{group | pid: pid, started: Bounds.now()}
        %{s | groups: :maps.put(g, group, map_get(:groups, s))}
      else
        s
      end

    start_group_rows(rest, s)
  end

  defp send_members(n, n, s), do: notify_dead(:maps.to_list(map_get(:groups, s)), s)

  defp send_members(i, n, s) do
    if Bounds.now() < map_get(:d, s) do
      case :maps.find(i, map_get(:positions, s)) do
        {:ok, %{phase: :resolved, group: g, w: w}} ->
          group = :maps.get(g, map_get(:groups, s))
          {worker, _, _, alive} = :maps.get(w, map_get(:workers, s))

          if alive do
            send(
              worker,
              {map_get(:tag, s), :member, i, g, map_get(:pid, group), map_get(:u, s),
               :maps.get(w, map_get(:workers, group))}
            )
          end

        _ ->
          :ok
      end

      send_members(i + 1, n, s)
    else
      s
    end
  end

  defp notify_dead([], s), do: s

  defp notify_dead([{_, group} | rest], s) do
    dead_contributors(:maps.to_list(map_get(:workers, group)), map_get(:pid, group), s)
    notify_dead(rest, s)
  end

  defp dead_contributors([], _, _), do: :ok

  defp dead_contributors([{w, _} | rest], pid, s) do
    {_, _, _, alive} = :maps.get(w, map_get(:workers, s))
    if not alive and pid != nil, do: send(pid, {map_get(:tag, s), :contributor_down, w})
    dead_contributors(rest, pid, s)
  end

  defp summary(s, g, kind) do
    case :maps.find(g, map_get(:groups, s)) do
      {:ok, %{duration: nil} = group} when map_get(:pid, group) != nil ->
        :erlang.exit(map_get(:pid, group), :kill)
        group_notice(:maps.to_list(map_get(:workers, group)), s, g, kind)
        duration = max(0, Bounds.now() - map_get(:started, group))
        %{s | groups: :maps.put(g, %{group | duration: duration}, map_get(:groups, s))}

      _ ->
        s
    end
  end

  defp group_notice([], _, _, _), do: :ok

  defp group_notice([{w, _} | rest], s, g, kind) do
    {pid, _, _, alive} = :maps.get(w, map_get(:workers, s))
    if alive, do: send(pid, {map_get(:tag, s), :group_summary, g, kind})
    group_notice(rest, s, g, kind)
  end

  defp expire_u(s) do
    s = expire_groups(:maps.to_list(map_get(:groups, s)), s)
    %{s | expired_u: true}
  end

  defp expire_groups([], s), do: s
  defp expire_groups([{g, _} | rest], s), do: expire_groups(rest, summary(s, g, :timeout))

  defp worker_down(s, pid, reason) do
    case :maps.find(pid, map_get(:pids, s)) do
      {:ok, w} ->
        {^pid, lo, hi, _} = :maps.get(w, map_get(:workers, s))
        s = %{s | workers: :maps.put(w, {pid, lo, hi, false}, map_get(:workers, s))}
        s = dead_positions(lo, hi, s, reason)
        dead_groups(:maps.to_list(map_get(:groups, s)), w, s)

      :error ->
        s
    end
  end

  defp dead_positions(i, hi, s, _) when i > hi, do: s

  defp dead_positions(i, hi, s, reason) do
    p = :maps.get(i, map_get(:positions, s))
    if map_get(:resolver, p) != nil, do: :erlang.exit(map_get(:resolver, p), :kill)

    failure =
      if reason == :normal,
        do: {:decryption_failed, :crypto, nil},
        else: {:internal_failure, :internal, nil}

    s =
      if map_get(:result, p) == nil and
           (reason != :normal or map_get(:phase, p) in [:resolved, :refused, :width]),
        do: put(s, i, %{p | phase: :refused, result: failure}, 0),
        else: s

    dead_positions(i + 1, hi, s, reason)
  end

  defp dead_groups([], _, s), do: s

  defp dead_groups([{_, group} | rest], w, s) do
    if map_get(:pid, group) != nil and is_map_key(map_get(:workers, group), w),
      do: send(map_get(:pid, group), {map_get(:tag, s), :contributor_down, w})

    dead_groups(rest, w, s)
  end

  defp deadline(s) do
    s = drain_preflight(s, map_get(:d, s) + Bounds.preflight())

    case s do
      :overrun -> :internal_failure
      :failed -> :internal_failure
      %{n: nil} -> reply(s, {:outer, :deadline_exceeded, :crypto})
      _ -> reply(fill_deadline(0, map_get(:n, s), s), :ok)
    end
  end

  defp drain_preflight(%{preflight: nil} = s, _), do: s

  defp drain_preflight(s, at) do
    if Bounds.now() >= at do
      :erlang.exit(map_get(:preflight, s), :kill)
      :overrun
    else
      receive_preflight(s, at)
    end
  end

  defp receive_preflight(s, at) do
    tag = map_get(:tag, s)
    pid = map_get(:preflight, s)
    guard = map_get(:guard, s)

    receive do
      {^tag, :cardinality, n, tc} ->
        drain_preflight(cardinality(s, n, tc), at)

      {^tag, :preflight, :deadline} ->
        drain_preflight(%{s | preflight_final: true}, at)

      {^tag, :preflight, {:outer, _, _}} ->
        drain_preflight(%{s | preflight_final: true}, at)

      {^tag, :handed_off} ->
        drain_preflight(%{s | preflight_final: true}, at)

      {:EXIT, ^pid, _} ->
        if map_get(:preflight_final, s), do: %{s | preflight: nil}, else: :failed

      {:EXIT, ^guard, _} ->
        :ets.foldl(
          fn row, acc ->
            kill_registered(row)
            acc
          end,
          :ok,
          map_get(:registry, s)
        )

        :overrun

      _ ->
        drain_preflight(s, at)
    after
      Bounds.remaining(at) -> drain_preflight(s, at)
    end
  end

  defp fill_deadline(n, n, s), do: s

  defp fill_deadline(i, n, s) do
    p =
      :maps.get(i, map_get(:positions, s), %{
        w: 0,
        phase: :unadmitted,
        result: nil,
        resolver: nil,
        group: nil
      })

    s =
      if map_get(:result, p) == nil,
        do: put(s, i, %{p | result: expiry(:d, map_get(:phase, p))}, 0),
        else: s

    fill_deadline(i + 1, n, s)
  end

  defp reply(s, outcome) do
    if outcome == :ok do
      settled_messages(0, map_get(:n, s), s)
      group_messages(:maps.to_list(map_get(:groups, s)), s)
    end

    :ets.insert(map_get(:registry, s), {:outcome, :replied})

    send(
      map_get(:address, s),
      {map_get(:tag, s), :reply, outcome, map_get(:n, s), map_get(:next_group, s)}
    )

    :replied
  end

  defp settled_messages(n, n, _), do: :ok

  defp settled_messages(i, n, s) do
    p = :maps.get(i, map_get(:positions, s))
    {reason, layer, auth} = map_get(:result, p)
    send(map_get(:address, s), {map_get(:tag, s), :settled, i, reason, layer, auth})
    settled_messages(i + 1, n, s)
  end

  defp group_messages([], _), do: :ok

  defp group_messages([{_, group} | rest], s) do
    duration =
      if map_get(:duration, group) == nil and map_get(:started, group) != nil,
        do: max(0, Bounds.now() - map_get(:started, group)),
        else: map_get(:duration, group)

    if duration != nil,
      do:
        send(
          map_get(:address, s),
          {map_get(:tag, s), :group, duration, map_get(:members, group)}
        )

    group_messages(rest, s)
  end

  defp kill_registered({:outcome, _}), do: :ok
  defp kill_registered({_, pid, _}), do: :erlang.exit(pid, :kill)
end
