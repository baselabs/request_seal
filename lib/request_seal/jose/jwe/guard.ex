defmodule RequestSeal.JOSE.JWE.Guard do
  @moduledoc false
  import :erlang, only: [map_get: 2]
  alias RequestSeal.JOSE.JWE.{Bounds, Coordinator}

  @spec run(
          reference(),
          pid(),
          reference(),
          reference(),
          :single | :batch,
          integer(),
          integer(),
          integer(),
          pos_integer()
        ) :: no_return()
  def run(tag, caller, address, flag, mode, r, d, f, unwrap) do
    :erlang.process_flag(:trap_exit, true)

    try do
      notice = :ets.new(:caller_notice, [:private, {:heir, self(), {tag, :caller}}])

      case give_caller(notice, caller, tag, f) do
        true ->
          ended = :ets.new(:ended, [:private, :set])
          registry = :ets.new(:registry, [:protected, :set, {:heir, self(), {tag, :registry}}])

          coordinator =
            :erlang.spawn_link(Coordinator, :run, [
              tag,
              self(),
              caller,
              notice,
              address,
              flag,
              mode,
              r,
              d,
              unwrap
            ])

          :ets.give_away(registry, coordinator, {tag, :registry})
          :erlang.send_after(Bounds.milliseconds(f), self(), {tag, :f}, abs: true)

          loop(%{
            tag: tag,
            caller_notice: notice,
            ended: ended,
            registry: registry,
            coordinator: coordinator,
            flag: flag,
            d: d,
            f: f,
            ended_at: nil,
            exit_seen: false,
            awaiting: 0,
            stop_at: nil,
            anchor: nil,
            cause: nil
          })

        :deadline ->
          :deadline

        false ->
          :normal
      end
    catch
      _, _ -> :internal_failure
    end
    |> finish()
  end

  defp finish(reason), do: exit(reason)

  defp give_caller(notice, caller, tag, f) do
    try do
      if Bounds.now() < f do
        :ets.give_away(notice, caller, {tag, :caller})
      else
        :deadline
      end
    catch
      :error, :badarg -> false
    end
  end

  defp loop(s) do
    s = check(s)

    case s do
      %{ended_at: ended, awaiting: 0, exit_seen: true} when ended != nil ->
        reason(s)

      %{stop_at: at} when at != nil ->
        if Bounds.now() >= at, do: reason(s), else: receive_one(s)

      %{anchor: anchor} when anchor != nil ->
        if Bounds.now() >= anchor + Bounds.teardown(Bounds.max_tokens()),
          do: reason(s),
          else: receive_one(s)

      _ ->
        receive_one(s)
    end
  end

  # This owner read precedes every dequeue, including a queued registry transfer.
  defp check(%{ended_at: nil} = s) do
    now = Bounds.now()

    if :ets.info(map_get(:registry, s), :owner) == self() do
      anchor =
        if map_get(:anchor, s) == nil, do: min(now, map_get(:d, s)), else: map_get(:anchor, s)

      stop_at = stop_at(anchor, :atomics.get(map_get(:flag, s), 2))

      :erlang.send_after(Bounds.milliseconds(stop_at), self(), {map_get(:tag, s), :stop},
        abs: true
      )

      # A registered custody child proves P3 joined every resolver notice.
      # Retain the complete registry, but do not look up those ended pids again.
      resolvers_ended = :ets.lookup(map_get(:registry, s), {:custody, 0}) != []

      awaiting =
        if resolvers_ended do
          sweep_registry(s)
        else
          :ets.foldl(fn row, n -> sweep(row, s, n) end, 0, map_get(:registry, s))
        end

      %{s | ended_at: now, anchor: anchor, stop_at: stop_at, awaiting: awaiting}
    else
      cause(s, now)
    end
  end

  defp check(s), do: s

  defp cause(%{cause: nil} = s, now) do
    cond do
      :ets.info(map_get(:caller_notice, s), :owner) == self() -> kill(s, :caller_gone, now)
      now >= map_get(:f, s) -> kill(s, :deadline, map_get(:f, s))
      true -> s
    end
  end

  defp cause(s, _), do: s

  defp kill(s, cause, anchor) do
    :erlang.exit(map_get(:coordinator, s), :kill)

    :erlang.send_after(
      Bounds.milliseconds(anchor + Bounds.teardown(Bounds.max_tokens())),
      self(),
      {map_get(:tag, s), :stop},
      abs: true
    )

    %{s | cause: cause, anchor: anchor}
  end

  # Kept as one named function so the shipped calculation can be return-traced.
  def stop_at(anchor, n), do: anchor + Bounds.teardown(n)

  # Slot zero exists only after the resolver join. Filter those immutable ended
  # rows inside ETS; copy at most 64 remaining rows into each sweep page.
  defp sweep_registry(s) do
    match = [
      {{{:"$1", :_}, :_, :_}, [{:"=/=", :"$1", :resolver}], [:"$_"]},
      {{:"$1", :_, :_}, [{:is_atom, :"$1"}], [:"$_"]}
    ]

    sweep_pages(:ets.select(map_get(:registry, s), match, 64), s, 0)
  end

  defp sweep_pages(:"$end_of_table", _, n), do: n

  defp sweep_pages({rows, continuation}, s, n) do
    n = sweep_rows(rows, s, n)
    sweep_pages(:ets.select(continuation), s, n)
  end

  defp sweep_rows([], _, n), do: n
  defp sweep_rows([row | rest], s, n), do: sweep_rows(rest, s, sweep(row, s, n))

  defp sweep({:outcome, _}, _, n), do: n

  defp sweep({_, pid, :library}, _, n) do
    :erlang.monitor(:process, pid)
    n + 1
  end

  defp sweep({slot, pid, :caller}, s, n) do
    %{ended: ended} = s

    case :ets.lookup_element(ended, slot, 2, :undefined) do
      ^pid ->
        n

      :undefined ->
        :erlang.exit(pid, :kill)
        n + 1

      _ ->
        :erlang.monitor(:process, pid)
        n + 1
    end
  end

  defp receive_one(
         %{
           tag: tag,
           coordinator: coordinator,
           ended: ended,
           registry: registry,
           ended_at: ended_at,
           awaiting: awaiting
         } = s
       ) do
    # F, cancellation and the owner flip each arm an absolute wakeup once.
    # Per-notice timeout conversion adds work without changing that deadline.
    receive do
      {:"ETS-TRANSFER", tid, from, {^tag, :slot, slot}} ->
        # Ends are needed as a set only until the one sweep. Afterwards the
        # immutable registry and awaiting counter record each notice directly.
        if ended_at == nil, do: :ets.insert(ended, {slot, from})
        :ets.delete(tid)

        if ended_at == nil do
          if map_get(:cause, s) == nil, do: send(coordinator, {tag, :ended, slot})
          loop(s)
        else
          case :ets.lookup(registry, slot) do
            [{^slot, ^from, :caller}] ->
              join(s, awaiting - 1, map_get(:exit_seen, s))

            [{^slot, pid, :caller}] ->
              :erlang.monitor(:process, pid)
              join(s, awaiting, map_get(:exit_seen, s))

            _ ->
              join(s, awaiting, map_get(:exit_seen, s))
          end
        end

      {:EXIT, ^coordinator, _atom} ->
        loop(%{s | exit_seen: true})

      {:DOWN, _, :process, _, _atom} ->
        loop(%{s | awaiting: awaiting - 1})

      _ ->
        loop(s)
    end
  end

  # After the sole sweep the registry, anchor and reason cannot change. Carry
  # only the join counters between notices instead of copying the state map
  # for every child. The absolute stop is still checked before every dequeue.
  defp join(s, awaiting, exit_seen) do
    if (awaiting == 0 and exit_seen) or Bounds.now() >= map_get(:stop_at, s) do
      reason(s)
    else
      tag = map_get(:tag, s)
      coordinator = map_get(:coordinator, s)

      receive do
        {:"ETS-TRANSFER", tid, from, {^tag, :slot, slot}} ->
          :ets.delete(tid)

          case :ets.lookup(map_get(:registry, s), slot) do
            [{^slot, ^from, :caller}] ->
              join(s, awaiting - 1, exit_seen)

            [{^slot, pid, :caller}] ->
              :erlang.monitor(:process, pid)
              join(s, awaiting, exit_seen)

            _ ->
              join(s, awaiting, exit_seen)
          end

        {:EXIT, ^coordinator, _atom} ->
          join(s, awaiting, true)

        {:DOWN, _, :process, _, _atom} ->
          join(s, awaiting - 1, exit_seen)

        _ ->
          join(s, awaiting, exit_seen)
      end
    end
  end

  defp reason(s) do
    case :ets.lookup(map_get(:registry, s), :outcome) do
      [{:outcome, :replied}] ->
        :replied

      _ ->
        case map_get(:cause, s) do
          :caller_gone -> :normal
          :deadline -> :deadline
          _ -> :internal_failure
        end
    end
  end
end
