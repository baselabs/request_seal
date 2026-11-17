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
      :erlang.send_after(Bounds.milliseconds(stop_at), self(), {map_get(:tag, s), :stop}, abs: true)
      awaiting = :ets.foldl(fn row, n -> sweep(row, s, n) end, 0, map_get(:registry, s))
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

  defp sweep({:outcome, _}, _, n), do: n

  defp sweep({_, pid, :library}, _, n) do
    :erlang.monitor(:process, pid)
    n + 1
  end

  defp sweep({slot, pid, :caller}, s, n) do
    %{ended: ended} = s

    case :ets.lookup(ended, slot) do
      [{^slot, ^pid}] ->
        n

      [{^slot, _}] ->
        :erlang.monitor(:process, pid)
        n + 1

      [] ->
        :erlang.exit(pid, :kill)
        n + 1
    end
  end

  defp receive_one(%{
         tag: tag,
         coordinator: coordinator,
         ended: ended,
         registry: registry,
         ended_at: ended_at,
         awaiting: awaiting
       } = s) do
    # F, cancellation and the owner flip each arm an absolute wakeup once.
    # Per-notice timeout conversion adds work without changing that deadline.
    receive do
      {:"ETS-TRANSFER", tid, from, {^tag, :slot, slot}} ->
        :ets.insert(ended, {slot, from})
        :ets.delete(tid)

        s =
          if ended_at == nil do
            if map_get(:cause, s) == nil, do: send(coordinator, {tag, :ended, slot})
            s
          else
            case :ets.lookup(registry, slot) do
              [{^slot, ^from, :caller}] ->
                %{s | awaiting: awaiting - 1}

              [{^slot, pid, :caller}] ->
                :erlang.monitor(:process, pid)
                s

              _ ->
                s
            end
          end

        loop(s)

      {:EXIT, ^coordinator, _atom} ->
        loop(%{s | exit_seen: true})

      {:DOWN, _, :process, _, _atom} ->
        loop(%{s | awaiting: awaiting - 1})

      _ ->
        loop(s)
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
