defmodule RequestSeal.JOSE.JWE.Guard do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.{Bounds, Coordinator}

  def run(tag, caller, address, flag, mode, r, d, f, unwrap) do
    :erlang.process_flag(:trap_exit, true)

    try do
      notice = :ets.new(:caller_notice, [:private, {:heir, self(), {tag, :caller}}])

      if give_caller(notice, caller, tag) do
        ended = :ets.new(:ended, [:private, :set])
        registry = :ets.new(:registry, [:protected, :set, {:heir, self(), {tag, :registry}}])

        coordinator =
          :erlang.spawn_link(Coordinator, :run, [
            tag, self(), caller, notice, address, flag, mode, r, d, unwrap
          ])

        :ets.give_away(registry, coordinator, {tag, :registry})
        :erlang.send_after(Bounds.milliseconds(f), self(), {tag, :f}, abs: true)

        loop(%{
          tag: tag, caller_notice: notice, ended: ended, registry: registry,
          coordinator: coordinator, flag: flag, d: d, f: f, ended_at: nil,
          exit_seen: false, awaiting: 0, stop_at: nil, anchor: nil, cause: nil
        })
      else
        :normal
      end
    catch
      _, _ -> :internal_failure
    end
    |> finish()
  end

  defp finish(reason), do: exit(reason)

  defp give_caller(notice, caller, tag) do
    try do
      :ets.give_away(notice, caller, {tag, :caller})
    catch
      :error, :badarg -> false
    end
  end

  defp loop(s) do
    s = check(s)

    cond do
      s.ended_at != nil and s.awaiting == 0 and s.exit_seen -> reason(s)
      s.stop_at != nil and Bounds.now() >= s.stop_at -> reason(s)
      s.anchor != nil and s.ended_at == nil and
          Bounds.now() >= s.anchor + Bounds.teardown(Bounds.max_tokens()) -> reason(s)
      true -> receive_one(s)
    end
  end

  # This owner read precedes every dequeue, including a queued registry transfer.
  defp check(%{ended_at: nil} = s) do
    now = Bounds.now()

    if :ets.info(s.registry, :owner) == self() do
      anchor = if s.anchor == nil, do: min(now, s.d), else: s.anchor
      stop_at = stop_at(anchor, :atomics.get(s.flag, 2))
      awaiting = :ets.foldl(fn row, n -> sweep(row, s, n) end, 0, s.registry)
      %{s | ended_at: now, anchor: anchor, stop_at: stop_at, awaiting: awaiting}
    else
      cause(s, now)
    end
  end

  defp check(s), do: s

  defp cause(%{cause: nil} = s, now) do
    cond do
      :ets.info(s.caller_notice, :owner) == self() -> kill(s, :caller_gone, now)
      now >= s.f -> kill(s, :deadline, s.f)
      true -> s
    end
  end

  defp cause(s, _), do: s

  defp kill(s, cause, anchor) do
    :erlang.exit(s.coordinator, :kill)
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
    case :ets.lookup(s.ended, slot) do
      [{^slot, ^pid}] -> n
      [{^slot, _}] ->
        :erlang.monitor(:process, pid)
        n + 1
      [] ->
        :erlang.exit(pid, :kill)
        n + 1
    end
  end

  defp receive_one(s) do
    tag = s.tag
    coordinator = s.coordinator
    target = cond do
      s.stop_at != nil -> s.stop_at
      s.anchor != nil -> s.anchor + Bounds.teardown(Bounds.max_tokens())
      true -> s.f
    end

    receive do
      {:'ETS-TRANSFER', tid, from, {^tag, :slot, slot}} ->
        :ets.insert(s.ended, {slot, from})
        :ets.delete(tid)

        s =
          if s.ended_at == nil do
            if s.cause == nil, do: send(coordinator, {tag, :ended, slot})
            s
          else
            case :ets.lookup(s.registry, slot) do
              [{^slot, ^from, :caller}] -> %{s | awaiting: s.awaiting - 1}
              [{^slot, pid, :caller}] ->
                :erlang.monitor(:process, pid)
                s
              _ -> s
            end
          end

        loop(s)

      {:EXIT, ^coordinator, _atom} -> loop(%{s | exit_seen: true})
      {:DOWN, _, :process, _, _atom} -> loop(%{s | awaiting: s.awaiting - 1})
      _ -> loop(s)
    after
      Bounds.remaining(target) -> loop(s)
    end
  end

  defp reason(s) do
    case :ets.lookup(s.registry, :outcome) do
      [{:outcome, :replied}] -> :replied
      _ -> case s.cause do
        :caller_gone -> :normal
        :deadline -> :deadline
        _ -> :internal_failure
      end
    end
  end
end
