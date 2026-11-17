defmodule RequestSeal.JOSE.JWE.Open do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Guard}

  def open(input, policy, mode) when mode in [:single, :batch] do
    try do
      budgets(policy)
      {p, expected} = separate(policy, mode)
      Codec.ensure(Bounds.within?(p, Bounds.policy_words()), :invalid_policy)
      if mode == :single,
        do: Codec.ensure(Bounds.within?(expected, Bounds.item_words(), Bounds.binary_bytes()), :invalid_policy)
      started = Bounds.now()
      r = started + policy.resolve_timeout * 1_000
      d = started + policy.timeout * 1_000
      f = d + Bounds.finalization()
      tag = make_ref()
      address = :erlang.alias()
      flag = :atomics.new(2, [])
      caller = self()
      {guard, monitor} = :erlang.spawn_opt(Guard, :run,
        [tag, caller, address, flag, mode, r, d, f, policy.unwrap_timeout * 1_000],
        [:monitor, {:message_queue_data, :off_heap}])
      s = %{tag: tag, address: address, guard: guard, monitor: monitor, flag: flag,
        d: d, f: f, mode: mode, notice: nil, down: nil, reply: nil,
        payloads: %{}, settled: %{}, groups: [], auth: []}
      try do
        take_notice(s, input, p, expected)
      after
        :erlang.unalias(address)
        :erlang.demonitor(monitor, [:flush])
        drain(tag, nil)
      end
    catch
      :throw, {:jose_error, reason, layer} -> Codec.error(reason, layer)
      _, _ -> Codec.error(:internal_failure, :internal)
    end
  end

  # Establish notice ownership outside the work that can raise, so its table id
  # remains available to cleanup even if bootstrap or result assembly fails.
  defp take_notice(s, input, p, expected) do
    tag = s.tag
    monitor = s.monitor
    guard = s.guard
    at = s.f + Bounds.teardown(:atomics.get(s.flag, 2))
    receive do
      {:'ETS-TRANSFER', notice, ^guard, {^tag, :caller}} ->
        run(%{s | notice: notice}, input, p, expected)
      {:DOWN, ^monitor, :process, ^guard, reason} ->
        {answer, _} = wait(%{s | down: reason})
        answer
    after
      Bounds.remaining(at) ->
        if Bounds.now() < at, do: take_notice(s, input, p, expected),
          else: Codec.error(:deadline_exceeded, :crypto)
    end
  end

  defp run(s, input, p, expected) do
    try do
      count = if s.mode == :single, do: 1, else: count(input, 0, count_limit(p))
      current = bootstrap(s, input, p, expected, count)
      {outcome, current} = wait(current)
      wait_end(Bounds.now())
      cleanup(current)
      answer = materialize(outcome, current)
      emit(current, answer)
      answer
    catch
      :throw, {:jose_error, reason, layer} ->
        cancel(s)
        Codec.error(reason, layer)
      _, _ ->
        cancel(s)
        Codec.error(:internal_failure, :internal)
    after
      cleanup(s)
    end
  end

  defp cancel(s) do
    :atomics.put(s.flag, 1, 1)
    # Returning the caller notice uses the same cancellation marker as caller
    # death and wakes the guard without exposing any exception term to it.
    if :ets.info(s.notice, :owner) == self() do
      try do
        :ets.give_away(s.notice, s.guard, {s.tag, :caller})
      catch
        :error, :badarg -> :ok
      end
    end
    ref = :erlang.monitor(:process, s.guard)
    try do
      await_guard(s.guard, ref, s.f + Bounds.teardown(:atomics.get(s.flag, 2)))
    after
      :erlang.demonitor(ref, [:flush])
    end
    wait_end(Bounds.now())
  end

  defp await_guard(guard, ref, at) do
    receive do
      {:DOWN, ^ref, :process, ^guard, _} -> :ok
    after
      Bounds.remaining(at) ->
        if Bounds.now() < at, do: await_guard(guard, ref, at), else: :ok
    end
  end

  # The observable boundary precedes cleanup and every caller-owned handler.
  def wait_end(at), do: at

  defp budgets(p) do
    Codec.ensure(is_map(p) and not is_map_key(p, :__struct__), :invalid_policy)
    for_budget(:maps.get(:timeout, p, nil))
    for_budget(:maps.get(:resolve_timeout, p, nil))
    for_budget(:maps.get(:unwrap_timeout, p, nil))
    Codec.ensure(p.resolve_timeout + p.unwrap_timeout < p.timeout, :invalid_policy)
  end
  defp for_budget(n), do: Codec.ensure(is_integer(n) and n >= 1 and n <= 300_000, :invalid_policy)

  defp separate(p, mode) do
    protected = :maps.get(:protected, p, nil)
    Codec.ensure(is_map(protected), :invalid_policy)
    expected = :maps.get(:expected, protected, nil)
    if mode == :single, do: Codec.ensure(is_map_key(protected, :expected), :invalid_policy)
    stripped = if mode == :single, do: :maps.remove(:expected, protected), else: protected
    {:maps.put(:protected, stripped, p), expected}
  end

  defp count_limit(p) do
    case :maps.get(:max_tokens, p, 10_000) do
      n when is_integer(n) and n in 1..10_000 -> n
      _ -> 10_000
    end
  end
  defp count([], n, _), do: n
  defp count([_ | _], n, n), do: :over_cap
  defp count([_ | rest], n, limit), do: count(rest, n + 1, limit)
  defp count(_, _, _), do: :improper

  defp bootstrap(s, input, p, expected, count) do
    tag = s.tag
    monitor = s.monitor
    guard = s.guard
    receive do
      {^tag, :preflight, pid} ->
        send(pid, {tag, :policy, p})
        send(pid, {tag, :count, count})
        cond do
          count in [:over_cap, :improper] -> :ok
          s.mode == :single ->
            token = if is_binary(input), do: input, else: nil
            if continue?(s), do: send(pid, {tag, :item, 0, :exact, token, expected})
            send(pid, {tag, :input_end})
          true -> stream(input, 0, pid, s)
        end
        s
      {:DOWN, ^monitor, :process, ^guard, reason} -> %{s | down: reason}
    after
      Bounds.remaining(s.f + Bounds.teardown(:atomics.get(s.flag, 2))) -> s
    end
  end

  defp continue?(s), do: Bounds.now() < s.d and :atomics.get(s.flag, 1) == 0
  defp stream([], _, pid, s), do: send(pid, {s.tag, :input_end})
  defp stream([item | rest], i, pid, s) do
    if continue?(s) do
      {kind, token, expected} = shape(item)
      send(pid, {s.tag, :item, i, kind, token, expected})
      stream(rest, i + 1, pid, s)
    end
  end

  defp shape(%{token: token, expected: expected} = item) do
    kind = if map_size(item) == 2, do: :exact, else: :extra
    token = if is_binary(token), do: token, else: nil
    expected = cond do
      kind != :exact -> nil
      Bounds.within?(expected, Bounds.item_words(), Bounds.binary_bytes()) -> expected
      true -> :oversized
    end
    {kind, token, expected}
  end
  defp shape(_), do: {:not_item, nil, nil}

  defp wait(s) do
    at = s.f + Bounds.teardown(:atomics.get(s.flag, 2))
    cond do
      Bounds.now() >= at -> {Codec.error(:deadline_exceeded, :crypto), s}
      s.down != nil and s.reply != nil -> finish_reply(s)
      s.down == :deadline -> {Codec.error(:deadline_exceeded, :crypto), s}
      s.down != nil and s.down != :replied -> {Codec.error(:internal_failure, :internal), s}
      true -> receive_one(s, at)
    end
  end

  defp receive_one(s, at) do
    tag = s.tag
    monitor = s.monitor
    guard = s.guard
    receive do
      {:'ETS-TRANSFER', notice, _, {^tag, :caller}} -> wait(%{s | notice: notice})
      {^tag, :payload, i, payload} -> wait(%{s | payloads: :maps.put(i, payload, s.payloads)})
      {^tag, :settled, i, reason, layer, auth} ->
        wait(%{s | settled: :maps.put(i, {reason, layer}, s.settled), auth: [auth | s.auth]})
      {^tag, :group, duration, items} -> wait(%{s | groups: [{duration, items} | s.groups]})
      {^tag, :reply, outcome, n, groups} -> wait(%{s | reply: {outcome, n, groups}})
      {:DOWN, ^monitor, :process, ^guard, reason} -> wait(%{s | down: reason})
    after
      Bounds.remaining(at) -> wait(s)
    end
  end

  defp finish_reply(%{reply: {{:outer, reason, layer}, _, _}} = s), do: {Codec.error(reason, layer), s}
  defp finish_reply(%{reply: {:ok, n, _}} = s) do
    if missing?(0, n, s) and Bounds.now() < s.f do
      receive_one(s, s.f)
    else
      {{:results, n}, s}
    end
  end
  defp materialize({:results, n}, s) do
    results = results(0, n, s, [])
    if s.mode == :single, do: hd(results), else: {:ok, results}
  end
  defp materialize(error, _), do: error

  defp missing?(n, n, _), do: false
  defp missing?(i, n, s) do
    case :maps.find(i, s.settled) do
      {:ok, {:ok, _}} -> not is_map_key(s.payloads, i) or missing?(i + 1, n, s)
      _ -> missing?(i + 1, n, s)
    end
  end
  defp results(n, n, _, acc), do: :lists.reverse(acc)
  defp results(i, n, s, acc) do
    result = case :maps.find(i, s.settled) do
      {:ok, {:ok, _}} -> case :maps.find(i, s.payloads) do
        {:ok, payload} -> {:ok, payload}
        :error -> Codec.error(:internal_failure, :internal)
      end
      {:ok, {reason, layer}} -> Codec.error(reason, layer)
      :error -> Codec.error(:internal_failure, :internal)
    end
    results(i + 1, n, s, [result | acc])
  end

  defp cleanup(s) do
    :erlang.unalias(s.address)
    drain(s.tag, s.notice)
  end
  defp drain(tag, notice) do
    receive do
      {:'ETS-TRANSFER', tid, _, {^tag, :caller}} -> drain(tag, tid)
      message when is_tuple(message) and tuple_size(message) > 0 and elem(message, 0) == tag -> drain(tag, notice)
    after
      0 -> if notice != nil and :ets.info(notice, :owner) == self(), do: :ets.delete(notice)
    end
  end

  defp emit(s, answer) do
    Enum.each(Enum.reverse(s.auth), fn auth ->
      if auth != nil,
        do: :telemetry.execute([:request_seal, :jose, :content_authentication], %{}, %{outcome: auth})
    end)
    Enum.each(s.groups, fn {us, items} ->
      :telemetry.execute([:request_seal, :custody, :unwrap],
        %{duration: System.convert_time_unit(us, :microsecond, :native), items: items}, %{})
    end)
    if s.mode == :batch do
      results = case answer do
        {:ok, results} -> results
        _ -> []
      end
      count = :atomics.get(s.flag, 2)
      groups = case s.reply do
        {_, _, groups} -> groups
        _ -> 0
      end
      :telemetry.execute([:request_seal, :jose, :decrypt_many],
        %{count: count, groups: groups, failed: Enum.count(results, &match?({:error, _}, &1)),
          deadline_exceeded: Enum.count(results, &match?({:error, %{reason: :deadline_exceeded}}, &1))}, %{})
    end
  end
end
