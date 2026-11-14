defmodule RequestSeal.JOSE.JWE.Open do
  @moduledoc false
  alias RequestSeal.Custody
  alias Custody.{Context, Sink}
  alias RequestSeal.JOSE.{Error, Header, KeyManagement.Agreement, Support}
  alias RequestSeal.JOSE.JWE.Result
  import Support
  @ecdh ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)

  def call(items, p, started, batch?) do
    caller = self()
    reply = :erlang.alias()
    deadline = started + p.timeout

    {pid, monitor} =
      spawn_monitor(fn ->
        Process.flag(:sensitive, true)
        Process.flag(:trap_exit, true)
        owner = Process.monitor(caller)
        fallback = if batch?, do: :deadline_exceeded, else: :decryption_failed

        result =
          safe(fn -> execute(items, p, started, owner, caller, batch?) end, fallback, :crypto)

        if Process.alive?(caller), do: send(reply, {reply, result})
      end)

    try do
      receive do
        {^reply, result} ->
          # The original monitor proves coordinator termination; allocating a
          # second monitor on every successful single open adds no protection.
          stop_coordinator(pid, monitor)

          if now() < deadline + 100,
            do: result,
            else: {:error, Error.new(:deadline_exceeded, :crypto)}

        {:DOWN, ^monitor, _, ^pid, _} ->
          {:error,
           Error.new(if(batch?, do: :deadline_exceeded, else: :decryption_failed), :crypto)}
      after
        max(deadline + 100 - now(), 0) ->
          stop_coordinator(pid, monitor)
          {:error, Error.new(:deadline_exceeded, :crypto)}
      end
    after
      :erlang.unalias(reply)
      Process.demonitor(monitor, [:flush])
      flush(reply)
    end
  end

  defp stop_coordinator(pid, monitor) do
    Process.exit(pid, :kill)
    receive do: ({:DOWN, ^monitor, _, ^pid, _} -> :ok)
  end

  defp flush(reply) do
    receive do
      {^reply, _} -> flush(reply)
    after
      0 -> :ok
    end
  end

  defp execute(items, p, started, owner, caller, batch?) do
    rows = if batch?, do: preflight!(items, p), else: [{0, hd(items), :unprepared, nil}]

    state = %{
      p: p,
      r: started + p.resolve_timeout,
      d: started + p.timeout,
      owner: owner,
      count: length(items),
      admissions: %{},
      pending_admissions: MapSet.new(indices(length(items))),
      rprime: nil,
      tokens: %{},
      results: %{},
      resolvers: %{},
      resolved: %{},
      resolution_done: false,
      groups: %{},
      group_count: 0,
      workers: %{},
      idle: [],
      queue: :queue.new()
    }

    # All children link to this sensitive coordinator. An abnormal coordinator
    # exit kills them too; its ordinary finalization explicitly reaps them.
    try do
      state =
        if batch? do
          start_admission(state, rows)
        else
          # Single policy validation already checked expected; no batch scan or
          # second expectation encoding is needed on the single-token path.
          [{index, item, _, _}] = rows
          result = safe(fn -> {:ok, admit(item.token, item.expected, p, :unprepared)} end)
          accept_admission(state, index, result)
        end

      loop(state)
    after
      # The process dictionary holds PIDs/aliases only, never keys or plaintext.
      cleanup(started + p.timeout, owner, caller)
    end
  end

  defp preflight!(items, p) do
    ensure(proper_list?(items), :invalid_serialization)
    ensure(length(items) <= p.max_tokens, :limit)

    {rows, input, plaintext, _cache} =
      items
      |> Enum.with_index()
      |> Enum.reduce({[], 0, 0, %{}}, fn {item, index}, {rows, input, plaintext, cache} ->
        case item do
          %{token: token, expected: expected} ->
            {encoded, cache} =
              case Map.fetch(cache, expected) do
                {:ok, size} ->
                  {size, cache}

                :error ->
                  size =
                    case safe(fn -> {:ok, byte_size(json_encode(expected))} end) do
                      {:ok, size} -> size
                      _ -> 0
                    end

                  {size, Map.put(cache, expected, size)}
              end

            input = input + encoded + if(is_binary(token), do: byte_size(token), else: 0)
            split = safe(fn -> {:ok, compact(token, 5)} end)

            size =
              case split do
                {:ok, [_, _, _, ct, _]} -> div(byte_size(ct) * 3, 4)
                _ -> 0
              end

            {[{index, item, split, encoded} | rows], input, plaintext + size, cache}

          _ ->
            {[{index, item, :unprepared, nil} | rows], input, plaintext, cache}
        end
      end)

    ensure(input <= p.max_total_input and plaintext <= p.max_total_plaintext, :limit)
    Enum.reverse(rows)
  end

  defp start_admission(state, []), do: state

  defp start_admission(state, rows) do
    parent = self()
    p = Map.drop(state.p, [:key_resolver])
    size = ceil(length(rows) / System.schedulers_online())

    Enum.reduce(Enum.chunk_every(rows, size), state, fn range, s ->
      {pid, ref} =
        :erlang.spawn_opt(__MODULE__, :admission_worker, [parent, range, p, s.r], [
          :link,
          :monitor
        ])

      track(pid, ref)
      {first, _, _, _} = hd(range)
      {last, _, _, _} = List.last(range)
      %{s | admissions: Map.put(s.admissions, ref, {pid, first, last})}
    end)
  end

  @doc false
  def admission_worker(parent, rows, p, deadline) do
    Process.flag(:sensitive, true)

    Enum.each(rows, fn {index, item, split, encoded} ->
      if now() < deadline do
        result =
          safe(fn ->
            ensure(
              is_map(item) and map_size(item) == 2 and is_map_key(item, :token) and
                is_map_key(item, :expected),
              :invalid_serialization
            )

            expected!(
              item.expected,
              p.protected.permitted,
              ~w(alg enc iv tag epk apu apv),
              encoded
            )

            {:ok, admit(item.token, item.expected, p, split)}
          end)

        send(parent, {:admitted, self(), index, result})
      end
    end)

    # Finished range owners exit naturally. Their monitors stay tracked until
    # termination; only the reusable AEAD pool has idle workers.
    :ok
  end

  defp accept_admission(state, index, result) do
    accepted_at = now()

    if accepted_at >= state.r do
      state
    else
      state = %{state | pending_admissions: MapSet.delete(state.pending_admissions, index)}

      case result do
        {:error, _} = error ->
          seal_barrier(put_result(state, index, error), accepted_at)

        {:ok, token} ->
          state = %{state | tokens: Map.put(state.tokens, index, token)}

          if token.width_valid do
            seal_barrier(start_resolver(state, index, token), now())
          else
            state = seal_barrier(state, accepted_at)
            state = prepare_fallback(state, index)
            if Map.has_key?(state.tokens, index), do: enqueue(state, index, :error), else: state
          end
      end
    end
  end

  defp admit(token, expected, p, split) do
    [protected, ek, iv, ct, tag] =
      case split do
        :unprepared -> compact(token, 5)
        {:ok, parts} -> parts
        {:error, %{reason: reason, layer: layer}} -> fail(reason, layer)
      end

    h = Header.parse(protected)
    alg = selected(h, :jwe, p.algorithms, p.encryption)
    ek = decode(ek)
    iv = decode(iv)
    ensure(byte_size(iv) == 12, :invalid_iv)
    tag = decode(tag)
    ensure(byte_size(tag) == 16, :invalid_tag)
    ct = decode(ct)
    ensure(byte_size(ct) <= p.max_plaintext, :limit)
    valid = width_valid?(alg, ek, h["enc"])
    params = params(alg, h)

    read =
      ["alg", "enc"] ++
        cond do
          alg in ~w(A128GCMKW A256GCMKW) -> ~w(iv tag)
          alg in @ecdh -> ~w(epk apu apv)
          true -> []
        end

    protected!(h, expected, p.protected.permitted, read)

    %{
      protected: protected,
      h: h,
      alg: alg,
      ek: ek,
      iv: iv,
      ct: ct,
      tag: tag,
      params: params,
      width_valid: valid
    }
  end

  defp width_valid?(alg, ek, enc) when alg in ~w(A128KW A256KW ECDH-ES+A128KW ECDH-ES+A256KW),
    do: byte_size(ek) == width(enc) + 8

  defp width_valid?(alg, ek, _) when alg in ["dir", "ECDH-ES"], do: ek == ""

  defp width_valid?(alg, ek, enc) when alg in ~w(A128GCMKW A256GCMKW),
    do: byte_size(ek) == width(enc)

  defp width_valid?(_, ek, _), do: byte_size(ek) in 256..1024

  defp params(alg, h) when alg in ~w(A128GCMKW A256GCMKW) do
    iv = decode(h["iv"])
    ensure(byte_size(iv) == 12, :invalid_iv)
    tag = decode(h["tag"])
    ensure(byte_size(tag) == 16, :invalid_tag)
    %{iv: iv, tag: tag}
  end

  defp params(alg, h) when alg in @ecdh, do: Agreement.header_params!(alg, h)
  defp params(_, _), do: %{}

  defp start_resolver(state, index, token) do
    if now() >= state.r do
      put_result(state, index, {:error, Error.new(:key_resolver_failed, :key)})
    else
      request = %{algorithm: token.alg, encryption: token.h["enc"], header: token.h}
      parent = self()
      resolver = state.p.key_resolver
      deadline = state.r
      {pid, ref} = child(fn -> resolver_worker(parent, index, request, resolver, deadline) end)
      %{state | resolvers: Map.put(state.resolvers, ref, {pid, index})}
    end
  end

  @doc false
  def resolver_worker(parent, index, request, resolver, deadline) do
    Process.flag(:sensitive, true)

    result =
      safe(
        fn ->
          ensure(now() < deadline, :key_resolver_failed, :key)
          entry = resolve(resolver, request)

          ensure(
            map_size(entry) == 2 and match?(%{key: %RequestSeal.KeyHandle{}}, entry),
            :key_resolver_failed,
            :key
          )

          {:ok, entry.key}
        end,
        :key_resolver_failed,
        :key
      )

    send(parent, {:resolved, self(), index, result})
  end

  defp seal_barrier(state, timestamp) do
    if state.rprime == nil and MapSet.size(state.pending_admissions) == 0 and
         map_size(state.resolvers) == 0,
       do: %{state | rprime: min(timestamp, state.r)},
       else: state
  end

  defp loop(state) do
    state = expire(state)

    state =
      if now() < state.d and not state.resolution_done and
           (state.rprime != nil or
              (MapSet.size(state.pending_admissions) == 0 and map_size(state.resolvers) == 0)),
         do: start_groups(%{state | rprime: state.rprime || now()}),
         else: state

    state = fill_pool(state)

    cond do
      map_size(state.results) == state.count ->
        results = for index <- indices(state.count), do: Map.fetch!(state.results, index)
        {:ok, results, state.group_count}

      now() >= state.d ->
        results =
          for index <- indices(state.count),
              do: Map.get(state.results, index, {:error, Error.new(:deadline_exceeded, :crypto)})

        {:ok, results, state.group_count}

      true ->
        receive_work(state)
    end
  end

  defp receive_work(state) do
    owner = state.owner

    receive do
      {:DOWN, ^owner, _, _, _} ->
        exit(:shutdown)

      {:admitted, pid, index, result} ->
        case Map.fetch(state.admissions, Process.get({:monitor, pid})) do
          {:ok, {^pid, first, last}} when index >= first and index <= last ->
            if MapSet.member?(state.pending_admissions, index),
              do: loop(accept_admission(state, index, result)),
              else: loop(state)

          _ ->
            loop(state)
        end

      {:resolved, pid, index, result} ->
        case Map.fetch(state.resolvers, Process.get({:monitor, pid})) do
          :error ->
            loop(state)

          {:ok, {^pid, ^index}} ->
            ref = Process.get({:monitor, pid})
            s = %{state | resolvers: Map.delete(state.resolvers, ref)}

            accepted_at = now()

            s =
              if accepted_at >= s.r do
                put_result(s, index, {:error, Error.new(:key_resolver_failed, :key)})
              else
                case result do
                  {:ok, handle} -> %{s | resolved: Map.put(s.resolved, index, handle)}
                  {:error, _} = error -> put_result(s, index, error)
                end
              end

            loop(seal_barrier(s, accepted_at))
        end

      {tag, index, outcome} when is_reference(tag) ->
        case Map.fetch(state.groups, tag) do
          :error ->
            loop(state)

          {:ok, group} ->
            case Sink.accept(group.sink, index, outcome) do
              :expired ->
                loop(finish_group(state, tag, :timeout))

              :unknown ->
                loop(state)

              {:settled, outcome} ->
                if MapSet.member?(group.pending, index) do
                  group = %{group | pending: MapSet.delete(group.pending, index)}

                  loop(
                    enqueue(%{state | groups: Map.put(state.groups, tag, group)}, index, outcome)
                  )
                else
                  loop(state)
                end
            end
        end

      {tag, _summary} when is_reference(tag) ->
        loop(
          if Map.has_key?(state.groups, tag), do: finish_group(state, tag, :error), else: state
        )

      {:authenticated, pid, index, result} ->
        case Map.fetch(state.workers, Process.get({:monitor, pid})) do
          :error ->
            loop(state)

          {:ok, {^pid, ^index}} ->
            ref = Process.get({:monitor, pid})

            s = %{
              state
              | workers: Map.put(state.workers, ref, {pid, :idle}),
                idle: [pid | state.idle]
            }

            loop(if now() < s.d, do: put_result(s, index, result), else: s)
        end

      {:DOWN, ref, _, _, _} ->
        loop(down(state, ref))

      {:EXIT, _, _} ->
        loop(state)
    after
      wait_time(state) -> loop(state)
    end
  end

  defp expire(state) do
    state =
      if now() >= state.r and map_size(state.admissions) > 0 do
        for {ref, {pid, _, _}} <- state.admissions, do: retire(pid, ref)
        %{state | admissions: %{}}
      else
        state
      end

    state =
      if not state.resolution_done and state.rprime == nil and now() >= state.r do
        # R' is fixed at R BEFORE cancellation, fallback preparation or grouping.
        s =
          Enum.reduce(state.pending_admissions, state, fn index, s ->
            put_result(s, index, {:error, Error.new(:deadline_exceeded, :input)})
          end)

        s =
          Enum.reduce(s.resolvers, s, fn {ref, {pid, index}}, s ->
            retire(pid, ref)
            put_result(s, index, {:error, Error.new(:key_resolver_failed, :key)})
          end)

        %{s | resolvers: %{}, admissions: %{}, pending_admissions: MapSet.new(), rprime: state.r}
      else
        state
      end

    Enum.reduce(state.groups, state, fn {tag, group}, s ->
      if now() >= group.deadline, do: finish_group(s, tag, :timeout), else: s
    end)
  end

  defp start_groups(state) do
    # R' is fixed before fallback preparation; every U respects the reserve.
    deadline = state.rprime + state.p.unwrap_timeout
    state = Enum.reduce(state.resolved, state, fn {index, _}, s -> prepare_fallback(s, index) end)

    {ready, refused} =
      state.resolved
      |> Enum.filter(fn {index, _} -> Map.has_key?(state.tokens, index) end)
      |> Enum.split_with(fn {index, handle} ->
        # A resolver may select one handle for headers naming different
        # algorithms. Binding belongs to each token, never its first neighbour.
        handle.algorithm == {:jwe, state.tokens[index].alg} and
          proper_list?(handle.capabilities) and :unwrap in handle.capabilities
      end)

    state = Enum.reduce(refused, state, fn {index, _}, s -> enqueue(s, index, :error) end)
    groups = ready |> Enum.sort() |> Enum.group_by(&elem(&1, 1), &elem(&1, 0))

    Enum.reduce(groups, %{state | resolution_done: true, resolved: %{}}, fn {handle, indices},
                                                                            s ->
      items =
        Enum.map(indices, fn i ->
          t = s.tokens[i]
          {i, t.ek, t.params, width(t.h["enc"]) * 8}
        end)

      context = %Context{owner: self(), deadline: deadline}
      sink = Sink.new(items, context)
      tag = Sink.tag(sink)
      Process.put({:sink, tag}, sink)

      {worker, worker_ref} =
        child(fn ->
          receive do
            {^tag, :start, watcher} ->
              summary = Custody.unwrap(handle, items, sink, context)
              send(watcher, {tag, :unwrap_summary, summary})
          end
        end)

      parent = self()
      {pid, ref} = child(fn -> watch_unwrap(parent, worker, sink, context, items) end)
      Process.put({:unwrap_watcher, ref}, pid)

      Process.put({:group, ref}, tag)

      group = %{
        sink: sink,
        deadline: deadline,
        pending: MapSet.new(indices),
        worker: worker,
        worker_ref: worker_ref,
        pid: pid,
        ref: ref
      }

      %{s | groups: Map.put(s.groups, tag, group), group_count: s.group_count + 1}
    end)
  end

  defp watch_unwrap(parent, worker, sink, context, items) do
    # The watcher runs no custodian code. It survives cancellation of the real
    # callback long enough to report the one unwrap event. Both are direct,
    # sensitive, linked children tracked by the coordinator through DOWN.
    Process.flag(:trap_exit, true)
    owner = Process.monitor(parent)
    monitor = Process.monitor(worker)
    tag = Sink.tag(sink)
    started = System.monotonic_time()
    send(worker, {tag, :start, self()})

    {summary, down?} =
      receive do
        {^tag, :unwrap_summary, result} -> {result, false}
        {:DOWN, ^monitor, :process, ^worker, _} -> {{:error, :custodian_failure}, true}
        {:DOWN, ^owner, :process, ^parent, _} -> {{:error, :custodian_failure}, false}
        {:EXIT, ^parent, _} -> {{:error, :custodian_failure}, false}
        :cancel -> {{:error, :custodian_failure}, false}
      after
        Context.remaining(context) -> {{:error, :deadline_exceeded}, false}
      end

    unless down? do
      Process.exit(worker, :kill)
      receive do: ({:DOWN, ^monitor, :process, ^worker, _} -> :ok)
    end

    # The callback is now reaped. Telemetry runs in this killable child, never
    # in the coordinator; a blocking handler cannot hide caller death or D.
    Process.flag(:trap_exit, false)

    if Process.alive?(parent) do
      Custody.unwrap_telemetry(started, items)
      Sink.summary(sink, summary)
    end

    Process.demonitor(owner, [:flush])
  end

  defp finish_group(state, tag, outcome) do
    group = Map.fetch!(state.groups, tag)
    # Revoke and drain before settling remaining positions. A summary can never
    # replace an accepted prefix, and a queued delivery at U is never accepted.
    Sink.close(group.sink)
    Process.delete({:sink, tag})
    Process.delete({:group, group.ref})
    outcome = if now() >= group.deadline, do: :timeout, else: outcome
    retire(group.worker, group.worker_ref)
    send(group.pid, :cancel)
    state = %{state | groups: Map.delete(state.groups, tag)}
    Enum.reduce(Enum.sort(group.pending), state, &enqueue(&2, &1, outcome))
  end

  defp down(state, ref) do
    cond do
      Map.has_key?(state.admissions, ref) ->
        {pid, _, _} = state.admissions[ref]
        forget(pid, ref)
        %{state | admissions: Map.delete(state.admissions, ref)}

      Map.has_key?(state.resolvers, ref) ->
        {pid, index} = state.resolvers[ref]
        forget(pid, ref)

        state
        |> Map.put(:resolvers, Map.delete(state.resolvers, ref))
        |> put_result(index, {:error, Error.new(:key_resolver_failed, :key)})
        |> seal_barrier(now())

      Map.has_key?(state.workers, ref) ->
        {pid, index} = state.workers[ref]
        forget(pid, ref)

        s = %{state | workers: Map.delete(state.workers, ref), idle: List.delete(state.idle, pid)}

        if index == :idle,
          do: s,
          else: put_result(s, index, {:error, Error.new(:decryption_failed, :crypto)})

      true ->
        case Process.get({:group, ref}) do
          nil ->
            # A child can report a result before its DOWN reaches this owner.
            # The result stays settled; consume the monitor without flushing
            # or synchronously cancelling a completed process.
            case Process.get({:child, ref}) do
              nil ->
                state

              pid ->
                forget(pid, ref)
                state
            end

          tag ->
            forget(Map.fetch!(state.groups, tag).pid, ref)
            finish_group(state, tag, :error)
        end
    end
  end

  defp prepare_fallback(state, index) do
    token = state.tokens[index]
    # Draw once on EVERY path reaching key management, including success,
    # before handle/unwrap operations or AEAD. Both public open APIs use this.
    case safe(fn -> {:ok, random(width(token.h["enc"]))} end) do
      {:ok, fallback} ->
        %{state | tokens: Map.put(state.tokens, index, Map.put(token, :fallback, fallback))}

      {:error, _} = error ->
        put_result(state, index, error)
    end
  end

  defp enqueue(state, index, outcome),
    do: %{state | queue: :queue.in({index, outcome}, state.queue)}

  defp fill_pool(state) do
    if now() < state.d and
         (state.idle != [] or map_size(state.workers) < System.schedulers_online()) do
      case :queue.out(state.queue) do
        {:empty, _} ->
          state

        {{:value, {index, outcome}}, queue} ->
          {pid, ref, state} =
            case state.idle do
              [pid | rest] ->
                {pid, Process.get({:monitor, pid}), %{state | idle: rest}}

              [] ->
                {pid, ref} =
                  :erlang.spawn_opt(__MODULE__, :authentication_worker, [self()], [
                    :link,
                    :monitor
                  ])

                track(pid, ref)
                {pid, ref, state}
            end

          send(pid, {:authenticate, index, state.tokens[index], outcome})
          fill_pool(%{state | queue: queue, workers: Map.put(state.workers, ref, {pid, index})})
      end
    else
      state
    end
  end

  @doc false
  def authentication_worker(parent) do
    Process.flag(:sensitive, true)
    authentication_loop(parent)
  end

  defp authentication_loop(parent) do
    receive do
      {:authenticate, index, token, outcome} ->
        # authenticate/2 owns a fresh exception boundary and success flag on
        # EVERY iteration; no previous item's CEK or flag is carried forward.
        send(parent, {:authenticated, self(), index, authenticate(token, outcome)})
        authentication_loop(parent)

      :stop ->
        :ok
    end
  end

  defp authenticate(t, outcome) do
    safe(
      fn ->
        {cek, success} =
          case outcome do
            {:ok, cek} when t.width_valid -> {cek, true}
            _ -> {t.fallback, false}
          end

        plaintext =
          :crypto.crypto_one_time_aead(
            cipher(t.h["enc"]),
            cek,
            t.iv,
            t.ct,
            t.protected,
            t.tag,
            false
          )

        valid = is_binary(plaintext) and success
        # This event is immediately after the real AEAD returns. No stage, token,
        # bytes, identity, or timing measurement is exposed.
        :telemetry.execute([:request_seal, :jose, :content_authentication], %{}, %{
          outcome: if(valid, do: :ok, else: :failed)
        })

        ensure(valid, :decryption_failed, :crypto)

        {:ok,
         %Result{
           algorithm: t.alg,
           encryption: t.h["enc"],
           header: t.h,
           protected: t.protected,
           plaintext: plaintext
         }}
      end,
      :decryption_failed,
      :crypto
    )
  end

  defp put_result(state, index, result),
    do: %{
      state
      | results: Map.put(state.results, index, result),
        tokens: Map.delete(state.tokens, index)
    }

  defp wait_time(s) do
    deadlines =
      [s.d] ++
        if(s.resolution_done and map_size(s.admissions) == 0, do: [], else: [s.r]) ++
        Enum.map(s.groups, fn {_, g} -> g.deadline end)

    max(Enum.min(deadlines) - now(), 0)
  end

  defp child(fun) do
    {pid, ref} =
      :erlang.spawn_opt(
        fn ->
          Process.flag(:sensitive, true)
          fun.()
        end,
        [:link, :monitor]
      )

    track(pid, ref)
    {pid, ref}
  end

  defp track(pid, ref) do
    Process.put({:child, ref}, pid)
    Process.put({:monitor, pid}, ref)
  end

  defp retire(pid, _ref) do
    # Cancellation does not prove termination. Keep the monitor and link in
    # the child registry until DOWN is consumed, or finalization reaps it.
    Process.exit(pid, :kill)
  end

  defp forget(pid, ref) do
    Process.unlink(pid)
    Process.delete({:child, ref})
    Process.delete({:monitor, pid})
    Process.delete({:unwrap_watcher, ref})
  end

  defp cleanup(deadline, owner, caller) do
    for {{:sink, _}, sink} <- Process.get(), do: Sink.close(sink)
    children = for {{:child, ref}, pid} <- Process.get(), into: %{}, do: {ref, pid}
    cancelled = now() >= deadline or not Process.alive?(caller)

    for {ref, pid} <- children do
      if not cancelled and Process.get({:unwrap_watcher, ref}) == pid do
        send(pid, :cancel)
      else
        Process.exit(pid, :kill)
      end
    end

    reap(children, if(cancelled, do: :infinity, else: deadline), owner)
  end

  defp reap(children, _, _) when map_size(children) == 0, do: :ok

  defp reap(children, deadline, owner) do
    wait = if deadline == :infinity, do: :infinity, else: max(deadline - now(), 0)

    receive do
      {:DOWN, ^owner, :process, _, _} ->
        kill_children(children)
        reap(children, :infinity, owner)

      {:DOWN, ref, :process, pid, _} ->
        if Map.get(children, ref) == pid,
          do: reap(Map.delete(children, ref), deadline, owner),
          else: reap(children, deadline, owner)

      _ ->
        reap(children, deadline, owner)
    after
      wait ->
        kill_children(children)
        reap(children, :infinity, owner)
    end
  end

  defp kill_children(children) do
    for {_, pid} <- children, do: Process.exit(pid, :kill)
  end

  defp indices(0), do: []
  defp indices(n), do: 0..(n - 1)
  defp now, do: System.monotonic_time(:millisecond)
  defp width("A128GCM"), do: 16
  defp width("A256GCM"), do: 32
  defp cipher("A128GCM"), do: :aes_128_gcm
  defp cipher("A256GCM"), do: :aes_256_gcm
end
