defmodule RequestSeal.Test.JWEOpenRuntime do
  @moduledoc false
  alias RequestSeal.{Custody, JOSE.JWE}
  alias RequestSeal.JOSE.JWE.{Bounds, Codec}

  def policy(handle, extra \\ %{}) do
    Map.merge(
      %{
        algorithms: ["A256KW"],
        encryption: ["A256GCM"],
        max_plaintext: 1_048_576,
        max_tokens: 10_000,
        max_total_input: 67_108_864,
        max_total_plaintext: 67_108_864,
        timeout: 30_000,
        resolve_timeout: 20_000,
        unwrap_timeout: 5_000,
        protected: %{permitted: []},
        key_resolver: fn %{algorithm: a} -> {:ok, %{algorithm: a, key: handle}} end
      },
      extra
    )
  end

  def single(p, expected \\ %{}),
    do:
      p
      |> Map.drop([:max_tokens, :max_total_input, :max_total_plaintext])
      |> Map.put(:protected, %{expected: expected, permitted: p.protected.permitted})

  # Select a valid JSON tree close to W_item using the running VM's word size.
  # Empty strings keep aggregate encoded input below the public 64 MiB limit.
  def near_cap do
    Enum.reduce_while(1..334, %{}, fn count, previous ->
      maps = List.duplicate(%{"" => ""}, count)
      value = %{"pad" => Enum.chunk_every(maps, 32)}

      if :erts_debug.flat_size(value) > Bounds.item_words() or
           not Bounds.within?(value, Bounds.item_words()) do
        {:halt, previous}
      else
        {:cont, value}
      end
    end)
  end

  def real_key do
    kek = Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    {:ok, handle} = Custody.Local.new({:jwe, "A256KW"}, {:aes, kek})
    {:ok, token} = JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", handle)
    {handle, token}
  end

  def __after_compile__(env, binary) do
    key = {__MODULE__, :test_beam, env.module}
    :persistent_term.put(key, binary)
    ExUnit.after_suite(fn _ -> :persistent_term.erase(key) end)
  end

  def with_peer(fun, schedulers \\ :online) do
    paths = Enum.flat_map(:code.get_path(), fn p -> [~c"-pa", p] end)

    scheduler_args =
      if schedulers == :online,
        do: [],
        else: [~c"+S", String.to_charlist("#{schedulers}:#{schedulers}")]

    {:ok, peer, _} = :peer.start_link(%{connection: :standard_io, args: scheduler_args ++ paths})

    try do
      :ok = :peer.call(peer, :application, :ensure_started, [:crypto])
      :ok = :peer.call(peer, __MODULE__, :load_trace_modules, [])
      {:module, module} = :erlang.fun_info(fun, :module)

      case :persistent_term.get({__MODULE__, :test_beam, module}, nil) do
        nil ->
          :ok

        binary ->
          {:module, ^module} =
            :peer.call(peer, :code, :load_binary, [module, ~c"peer-test", binary])
      end

      :peer.call(peer, __MODULE__, :invoke, [fun], 600_000)
    after
      :peer.stop(peer)
    end
  end

  def invoke(fun) do
    :erlang.process_flag(:message_queue_data, :off_heap)
    fun.()
  end

  def load_trace_modules do
    # Install patterns only after loading their targets. Load OTP helpers here
    # too: loader replies contain file paths and are not JWE control messages.
    for module <- [
          :ets,
          :atomics,
          :lists,
          :maps,
          :binary,
          :re,
          :base64,
          :json,
          RequestSeal.JOSE.JWE.Bounds,
          RequestSeal.JOSE.JWE.Codec,
          RequestSeal.JOSE.JWE.Guard,
          RequestSeal.JOSE.JWE.Coordinator,
          RequestSeal.JOSE.JWE.Open,
          RequestSeal.JOSE.JWE.Preflight,
          RequestSeal.JOSE.JWE.Worker,
          RequestSeal.JOSE.JWE.Resolver,
          RequestSeal.JOSE.JWE.Unwrap,
          RequestSeal.Custody
        ] do
      {:module, ^module} = :code.ensure_loaded(module)
    end

    :ok
  end

  def launch(n, topology, options \\ []) do
    {handle, token} = real_key()
    observer = self()
    :persistent_term.put({RequestSeal.Test.JWEOpenBlockingCustodian, :observer}, observer)

    resolver = fn %{algorithm: a} ->
      send(observer, {:resolver_entered, self()})

      receive do
        :continue -> :ok
      end

      selected =
        if topology == :custody do
          ref = handle.ref
          id = self()

          %{
            handle
            | ref: fn ->
                send(observer, {:custody_ref_used, id})
                ref.()
              end,
              custodian: RequestSeal.Test.JWEOpenBlockingCustodian
          }
        else
          handle
        end

      {:ok, %{algorithm: a, key: selected}}
    end

    p = policy(handle, %{key_resolver: resolver})
    p = Map.merge(p, Keyword.get(options, :policy, %{}))

    expected =
      Keyword.get(
        options,
        :expected,
        if(Keyword.get(options, :near_cap, false), do: near_cap(), else: %{})
      )

    # Include the expectation in a real authenticated token, with real AES-KW.
    plaintext = Keyword.get(options, :plaintext, "payload")
    header = [{"alg", "A256KW"}, {"enc", "A256GCM"}]
    header = if expected == %{}, do: header, else: header ++ [{"pad", expected["pad"]}]

    token =
      if expected == %{} and plaintext == "payload",
        do: token,
        else: elem(JWE.encrypt(header, plaintext, handle), 1)

    items = Keyword.get(options, :items, List.duplicate(%{token: token, expected: expected}, n))
    single = Keyword.get(options, :single, false)
    p = if single, do: single(p, expected), else: p
    hold_caller = Keyword.get(options, :hold_caller, false)

    {caller, monitor} =
      spawn_monitor(fn ->
        receive do
          :go ->
            result = if single, do: JWE.decrypt(token, p), else: JWE.decrypt_many(items, p)
            send(observer, {:returned, self(), result})

            if hold_caller,
              do:
                (receive do
                   :release -> :ok
                 end)
        end
      end)

    flags = [
      :procs,
      :set_on_spawn,
      :receive,
      :call,
      :monotonic_timestamp,
      {:tracer, observer}
    ]

    flags = if Keyword.get(options, :trace_input, true), do: [:send | flags], else: flags
    :erlang.trace(caller, true, flags)

    baseline_tables = :erlang.system_info(:ets_count)
    baseline_processes = :erlang.system_info(:process_count)
    send(caller, :go)

    s = %{
      caller: caller,
      monitor: monitor,
      handle: handle,
      n: n,
      topology: topology,
      trace_input: Keyword.get(options, :trace_input, true),
      pids: %{},
      refs: %{},
      remaining: 0,
      guard_ended: false,
      guard: nil,
      coordinator: nil,
      preflight: nil,
      resolvers: [],
      resolver_count: 0,
      resolver_spawns: 0,
      custody: [],
      custody_count: 0,
      messages: [],
      events: [],
      peak: 0,
      peak_tables: 0,
      baseline_tables: baseline_tables,
      baseline_processes: baseline_processes,
      return: nil
    }

    s
  end

  def start(n, topology, options \\ []) do
    s = launch(n, topology, options)

    s =
      collect_until(s, fn s ->
        s.resolver_count == n and s.resolver_spawns == n
      end)

    s =
      case topology do
        :resolvers ->
          s

        :queued ->
          true = :erlang.suspend_process(s.guard)
          Enum.each(s.resolvers, &send(&1, :continue))
          await(fn -> info(s.guard, :message_queue_len) >= n end)
          s

        :custody ->
          Enum.each(s.resolvers, &send(&1, :continue))
          collect_until(s, fn s -> s.custody_count == n end)
      end

    s
  rescue
    error ->
      # The invoking peer is also stopped by with_peer/2 on a failed placement.
      reraise error, __STACKTRACE__
  end

  def trigger(s, trigger) do
    stamp = Bounds.now()
    {before_vm, _} = :erlang.statistics(:exact_reductions)
    before_guard = info(s.guard, :reductions)

    case trigger do
      :caller -> Process.exit(s.caller, :kill)
      {:caller_reason, reason} -> Process.exit(s.caller, reason)
      :f -> :ok
      :d -> :ok
      :u -> :ok
      :coordinator -> Process.exit(s.coordinator, :kill)
    end

    if s.topology == :queued, do: :erlang.resume_process(s.guard)
    s = collect_until(s, fn s -> s.guard_ended end)
    s = delivered(s) |> collect_ends() |> delivered() |> drain_observations()
    {after_vm, _} = :erlang.statistics(:exact_reductions)

    %{
      s
      | events: [
          {:measurement, stamp, Bounds.now(), before_guard, after_vm - before_vm} | s.events
        ]
    }
  end

  def delivered(s) do
    ref = :erlang.trace_delivered(:all)

    receive do
      {:trace_delivered, :all, ^ref} -> s
      event -> delivered_wait(observe(s, event), ref)
    end
  end

  defp delivered_wait(s, ref) do
    receive do
      {:trace_delivered, :all, ^ref} -> s
      event -> delivered_wait(observe(s, event), ref)
    end
  end

  def cleanup(s) do
    Process.exit(s.caller, :kill)
    s = delivered(s) |> drain_observations()
    ref = if is_pid(s.guard), do: Process.monitor(s.guard), else: nil

    for pid <- [s.guard, s.coordinator], is_pid(pid) do
      try do
        :erlang.resume_process(pid)
      catch
        _, _ -> :ok
      end
    end

    if ref != nil do
      receive do
        {:DOWN, ^ref, :process, _, _} -> :ok
      after
        5_000 -> Process.exit(s.guard, :kill)
      end
    end

    for pid <- Map.keys(s.pids) ++ [s.caller] do
      monitor = Process.monitor(pid)

      try do
        :erlang.resume_process(pid)
      catch
        _, _ -> :ok
      end

      Process.exit(pid, :kill)

      receive do
        {:DOWN, ^monitor, :process, ^pid, _} -> :ok
      end
    end

    for {monitor, _} <- s.refs, do: Process.demonitor(monitor, [:flush])
    if ref != nil, do: Process.demonitor(ref, [:flush])
    Custody.release(s.handle)
    :persistent_term.erase({RequestSeal.Test.JWEOpenBlockingCustodian, :observer})
    Process.demonitor(s.monitor, [:flush])
    flush()
  end

  def collect_return(s, at) do
    # A continuously populated trace queue must not starve the observer's
    # deadline, particularly when a reversing mutation spins on receive after 0.
    if s.return != nil or Bounds.now() >= at do
      s
    else
      receive do
        event -> collect_return(observe(s, event), at)
      after
        Bounds.remaining(at) -> s
      end
    end
  end

  def collect_ends(s, at \\ Bounds.now() + 1_000_000) do
    if s.remaining == 0 or Bounds.now() >= at do
      s
    else
      receive do
        event -> collect_ends(observe(s, event), at)
      after
        Bounds.remaining(at) -> s
      end
    end
  end

  def collect_until(s, predicate, timeout \\ 60_000) do
    if predicate.(s) do
      s
    else
      receive do
        event -> collect_until(observe(s, event), predicate, timeout)
      after
        timeout ->
          raise "placement/end markers missing: #{inspect({s.n, s.resolver_count, s.custody_count, s.return})}"
      end
    end
  end

  # Match each new event once. Scanning the accumulated history after every
  # message makes a placement quadratic before its marker can even arrive.
  def collect_event(s, predicate, timeout \\ 60_000) do
    if Enum.any?(s.events, predicate),
      do: s,
      else: receive_event(s, predicate, Bounds.now() + timeout * 1_000)
  end

  # Use this entry when the event cannot predate the caller's resume. Searching
  # the full history first can consume the whole production placement window.
  def receive_event(s, predicate, at) do
    receive do
      event ->
        current = observe(s, event)

        if predicate.(event),
          do: current,
          else: receive_event(current, predicate, at)
    after
      Bounds.remaining(at) -> raise "placement event missing"
    end
  end

  # Advance to a production deadline while continuing to consume trace/end
  # events. The absolute clock, rather than a sleep interval, decides arrival.
  def until(s, at) do
    if Bounds.now() >= at do
      s
    else
      receive do
        event -> until(observe(s, event), at)
      after
        Bounds.remaining(at) -> until(s, at)
      end
    end
  end

  def registry(s) do
    Enum.find_value(s.events, fn
      {:received, pid, {:"ETS-TRANSFER", table, _, {_, :registry}}}
      when pid == s.coordinator ->
        table

      _ ->
        nil
    end)
  end

  def observe(s, {:trace_ts, parent, :spawn, pid, {module, function, args}, stamp} = event) do
    ref = Process.monitor(pid)

    role =
      case module do
        RequestSeal.JOSE.JWE.Guard -> :guard
        RequestSeal.JOSE.JWE.Coordinator -> :coordinator
        RequestSeal.JOSE.JWE.Preflight -> :preflight
        RequestSeal.JOSE.JWE.Worker -> :worker
        RequestSeal.JOSE.JWE.Resolver -> :resolver
        RequestSeal.JOSE.JWE.Unwrap -> :custody
        _ -> :other
      end

    # Timed runs omit caller input sends. Coordinator control sends remain
    # observable before the blocked resolvers are released into the barrier.
    if role == :coordinator and not s.trace_input do
      try do
        :erlang.trace(pid, true, [:send])
      catch
        :error, :badarg -> :ok
      end
    end

    s = %{
      s
      | pids: Map.put(s.pids, pid, role),
        refs: Map.put(s.refs, ref, false),
        events: [{:spawn, parent, pid, module, function, args, stamp} | s.events],
        remaining: s.remaining + 1,
        resolver_spawns: s.resolver_spawns + if(role == :resolver, do: 1, else: 0)
    }

    s = if role in [:guard, :coordinator, :preflight], do: Map.put(s, role, pid), else: s
    # The isolated peer has no unrelated workload. A VM count avoids making the
    # observer's own setup quadratic; the traced pid map proves the role and
    # lifetime inventories independently, and each pid still has an end monitor.
    alive = max(0, :erlang.system_info(:process_count) - s.baseline_processes)

    %{
      s
      | peak: max(s.peak, alive),
        peak_tables:
          max(
            s.peak_tables,
            :erlang.system_info(:ets_count) - s.baseline_tables
          ),
        messages: [event | s.messages]
    }
  end

  def observe(s, {:trace_ts, pid, :receive, message, _} = event) do
    messages =
      if pid in [s.guard, s.coordinator, s.caller], do: [event | s.messages], else: s.messages

    %{s | messages: messages, events: [{:received, pid, message} | s.events]}
  end

  def observe(s, {:trace_ts, _, :send, _, _, _} = event),
    do: %{s | messages: [event | s.messages], events: [event | s.events]}

  def observe(s, {:resolver_entered, pid}),
    do: %{s | resolvers: [pid | s.resolvers], resolver_count: s.resolver_count + 1}

  def observe(s, {:custody_entered, pid}),
    do: %{s | custody: [pid | s.custody], custody_count: s.custody_count + 1}

  def observe(s, {:DOWN, ref, :process, pid, reason}) do
    if :maps.get(ref, s.refs, true) == false,
      do: %{
        s
        | refs: Map.put(s.refs, ref, true),
          remaining: s.remaining - 1,
          guard_ended: s.guard_ended or pid == s.guard,
          events: [{:end, pid, Bounds.now(), reason} | s.events]
      },
      else: s
  end

  def observe(s, {:returned, _, result}), do: %{s | return: result}
  def observe(s, event), do: %{s | events: [event | s.events]}

  defp drain_observations(s) do
    receive do
      event -> drain_observations(observe(s, event))
    after
      0 -> s
    end
  end

  # OTP may yield inside a native byte scan. Match the retained
  # Codec continuation regardless of the current MFA, on the suspended stack.
  # A queued call trace or an OTP frame alone never proves placement.
  def in_codec_unit?(pid, functions) do
    Enum.any?(info(pid, :current_stacktrace) || [], fn
      {Codec, function, _, _} -> function in functions
      _ -> false
    end)
  end

  def info(pid, key) do
    case Process.info(pid, key) do
      {^key, value} -> value
      nil -> nil
    end
  end

  def await(fun, attempts \\ 10_000)
  def await(_, 0), do: raise("placement unavailable")

  def await(fun, attempts) do
    if fun.(),
      do: :ok,
      else:
        (
          Process.sleep(1)
          await(fun, attempts - 1)
        )
  end

  defp flush do
    receive do
      _ -> flush()
    after
      0 -> :ok
    end
  end
end

defmodule RequestSeal.Test.JWEOpenBlockingCustodian do
  @moduledoc false
  @behaviour RequestSeal.Custody
  def unwrap(ref, algorithm, items, sink, context) do
    # A real caller-selected custodian; no fake cryptographic result. The
    # test chooses whether its real Local unwrap starts before cancellation.
    send(context.owner, {:custody_entry, self()})
    observer = :persistent_term.get({__MODULE__, :observer})
    send(observer, {:custody_entered, self()})

    receive do
      :continue -> RequestSeal.Custody.Local.unwrap(ref, algorithm, items, sink, context)
    end
  end

  def sign(_, _, _, _), do: {:error, :unsupported_operation}

  def wrap(ref, algorithm, cek, context),
    do: RequestSeal.Custody.Local.wrap(ref, algorithm, cek, context)

  def public_key(ref), do: RequestSeal.Custody.Local.public_key(ref)
  def identity(ref), do: RequestSeal.Custody.Local.identity(ref)
  def release(ref, context), do: RequestSeal.Custody.Local.release(ref, context)
end
