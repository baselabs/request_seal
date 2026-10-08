defmodule RequestSeal.Discovery.Cache do
  @moduledoc """
  Optional caller-started bounded discovery cache; no timers or background refresh.

  `start_link/1` accepts `:name` (GenServer name), `:max_sources` (64, 1–4,096),
  `:max_in_flight` (8, 1–256) and `:clock` (Unix seconds, default system clock).
  Source identity includes all configuration and trust roots. A full cache
  returns `:cache_overloaded`; it never silently evicts revocation tombstones.
  Pending waiters are bounded to 32 per in-flight capacity slot.

  `resolve/4` accepts `:algorithms` (all HTTP algorithms by default), `:timeout`
  and `:clock`. It fetches on expiry/miss, single-flight per source, returns
  `{:ok, Discovery.Resolution}` or `{:error, Discovery.Error}`, and never serves
  stale keys after failure. Unknown keys in a fresh set do not trigger refetch.
  In thumbprint mode, source revocations and tombstones reject before fetching.
  In directory ID mode, they filter computed thumbprints after discovery; a
  matching directory ID cannot override or become a revocation identity.
  `refresh/2` explicitly fetches even during negative freshness, immediately
  replacing the old snapshot on success. Failures retain the last observed
  snapshot without extending its freshness. If it is stale, calls within
  `negative_ttl` return `:source_unavailable` without another connection.
  CIMD failures are never cached, as required by CIMD-02 Section 5.2.
  No-store/no-cache snapshots serve only current waiters and are never retained.

  `remove/3` persistently denies a thumbprint for that source, including across
  refresh and invalidation. `invalidate/2` discards freshness and cancels pending
  fetches, retaining tombstones. Both return `:ok` or a bounded error. Removing
  the source's denial requires a caller-created new cache/configuration.
  Refresh returns `{:ok, KeySet}` or a bounded error. Last-waiter cancellation
  kills the socket-owning fetcher; cache termination also cancels all fetches.
  """
  use GenServer
  alias RequestSeal.{Discovery, Crypto, SignatureFields}
  alias RequestSeal.Discovery.{Source, Error, Support, KeySet}
  import Support, only: [ensure: 2]

  @doc "Start the explicitly caller-owned cache."
  @spec start_link(keyword()) :: GenServer.on_start() | {:error, Error.t()}
  def start_link(opts \\ []) do
    Support.safe(
      fn ->
        Support.options(opts, [:name, :max_sources, :max_in_flight, :clock])
        sources = Keyword.get(opts, :max_sources, 64)
        flight = Keyword.get(opts, :max_in_flight, 8)

        ensure(
          is_integer(sources) and sources in 1..4096 and is_integer(flight) and flight in 1..256,
          :invalid_options
        )

        clock = Keyword.get(opts, :clock, fn -> System.system_time(:second) end)
        Support.clock(clock)
        name = Keyword.take(opts, [:name])
        GenServer.start_link(__MODULE__, {sources, flight, clock}, name)
      end,
      :invalid_options
    )
  end

  @doc "Resolve a source-selected key ID; misses/expiry fetch under caller limits."
  @spec resolve(GenServer.server(), Source.t(), binary(), keyword()) ::
          {:ok, RequestSeal.Discovery.Resolution.t()} | {:error, Error.t()}
  def resolve(cache, source, keyid, opts \\ []) do
    Support.safe(
      fn ->
        Source.validate!(source)
        Support.options(opts, [:algorithms, :timeout, :clock])
        algorithms = Keyword.get(opts, :algorithms, Crypto.algorithms())

        ensure(
          is_list(algorithms) and length(algorithms) in 1..64 and
            Enum.all?(algorithms, &SignatureFields.algorithm?/1),
          :invalid_options
        )

        ensure(Source.key_id?(source, keyid), :unknown_key)
        ensure(source.key_id == :directory or keyid not in source.revoked, :revoked_key)
        timeout = Keyword.get(opts, :timeout, source.timeout)
        ensure(is_integer(timeout) and timeout in 1..300_000, :invalid_options)
        if Keyword.has_key?(opts, :clock), do: Support.clock(opts[:clock])

        request =
          {:resolve, source, keyid, algorithms, Keyword.get(opts, :clock),
           min(timeout, source.timeout)}

        Support.run(min(timeout, source.timeout), fn _ ->
          GenServer.call(cache, request, :infinity)
        end)
      end,
      :source_unavailable
    )
  end

  @doc """
  Explicitly replace a source snapshot on success. Failures retain the last
  observed snapshot without extending its freshness; stale keys are never served.
  """
  @spec refresh(GenServer.server(), Source.t()) :: {:ok, KeySet.t()} | {:error, Error.t()}
  def refresh(cache, source) do
    Support.safe(
      fn ->
        Source.validate!(source)

        Support.run(source.timeout, fn _ ->
          GenServer.call(cache, {:refresh, source}, :infinity)
        end)
      end,
      :source_unavailable
    )
  end

  @doc "Deny a thumbprint persistently for this cache and source."
  @spec remove(GenServer.server(), Source.t(), binary()) :: :ok | {:error, Error.t()}
  def remove(cache, source, thumbprint), do: administrative(cache, source, {:remove, thumbprint})
  @doc "Discard a snapshot and pending work, preserving explicit removals."
  @spec invalidate(GenServer.server(), Source.t()) :: :ok | {:error, Error.t()}
  def invalidate(cache, source), do: administrative(cache, source, :invalidate)

  defp administrative(cache, source, action) do
    Support.safe(
      fn ->
        Source.validate!(source)
        if is_tuple(action), do: ensure(Source.thumbprint?(elem(action, 1)), :unknown_key)
        GenServer.call(cache, {:admin, source, action})
      end,
      :source_unavailable
    )
  end

  @impl true
  def init({sources, flight, clock}) do
    Process.flag(:trap_exit, true)

    {:ok,
     %{
       max_sources: sources,
       max_in_flight: flight,
       clock: clock,
       entries: %{},
       failures: %{},
       pending: %{},
       removed: %{},
       enrolled: MapSet.new()
     }}
  end

  @impl true
  def handle_call({:resolve, source, keyid, algorithms, clock, timeout}, from, state) do
    result =
      Support.safe(
        fn ->
          clock = clock || state.clock
          now = Support.clock(clock)
          ensure(source.key_id == :directory or not removed?(state, source, keyid), :revoked_key)

          case Map.get(state.entries, source) do
            {:positive, set} when now < set.expires_at ->
              {:reply, lookup(set, keyid, algorithms, now), state}

            _ ->
              case Map.get(state.failures, source) do
                expires when is_integer(expires) and now < expires ->
                  {:reply, {:error, Error.new(:source_unavailable)}, state}

                _ ->
                  pending(
                    source,
                    {:resolve, keyid, algorithms, clock},
                    clock,
                    timeout,
                    from,
                    state
                  )
              end
          end
        end,
        :source_unavailable
      )

    finish_call(result, state)
  end

  def handle_call({:refresh, source}, from, state) do
    result =
      Support.safe(
        fn ->
          pending(source, :refresh, state.clock, source.timeout, from, state)
        end,
        :source_unavailable
      )

    finish_call(result, state)
  end

  def handle_call({:admin, source, action}, _, state) do
    result =
      Support.safe(
        fn ->
          state = enroll(source, state)

          case action do
            {:remove, kid} ->
              removed = Map.update(state.removed, source, MapSet.new([kid]), &MapSet.put(&1, kid))
              ensure(MapSet.size(removed[source]) <= 256, :limit)

              entries =
                case Map.get(state.entries, source) do
                  {:positive, set} ->
                    Map.put(
                      state.entries,
                      source,
                      {:positive, %{set | keys: reject_removed(set.keys, MapSet.new([kid]))}}
                    )

                  _ ->
                    state.entries
                end

              {:reply, :ok, %{state | removed: removed, entries: entries}}

            :invalidate ->
              state = cancel(source, state)

              {:reply, :ok,
               %{
                 state
                 | entries: Map.delete(state.entries, source),
                   failures: Map.delete(state.failures, source)
               }}
          end
        end,
        :source_unavailable
      )

    finish_call(result, state)
  end

  defp finish_call({:error, _} = error, state), do: {:reply, error, state}
  defp finish_call(result, _), do: result

  defp pending(source, request, clock, timeout, from, state) do
    state = enroll(source, state)

    waiters =
      Enum.reduce(state.pending, 0, fn {_, flight}, acc -> acc + map_size(flight.waiters) end)

    ensure(waiters < state.max_in_flight * 32, :cache_overloaded)
    ref = Process.monitor(elem(from, 0))
    waiter = {from, request}

    case Map.get(state.pending, source) do
      nil ->
        if map_size(state.pending) >= state.max_in_flight do
          Process.demonitor(ref, [:flush])
          ensure(false, :cache_overloaded)
        end

        owner = self()
        token = make_ref()

        {pid, monitor} =
          :erlang.spawn_opt(
            fn ->
              result = Discovery.fetch(source, clock: clock, timeout: timeout)
              send(owner, {:fetched, source, token, result})
            end,
            [:link, :monitor]
          )

        flight = %{
          pid: pid,
          monitor: monitor,
          token: token,
          waiters: %{ref => waiter},
          clock: clock
        }

        {:noreply,
         %{
           state
           | pending: Map.put(state.pending, source, flight)
         }}

      flight ->
        flight = %{flight | waiters: Map.put(flight.waiters, ref, waiter)}
        {:noreply, %{state | pending: Map.put(state.pending, source, flight)}}
    end
  end

  defp enroll(source, state) do
    ensure(
      MapSet.member?(state.enrolled, source) or MapSet.size(state.enrolled) < state.max_sources,
      :cache_overloaded
    )

    %{state | enrolled: MapSet.put(state.enrolled, source)}
  end

  defp reject_removed(keys, tombstones),
    do: Map.reject(keys, fn {_, entry} -> MapSet.member?(tombstones, entry.thumbprint) end)

  defp removed?(state, source, kid),
    do: MapSet.member?(Map.get(state.removed, source, MapSet.new()), kid)

  @impl true
  def handle_info({:fetched, source, token, result}, state) do
    case Map.get(state.pending, source) do
      %{token: ^token} = flight -> complete(source, flight, result, state)
      _ -> {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _, _}, state) do
    case Enum.find(state.pending, fn {_, flight} -> flight.monitor == ref end) do
      {source, flight} ->
        complete(source, flight, {:error, Error.new(:source_unavailable)}, state)

      nil ->
        pending =
          Enum.reduce(state.pending, %{}, fn {source, flight}, acc ->
            if Map.has_key?(flight.waiters, ref) do
              flight = %{flight | waiters: Map.delete(flight.waiters, ref)}

              if map_size(flight.waiters) == 0 do
                stop_flight(flight)
                acc
              else
                Map.put(acc, source, flight)
              end
            else
              Map.put(acc, source, flight)
            end
          end)

        {:noreply, %{state | pending: pending}}
    end
  end

  def handle_info({:EXIT, _, _}, state), do: {:noreply, state}

  defp complete(source, flight, result, state) do
    Process.demonitor(flight.monitor, [:flush])
    # Removal is applied at completion too, so in-flight snapshots cannot
    # resurrect a key removed after this fetch started.
    result =
      case result do
        {:ok, set} ->
          {:ok,
           %{
             set
             | keys: reject_removed(set.keys, Map.get(state.removed, source, MapSet.new()))
           }}

        other ->
          other
      end

    Enum.each(flight.waiters, fn {ref, {from, request}} ->
      Process.demonitor(ref, [:flush])

      reply =
        case {result, request} do
          {{:ok, set}, {:resolve, keyid, algorithms, clock}} ->
            if source.key_id == :thumbprint and removed?(state, source, keyid),
              do: {:error, Error.new(:revoked_key)},
              else: fresh_lookup(set, keyid, algorithms, clock)

          {result, _} ->
            result
        end

      GenServer.reply(from, reply)
    end)

    stored =
      Support.safe(
        fn ->
          now = Support.clock(flight.clock)

          case result do
            {:ok, set} ->
              entries =
                if set.expires_at > now,
                  do: Map.put(state.entries, source, {:positive, set}),
                  else: Map.delete(state.entries, source)

              {entries, Map.delete(state.failures, source)}

            _ ->
              failures =
                if source.type != :cimd and source.negative_ttl > 0,
                  do: Map.put(state.failures, source, now + source.negative_ttl),
                  else: Map.delete(state.failures, source)

              {state.entries, failures}
          end
        end,
        :invalid_options
      )

    {entries, failures} =
      case stored do
        {entries, failures} when is_map(entries) and is_map(failures) -> {entries, failures}
        _ -> {state.entries, Map.delete(state.failures, source)}
      end

    {:noreply,
     %{state | entries: entries, failures: failures, pending: Map.delete(state.pending, source)}}
  end

  defp fresh_lookup(set, keyid, algorithms, clock) do
    Support.safe(
      fn ->
        now = Support.clock(clock)
        # This response serves only its current waiters, never a later cache
        # hit. HTTP no-store/max-age=0 does not invalidate a newly fetched key;
        # original key/proof expiry still applies, even across a clock tick.
        transient =
          if set.expires_at == set.fetched_at,
            do: %{set | expires_at: now + 1},
            else: set

        case lookup(transient, keyid, algorithms, now) do
          {:ok, resolution} -> {:ok, %{resolution | expires_at: set.keys[keyid].expires_at}}
          error -> error
        end
      end,
      :invalid_options
    )
  end

  defp lookup(set, keyid, algorithms, now) do
    case KeySet.lookup_at(set, keyid, algorithms, now) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, Error.new(:unknown_key)}
    end
  end

  defp cancel(source, state) do
    case Map.get(state.pending, source) do
      nil ->
        state

      flight ->
        stop_flight(flight)

        Enum.each(flight.waiters, fn {ref, {from, _}} ->
          Process.demonitor(ref, [:flush])
          GenServer.reply(from, {:error, Error.new(:source_unavailable)})
        end)

        %{state | pending: Map.delete(state.pending, source)}
    end
  end

  defp stop_flight(flight) do
    Process.demonitor(flight.monitor, [:flush])
    Process.exit(flight.pid, :kill)
  end

  @impl true
  def terminate(_, state) do
    Enum.each(state.pending, fn {_, flight} -> stop_flight(flight) end)
  end
end
