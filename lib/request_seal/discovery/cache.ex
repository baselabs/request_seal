defmodule RequestSeal.Discovery.Cache do
  @moduledoc """
  Optional caller-started bounded discovery cache; no timers or background refresh.

  Source identity includes all configuration and trust roots. A full cache
  returns `:cache_overloaded`; it never silently evicts revocation tombstones.

  Fetches are single-flight per source, and the cache never serves stale keys.
  A failed fetch retains the last observed snapshot without extending its
  freshness. If that snapshot is stale, `resolve/4` calls within `negative_ttl`
  return `:source_unavailable` without another connection; `refresh/2` still
  fetches. CIMD failures are never cached, as required by CIMD-02 Section 5.2.
  No-store/no-cache snapshots serve only current waiters and are never retained.

  Thumbprints denied with `remove/3` stay denied across refresh and
  invalidation. Removing the source's denial requires a caller-created new
  cache/configuration. Last-waiter cancellation kills the socket-owning fetcher;
  cache termination also cancels all fetches.
  """
  use GenServer
  alias RequestSeal.{Discovery, Crypto, SignatureFields}
  alias RequestSeal.Discovery.{Source, Error, Support, KeySet}
  import Support, only: [ensure: 2]

  @doc """
  Start the explicitly caller-owned cache, linked to the caller.

  The cache starts no timer and fetches nothing until a call asks for a source.
  Use `{RequestSeal.Discovery.Cache, opts}` as a child specification.

  ## Parameters

    * `opts` - keyword list without unknown or duplicate keys; see Options.

  ## Options

    * `:name` - a `GenServer` name to register. Default: none.
    * `:max_sources` - distinct sources the cache tracks, 1 through 4,096;
      default 64. Calls for a further source return `:cache_overloaded`.
    * `:max_in_flight` - concurrent source fetches, 1 through 256; default 8.
      Pending waiters across all fetches are bounded to 32 per slot.
    * `:clock` - arity-zero function returning Unix seconds from 0 through
      253,402,300,799, called once at start to validate it. Default: system time.

  ## Returns

    * `{:ok, pid}` - the started cache.
    * `{:error, %RequestSeal.Discovery.Error{}}` - reason `:invalid_options`.
      Meanings: `RequestSeal.Discovery.Error`.
    * Any other `GenServer.start_link/3` error, such as `{:error, {:already_started, pid}}`.

  ## Examples

      iex> {:ok, cache} = RequestSeal.Discovery.Cache.start_link(max_sources: 16, max_in_flight: 4)
      iex> is_pid(cache)
      true
      iex> GenServer.stop(cache)
      :ok
      iex> RequestSeal.Discovery.Cache.start_link(max_sources: 0)
      {:error, %RequestSeal.Discovery.Error{reason: :invalid_options, retryable: false}}
  """
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

  @doc """
  Resolve a source-selected key ID, fetching the source on a miss or expiry under caller limits.

  A fresh snapshot answers directly; unknown keys in a fresh set do not trigger a
  refetch. Otherwise the call joins or starts the source's single fetch and
  looks the key up in the result. In thumbprint mode, source revocations and
  tombstones reject before fetching. In directory ID mode, they filter computed
  thumbprints after discovery; a matching directory ID cannot override or become
  a revocation identity.

  ## Parameters

    * `cache` - a running cache: pid or registered name.
    * `source` - a `RequestSeal.Discovery.Source`.
    * `keyid` - an ID under the source's `key_id` mode (see
      `RequestSeal.Discovery.KeySet.lookup/3`).
    * `opts` - keyword list without unknown or duplicate keys; see Options.

  ## Options

    * `:algorithms` - 1 to 64 algorithm identifiers accepted by a policy; the
      first one compatible with the key is selected. Default:
      `RequestSeal.Crypto.algorithms/0`.
    * `:timeout` - milliseconds, 1 through 300,000, capped by the source's
      `:timeout`. Default: the source's `:timeout`.
    * `:clock` - arity-zero function returning Unix seconds from 0 through
      253,402,300,799, used for this call's freshness checks and any fetch it
      starts. Default: the cache's clock.

  ## Returns

    * `{:ok, %RequestSeal.Discovery.Resolution{}}` - the key with its selected
      algorithm and provenance.
    * `{:error, %RequestSeal.Discovery.Error{}}` - reasons this function can return:
      `:invalid_source`, `:invalid_options`, `:unknown_key` (malformed ID, or no
      fresh, compatible key with that ID), `:revoked_key`, `:source_unavailable`
      (negative freshness, invalidation, a failed fetcher, or, from 0.5.0, a
      cache that is not running; 0.4.1 returns `:invalid_response` for that case), `:cache_overloaded`, `:deadline_exceeded`, and any error from
      `RequestSeal.Discovery.fetch/2`. Meanings:
      `RequestSeal.Discovery.Error`.

  ## Examples

      iex> {:ok, cache} = RequestSeal.Discovery.Cache.start_link()
      iex> {:ok, source} =
      ...>   RequestSeal.Discovery.Source.new(%{type: :jwks_uri, location: "https://keys.example/jwks.json"})
      iex> RequestSeal.Discovery.Cache.resolve(cache, source, "not-a-thumbprint")
      {:error, %RequestSeal.Discovery.Error{reason: :unknown_key, retryable: false}}
      iex> thumbprint = Base.url_encode64(:crypto.hash(:sha256, "example key"), padding: false)
      iex> :ok = RequestSeal.Discovery.Cache.remove(cache, source, thumbprint)
      iex> RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])
      {:error, %RequestSeal.Discovery.Error{reason: :revoked_key, retryable: false}}
      iex> GenServer.stop(cache)
      :ok

  Fragment (requires a started `:ssl` application and an HTTPS peer at
  `keys.example`; not executed here):

      {:ok, resolution} =
        RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint,
          algorithms: ["ed25519", "ecdsa-p256-sha256"],
          timeout: 2_000
        )
  """
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

        Support.run(min(timeout, source.timeout), fn _ -> call(cache, request, :infinity) end)
      end,
      :source_unavailable
    )
  end

  @doc """
  Explicitly fetch a source and replace its snapshot on success.

  The fetch runs even during negative freshness; if a fetch for the source is
  already in progress, the call waits for that fetch. On success the old snapshot
  is replaced immediately; a failure keeps it without extending its freshness.

  ## Parameters

    * `cache` - a running cache: pid or registered name.
    * `source` - a `RequestSeal.Discovery.Source`; the fetch uses its `:timeout`
      and the cache's clock.

  ## Returns

    * `{:ok, %RequestSeal.Discovery.KeySet{}}` - the new snapshot, without
      thumbprints denied by `remove/3`.
    * `{:error, %RequestSeal.Discovery.Error{}}` - reasons this function can return:
      `:invalid_source`, `:invalid_options`, `:source_unavailable` (invalidation,
      a failed fetcher, or, from 0.5.0, a cache that is not running; 0.4.1
      returns `:invalid_response` for that case), `:cache_overloaded`,
      `:deadline_exceeded`, and any error from `RequestSeal.Discovery.fetch/2`. Meanings:
      `RequestSeal.Discovery.Error`.

  ## Examples

      iex> {:ok, cache} = RequestSeal.Discovery.Cache.start_link()
      iex> RequestSeal.Discovery.Cache.refresh(cache, %{type: :jwks_uri})
      {:error, %RequestSeal.Discovery.Error{reason: :invalid_source, retryable: false}}
      iex> GenServer.stop(cache)
      :ok

  Fragment (requires a started `:ssl` application and an HTTPS peer at
  `keys.example`; not executed here):

      {:ok, %RequestSeal.Discovery.KeySet{} = set} =
        RequestSeal.Discovery.Cache.refresh(cache, source)
  """
  @spec refresh(GenServer.server(), Source.t()) :: {:ok, KeySet.t()} | {:error, Error.t()}
  def refresh(cache, source) do
    Support.safe(
      fn ->
        Source.validate!(source)

        Support.run(source.timeout, fn _ -> call(cache, {:refresh, source}, :infinity) end)
      end,
      :source_unavailable
    )
  end

  @doc """
  Deny a thumbprint persistently for this cache and source.

  The thumbprint is dropped from any held snapshot and from fetches completing later.

  ## Parameters

    * `cache` - a running cache: pid or registered name.
    * `source` - a `RequestSeal.Discovery.Source`.
    * `thumbprint` - an RFC 7638 SHA-256 thumbprint (43 base64url characters).

  ## Returns

    * `:ok` - the thumbprint is denied.
    * `{:error, %RequestSeal.Discovery.Error{}}` - reasons this function can return:
      `:invalid_source`, `:invalid_options`, `:unknown_key` (not a thumbprint),
      `:limit` (more than 256 denials for the source), `:cache_overloaded`,
      `:source_unavailable` (including a cache that is not running). Meanings:
      `RequestSeal.Discovery.Error`.

  ## Examples

      iex> {:ok, cache} = RequestSeal.Discovery.Cache.start_link()
      iex> {:ok, source} =
      ...>   RequestSeal.Discovery.Source.new(%{type: :jwks_uri, location: "https://keys.example/jwks.json"})
      iex> thumbprint = Base.url_encode64(:crypto.hash(:sha256, "retired key"), padding: false)
      iex> RequestSeal.Discovery.Cache.remove(cache, source, thumbprint)
      :ok
      iex> RequestSeal.Discovery.Cache.remove(cache, source, "build-signer-1")
      {:error, %RequestSeal.Discovery.Error{reason: :unknown_key, retryable: false}}
      iex> GenServer.stop(cache)
      :ok
  """
  @spec remove(GenServer.server(), Source.t(), binary()) :: :ok | {:error, Error.t()}
  def remove(cache, source, thumbprint), do: administrative(cache, source, {:remove, thumbprint})

  @doc """
  Discard a source's snapshot, negative freshness and pending fetch, preserving explicit removals.

  Callers waiting on the canceled fetch receive `:source_unavailable`. The next
  `resolve/4` for the source fetches again.

  ## Parameters

    * `cache` - a running cache: pid or registered name.
    * `source` - a `RequestSeal.Discovery.Source`.

  ## Returns

    * `:ok` - the source state is discarded.
    * `{:error, %RequestSeal.Discovery.Error{}}` - reasons this function can return:
      `:invalid_source`, `:invalid_options`, `:cache_overloaded`,
      `:source_unavailable` (including a cache that is not running). Meanings:
      `RequestSeal.Discovery.Error`.

  ## Examples

      iex> {:ok, cache} = RequestSeal.Discovery.Cache.start_link()
      iex> {:ok, source} =
      ...>   RequestSeal.Discovery.Source.new(%{type: :jwks_uri, location: "https://keys.example/jwks.json"})
      iex> RequestSeal.Discovery.Cache.invalidate(cache, source)
      :ok
      iex> GenServer.stop(cache)
      :ok
      iex> RequestSeal.Discovery.Cache.invalidate(cache, source)
      {:error, %RequestSeal.Discovery.Error{reason: :source_unavailable, retryable: true}}
  """
  @spec invalidate(GenServer.server(), Source.t()) :: :ok | {:error, Error.t()}
  def invalidate(cache, source), do: administrative(cache, source, :invalidate)

  defp administrative(cache, source, action) do
    Support.safe(
      fn ->
        Source.validate!(source)
        if is_tuple(action), do: ensure(Source.thumbprint?(elem(action, 1)), :unknown_key)
        call(cache, {:admin, source, action}, 5000)
      end,
      :source_unavailable
    )
  end

  # A cache that is not running (or exits during the call) is unavailable, the
  # same closed, retryable reason for every operation.
  defp call(cache, request, timeout) do
    GenServer.call(cache, request, timeout)
  catch
    :exit, _ -> throw({:discovery_error, :source_unavailable})
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

        # A stored validator makes the revalidation conditional: an unchanged
        # source answers 304 and its key set stays put. A CIMD document is not
        # the key set itself — its 304 says nothing about the nested JWKS it
        # names — so CIMD sources always revalidate unconditionally.
        {etag, lifetime} =
          case Map.get(state.entries, source) do
            {:positive, set} when source.type != :cimd ->
              now = Support.clock(state.clock)

              if set.etag != nil and keys_alive?(set, now),
                do: {set.etag, max(set.expires_at - set.fetched_at, 0)},
                else: {nil, nil}

            _ ->
              {nil, nil}
          end

        {pid, monitor} =
          :erlang.spawn_opt(
            fn ->
              result =
                Discovery.fetch_with_validators(source, etag, lifetime,
                  clock: clock,
                  timeout: timeout
                )

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

  # A 304 keeps the stored keys, so it can only renew a set whose every key
  # is still inside its own expiry; any dead key forces a full fetch.
  defp keys_alive?(set, now),
    do: set.keys != %{} and Enum.all?(set.keys, fn {_, entry} -> now < entry.expires_at end)

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
      case {result, Map.get(state.entries, source)} do
        {{:ok, {:not_modified, fresh}}, {:positive, stored}} ->
          # RFC 9111 Section 4.3.4: the stored representation stays; the 304's
          # own freshness directives and validator replace the stored ones. The
          # set never claims freshness beyond its earliest still-live key.
          keys = reject_removed(stored.keys, Map.get(state.removed, source, MapSet.new()))

          earliest =
            Enum.reduce(keys, fresh.expires_at, fn {_, entry}, bound ->
              min(bound, entry.expires_at)
            end)

          {:ok,
           %{
             stored
             | etag: fresh.etag,
               fetched_at: fresh.fetched_at,
               expires_at: min(fresh.expires_at, earliest),
               keys: keys
           }}

        {{:ok, {:not_modified, _}}, _} ->
          # No stored representation survived (for example an invalidation that
          # raced the fetch); a 304 cannot reconstruct one.
          {:error, Error.new(:source_unavailable)}

        {{:ok, set}, _} ->
          {:ok,
           %{
             set
             | keys: reject_removed(set.keys, Map.get(state.removed, source, MapSet.new()))
           }}

        {other, _} ->
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
