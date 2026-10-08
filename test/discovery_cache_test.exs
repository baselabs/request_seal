Code.require_file("support/discovery_peer_helper.exs", __DIR__)

defmodule RequestSeal.DiscoveryCacheTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Discovery, PublicKey}
  alias RequestSeal.Discovery.{Source, Cache}
  alias RequestSeal.DiscoveryPeer, as: Peer

  defp setup_cache(attrs \\ %{}, opts \\ []) do
    {:ok, publisher} =
      Agent.start_link(fn -> %{keys: [Peer.public_jwk()], cache: "max-age=1", status: 200} end)

    p =
      Peer.start(fn socket, request ->
        doc = Agent.get(publisher, & &1)
        type = Map.get(attrs, :type, :directory)
        host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, request) |> Enum.at(1)

        body =
          if type == :cimd,
            do:
              :json.encode(%{
                "client_id" => "https://" <> host <> "/client",
                "jwks" => %{"keys" => doc.keys}
              })
              |> IO.iodata_to_binary(),
            else: Peer.directory(doc.keys)

        media =
          if type == :directory,
            do: "application/http-message-signatures-directory+json",
            else: "application/json"

        Peer.reply(
          socket,
          body,
          [
            {"Content-Type", media},
            {"Cache-Control", doc.cache},
            {"Expires", Map.get(doc, :expires)}
          ]
          |> Enum.reject(fn {_, value} -> value == nil end),
          doc.status
        )
      end)

    on_exit(fn -> Peer.stop(p) end)

    {:ok, source} =
      Source.new(
        Map.merge(
          %{
            type: :directory,
            location:
              "https://localhost:#{p.port}" <>
                if(Map.get(attrs, :type) == :cimd, do: "/client", else: ""),
            cacerts: p.cacerts,
            permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
            require_signed_directory: false
          },
          attrs
        )
      )

    {:ok, cache} = Cache.start_link(opts)
    {:ok, public} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, kid} = PublicKey.thumbprint(public)
    {p, publisher, source, cache, kid}
  end

  test "an explicit wall clock bounds key validity despite a frozen cache clock" do
    now = System.system_time(:second)
    past = now - 3600
    {_, publisher, source, cache, kid} = setup_cache(%{}, clock: fn -> past end)

    Agent.update(
      publisher,
      &%{&1 | cache: "max-age=7200", keys: [Map.put(Peer.public_jwk(), "exp", now - 1)]}
    )

    assert {:ok, _} = Cache.refresh(cache, source)
    assert accepts() == 1
    # The cache's own clock intentionally still considers this key fresh.
    assert {:ok, resolution} = Cache.resolve(cache, source, kid, algorithms: ["ed25519"])
    assert resolution.expires_at == now - 1
    assert accepts() == 0

    assert {:error, %{reason: :unknown_key}} =
             Cache.resolve(cache, source, kid,
               algorithms: ["ed25519"],
               clock: fn -> System.system_time(:second) end
             )

    assert accepts() == 1
  end

  test "cache fetches enforce same-origin redirects and explicit any-HTTPS permission" do
    target =
      Peer.start(fn socket, _ ->
        Peer.reply(socket, Peer.directory(), [
          {"Content-Type", "application/json"},
          {"Cache-Control", "max-age=60"}
        ])
      end)

    on_exit(fn -> Peer.stop(target) end)

    publisher =
      Peer.start(fn socket, request ->
        cond do
          String.starts_with?(request, "GET /same ") ->
            Peer.reply(socket, "", [{"Location", "/keys"}], 302)

          String.starts_with?(request, "GET /cross ") ->
            Peer.reply(socket, "", [{"Location", "https://localhost:#{target.port}/keys"}], 302)

          true ->
            Peer.reply(socket, Peer.directory(), [
              {"Content-Type", "application/json"},
              {"Cache-Control", "max-age=60"}
            ])
        end
      end)

    on_exit(fn -> Peer.stop(publisher) end)

    {:ok, source} =
      Source.new(%{
        type: :jwks_uri,
        location: "https://localhost:#{publisher.port}/same",
        cacerts: publisher.cacerts ++ target.cacerts,
        permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
        max_redirects: 1
      })

    cache = start_supervised!({Cache, []})
    {:ok, key} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, kid} = PublicKey.thumbprint(key)
    assert {:ok, same} = Cache.resolve(cache, source, kid, algorithms: ["ed25519"])
    assert same.location == "https://localhost:#{publisher.port}/keys"
    assert same.origin == "https://localhost:#{publisher.port}"
    assert accepts() == 2
    cross = %{source | location: "https://localhost:#{publisher.port}/cross"}

    assert {:error, %{reason: :redirect_denied}} =
             Cache.resolve(cache, cross, kid, algorithms: ["ed25519"])

    assert accepts() == 1
    allowed = %{cross | redirect_scope: :any_https}
    assert {:ok, other} = Cache.resolve(cache, allowed, kid, algorithms: ["ed25519"])
    assert other.location == "https://localhost:#{target.port}/keys"
    assert other.origin == "https://localhost:#{target.port}"
    assert accepts() == 2
  end

  defp accepts do
    receive do
      {:accepted, _} -> 1 + accepts()
    after
      0 -> 0
    end
  end

  @tag fix2: true
  test "default freshness reuses the configured directory until 300 seconds elapse" do
    now = System.system_time(:second)
    {:ok, clock} = Agent.start_link(fn -> now end)
    {_, publisher, source, cache, kid} = setup_cache(%{}, clock: fn -> Agent.get(clock, & &1) end)
    Agent.update(publisher, &%{&1 | cache: nil})
    resolver = Discovery.resolver({cache, source}, algorithms: ["ed25519"])
    assert {:ok, _} = resolver.(%{keyid: kid})
    assert accepts() == 1
    {:positive, set} = :sys.get_state(cache).entries[source]
    assert set.expires_at == now + 300
    Agent.update(clock, fn _ -> now + 299 end)
    assert {:ok, _} = resolver.(%{keyid: kid})
    assert accepts() == 0
    Agent.update(clock, fn _ -> now + 300 end)
    assert {:ok, _} = resolver.(%{keyid: kid})
    assert accepts() == 1
  end

  @tag fix2: true
  test "Expires keeps the directory cached only until its explicit expiry" do
    now = System.system_time(:second)
    {:ok, clock} = Agent.start_link(fn -> now end)
    {_, publisher, source, cache, kid} = setup_cache(%{}, clock: fn -> Agent.get(clock, & &1) end)
    expires = Calendar.strftime(DateTime.from_unix!(now + 60), "%a, %d %b %Y %H:%M:%S GMT")
    Agent.update(publisher, &Map.merge(&1, %{cache: nil, expires: expires}))
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    {:positive, set} = :sys.get_state(cache).entries[source]
    assert set.expires_at == now + 60
    Agent.update(clock, fn _ -> now + 59 end)
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 0
    Agent.update(clock, fn _ -> now + 60 end)
    Agent.update(publisher, &%{&1 | status: 503})

    assert {:error, %{reason: :unexpected_status, retryable: true}} =
             Cache.resolve(cache, source, kid, [])

    assert accepts() == 1
    assert {:error, %{reason: :source_unavailable}} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 0
  end

  test "freshness refetches, rotation removes old keys and tombstones survive refresh/invalidation" do
    {:ok, clock} = Agent.start_link(fn -> System.system_time(:second) end)
    {_, publisher, source, cache, kid} = setup_cache(%{}, clock: fn -> Agent.get(clock, & &1) end)
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 0
    Agent.update(clock, &(&1 + 1))
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    {:ok, rsa} = PublicKey.import(File.read!("test/fixtures/crypto/rsa_public.pem"), :pem)
    {:ok, jwk} = PublicKey.export(rsa, :jwk)
    {:ok, rotated} = PublicKey.thumbprint(rsa)
    Agent.update(publisher, &%{&1 | keys: [Peer.public_jwk(), jwk]})
    assert {:ok, _} = Cache.refresh(cache, source)
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert {:ok, _} = Cache.resolve(cache, source, rotated, [])
    Agent.update(publisher, &%{&1 | keys: [jwk]})
    assert {:ok, _} = Cache.refresh(cache, source)
    assert {:error, %{reason: :unknown_key}} = Cache.resolve(cache, source, kid, [])
    assert {:ok, _} = Cache.resolve(cache, source, rotated, [])
    assert :ok = Cache.remove(cache, source, rotated)
    assert {:error, %{reason: :revoked_key}} = Cache.resolve(cache, source, rotated, [])
    assert {:ok, removed_set} = Cache.refresh(cache, source)
    refute Map.has_key?(removed_set.keys, rotated)
    assert :ok = Cache.invalidate(cache, source)
    assert {:error, %{reason: :revoked_key}} = Cache.resolve(cache, source, rotated, [])
    resolver = Discovery.resolver({cache, source}, algorithms: ["rsa-pss-sha512"])
    assert :error = resolver.(%{keyid: rotated})
  end

  test "configured revocation denies published keys without accepting a connection" do
    {_, _, source, cache, kid} = setup_cache()
    revoked = %{source | revoked: [kid]}
    assert {:error, %{reason: :revoked_key}} = Cache.resolve(cache, revoked, kid, [])
    assert accepts() == 0
  end

  test "no-store responses never enter the cache and unknown IDs do not trigger refetch floods" do
    {_, publisher, source, cache, kid} = setup_cache()
    Agent.update(publisher, &%{&1 | cache: "no-store, max-age=300"})
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 2
    refute Map.has_key?(:sys.get_state(cache).entries, source)
    Agent.update(publisher, &%{&1 | cache: "max-age=300"})
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    unknown = Base.url_encode64(:crypto.hash(:sha256, "unpublished thumbprint"), padding: false)
    assert {:error, %{reason: :unknown_key}} = Cache.resolve(cache, source, unknown, [])
    assert accepts() == 0
  end

  test "no-store completion across a clock tick retains key expiry without creating freshness" do
    for type <- [:directory, :jwks_uri, :cimd], expired <- [false, true] do
      now = System.system_time(:second)
      {:ok, ticks} = Agent.start_link(fn -> 0 end)

      clock = fn ->
        Agent.get_and_update(ticks, fn tick -> {now + if(tick >= 3, do: 2, else: 0), tick + 1} end)
      end

      {_, publisher, source, cache, kid} = setup_cache(%{type: type}, clock: clock)
      key = if expired, do: Map.put(Peer.public_jwk(), "exp", now + 1), else: Peer.public_jwk()
      Agent.update(publisher, &%{&1 | cache: "no-store, max-age=60", keys: [key]})

      if expired do
        assert {:error, %{reason: :unknown_key}} = Cache.resolve(cache, source, kid, [])
      else
        assert {:ok, resolution} = Cache.resolve(cache, source, kid, [])
        assert resolution.expires_at > now + 2
      end

      refute Map.has_key?(:sys.get_state(cache).entries, source)
    end
  end

  test "expiry plus outage never serves stale and negative entries stop new accepts" do
    {:ok, clock} = Agent.start_link(fn -> System.system_time(:second) end)
    {_, publisher, source, cache, kid} = setup_cache(%{}, clock: fn -> Agent.get(clock, & &1) end)
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    Agent.update(clock, &(&1 + 1))
    Agent.update(publisher, &%{&1 | status: 500})
    assert {:error, %{reason: :unexpected_status}} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    assert {:error, %{reason: :source_unavailable}} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 0
    Agent.update(publisher, &%{&1 | status: 200})
    assert {:ok, _} = Cache.refresh(cache, source)
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    Agent.update(clock, &(&1 + 1))
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
  end

  test "a failed refresh retains the observed directory without extending its freshness" do
    now = System.system_time(:second)
    {:ok, clock} = Agent.start_link(fn -> now end)
    {_, publisher, source, cache, kid} = setup_cache(%{}, clock: fn -> Agent.get(clock, & &1) end)
    Agent.update(publisher, &%{&1 | cache: "max-age=60"})
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    {:positive, original} = :sys.get_state(cache).entries[source]
    Agent.update(publisher, &%{&1 | status: 500})
    assert {:error, %{reason: :unexpected_status}} = Cache.refresh(cache, source)
    assert {:positive, ^original} = :sys.get_state(cache).entries[source]
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    Agent.update(clock, &(&1 + 61))
    assert {:error, %{reason: :unexpected_status}} = Cache.resolve(cache, source, kid, [])
    assert {:positive, ^original} = :sys.get_state(cache).entries[source]
    assert {:error, %{reason: :source_unavailable}} = Cache.resolve(cache, source, kid, [])
  end

  test "CIMD errors are not cached, and the next real document can recover immediately" do
    {_, publisher, source, cache, kid} = setup_cache(%{type: :cimd})
    Agent.update(publisher, &%{&1 | status: 500})
    assert {:error, %{reason: :unexpected_status}} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    assert {:error, %{reason: :unexpected_status}} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
    Agent.update(publisher, &%{&1 | status: 200})
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    assert accepts() == 1
  end

  test "concurrent resolves share one fetch, flood cap rejects and dead waiters cancel the fetch" do
    owner = self()

    p =
      Peer.start(fn socket, _ ->
        send(owner, {:blocked, self()})

        receive do
          :release ->
            Peer.reply(socket, Peer.directory(), [
              {"Content-Type", "application/http-message-signatures-directory+json"},
              {"Cache-Control", "max-age=60"}
            ])
        after
          5_000 -> :ok
        end
      end)

    on_exit(fn -> Peer.stop(p) end)

    {:ok, source} =
      Source.new(%{
        type: :directory,
        location: "https://localhost:#{p.port}",
        cacerts: p.cacerts,
        permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
        require_signed_directory: false
      })

    {:ok, cache} = Cache.start_link(max_in_flight: 1)
    {:ok, key} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, kid} = PublicKey.thumbprint(key)
    tasks = for _ <- 1..12, do: Task.async(fn -> Cache.resolve(cache, source, kid, []) end)
    assert_receive {:blocked, connection}, 1_000
    other = %{source | negative_ttl: 29}
    assert {:error, %{reason: :cache_overloaded}} = Cache.resolve(cache, other, kid, [])
    send(connection, :release)
    assert Enum.all?(Task.await_many(tasks), &match?({:ok, _}, &1))
    assert accepts() == 1
    assert :ok = Cache.invalidate(cache, source)
    caller = spawn(fn -> Cache.resolve(cache, source, kid, []) end)
    assert_receive {:blocked, connection}, 1_000
    Process.exit(caller, :kill)
    # The waiter monitor must release the single-flight slot without a timer.
    monitor = Process.monitor(connection)
    send(connection, :release)
    assert_receive {:DOWN, ^monitor, _, _, _}, 1_000
    refresh = Task.async(fn -> Cache.refresh(cache, other) end)
    assert_receive {:blocked, connection}, 1_000
    send(connection, :release)
    assert {:ok, _} = Task.await(refresh)
  end

  test "fetcher crash releases every waiter and closes its real TLS connection" do
    owner = self()

    p =
      Peer.start(fn socket, _ ->
        send(owner, {:connected, self()})
        send(owner, {:socket_closed, :ssl.recv(socket, 0, 5_000)})
      end)

    on_exit(fn -> Peer.stop(p) end)

    {:ok, source} =
      Source.new(%{
        type: :directory,
        location: "https://localhost:#{p.port}",
        cacerts: p.cacerts,
        permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
        require_signed_directory: false
      })

    {:ok, cache} = Cache.start_link()
    {:ok, key} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, kid} = PublicKey.thumbprint(key)
    tasks = for _ <- 1..2, do: Task.async(fn -> Cache.resolve(cache, source, kid, []) end)
    assert_receive {:connected, _}, 1_000
    wait_for_waiters(cache, source, 2, System.monotonic_time(:millisecond) + 1_000)
    flight = :sys.get_state(cache).pending[source]
    Process.exit(flight.pid, :kill)

    assert Enum.all?(
             Task.await_many(tasks),
             &match?({:error, %{reason: :source_unavailable}}, &1)
           )

    assert_receive {:socket_closed, {:error, :closed}}, 1_000
    assert :sys.get_state(cache).pending == %{}
  end

  defp wait_for_waiters(cache, source, count, deadline) do
    pending = :sys.get_state(cache).pending

    if pending[source] != nil and map_size(pending[source].waiters) == count do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline
      Process.sleep(5)
      wait_for_waiters(cache, source, count, deadline)
    end
  end

  test "bounded source enrollment and cache options reject safely" do
    {_, _, source, cache, kid} = setup_cache(%{}, max_sources: 1)
    assert {:ok, _} = Cache.resolve(cache, source, kid, [])
    other = %{source | negative_ttl: 10}
    assert {:error, %{reason: :cache_overloaded}} = Cache.resolve(cache, other, kid, [])
    assert {:error, %{reason: :invalid_options}} = Cache.resolve(cache, source, kid, timeout: 0)
    assert {:error, %{reason: :unknown_key}} = Cache.resolve(cache, source, "https://canary", [])
    assert {:error, %{reason: :invalid_options}} = Cache.start_link(max_sources: 0)
    assert {:error, %{reason: :invalid_options}} = Cache.start_link(max_in_flight: 0)
  end
end
