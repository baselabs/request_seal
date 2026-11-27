defmodule RequestSeal.ReplayStormSupport do
  import ExUnit.Assertions
  alias RequestSeal.Replay
  alias RequestSeal.Replay.Claim

  def assert_stale(store, nonce, swept_through) do
    claim = %Claim{namespace: "shared", key: nonce, retain_until: swept_through}
    assert {:error, %{reason: :store_failed}} = Replay.claim(store, claim, timeout: 10_000)
  end

  def storm(store, namespace, nonce, distinct?, retain_until) do
    parent = self()
    gate = make_ref()

    tasks =
      for i <- 1..64 do
        key = if distinct?, do: nonce <> <<i>>, else: nonce

        Task.async(fn ->
          send(parent, {:ready, gate, self()})

          receive do
            {:go, ^gate} -> :ok
          end

          {key,
           Replay.claim(store, %Claim{namespace: namespace, key: key, retain_until: retain_until},
             timeout: 10_000
           )}
        end)
      end

    for task <- tasks do
      pid = task.pid
      assert_receive {:ready, ^gate, ^pid}, 10_000
    end

    # Every task has reached the rendezvous before any claim is released.
    Enum.each(tasks, &send(&1.pid, {:go, gate}))
    results = Enum.map(tasks, &Task.await(&1, 15_000))
    grouped = Enum.group_by(results, &elem(&1, 0), &elem(&1, 1))
    assert map_size(grouped) == if(distinct?, do: 64, else: 1)

    for {_nonce, outcomes} <- grouped do
      assert Enum.count(outcomes, &(&1 == :claimed)) == 1
      assert Enum.all?(outcomes, &(&1 in [:claimed, :already_claimed]))
    end

    Map.keys(grouped)
  end
end

defmodule RequestSeal.ReplayETSPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties
  alias RequestSeal.Replay.{Claim, ETS}
  alias RequestSeal.Replay
  alias RequestSeal.ReplayStormSupport, as: Storm
  @seed 6401
  @runs 300

  property "64-task same and distinct nonce storms lose no claims and sweep bounds memory" do
    pid = start_supervised!({ETS, max_entries: 65})
    store = ETS.store(pid)
    table = :sys.get_state(pid).table
    baseline = :ets.info(table, :memory)
    expiry = :atomics.new(1, [])
    :ok = :atomics.put(expiry, 1, 100)
    assert {:ok, 0} = ETS.sweep(pid, 100)

    check all(
            nonce <- binary(min_length: 1, max_length: 32),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      retain_until = :atomics.add_get(expiry, 1, 1)
      Storm.assert_stale(store, nonce, retain_until - 1)
      same = Storm.storm(store, "shared", nonce, false, retain_until)
      distinct = Storm.storm(store, "distinct", nonce, true, retain_until)
      assert :ets.info(table, :size) == 66
      assert :ets.lookup_element(table, :count, 2) == 65

      for {namespace, keys} <- [{"shared", same}, {"distinct", distinct}], key <- keys do
        assert [{{:claim, ^namespace, ^key}, ^retain_until}] =
                 :ets.lookup(table, {:claim, namespace, key})

        assert :already_claimed =
                 Replay.claim(
                   store,
                   %Claim{namespace: namespace, key: key, retain_until: retain_until + 1},
                   timeout: 10_000
                 )
      end

      assert {:ok, 0} = ETS.sweep(pid, retain_until - 1)
      assert {:ok, 65} = ETS.sweep(pid, retain_until)
      assert :ets.info(table, :size) == 1
      assert :ets.lookup_element(table, :count, 2) == 0
      assert :ets.info(table, :memory) <= baseline + 1024
    end
  end
end

defmodule RequestSeal.ReplayPostgresPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties
  @moduletag :postgres
  alias RequestSeal.Custody.Context
  alias RequestSeal.Replay.Postgres
  alias RequestSeal.ReplayStormSupport, as: Storm
  @seed 6402
  @runs 300
  @tag timeout: 300_000
  property "64-task Postgres storms have one winner per nonce and bounded storage after sweep" do
    {:ok, _} = Application.ensure_all_started(:postgrex)
    uri = URI.parse(System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"))
    [username, password] = String.split(uri.userinfo, ":", parts: 2)

    options = [
      hostname: uri.host,
      port: uri.port,
      username: username,
      password: password,
      database: String.trim_leading(uri.path, "/"),
      pool_size: 64
    ]

    {:ok, pool} = Postgrex.start_link(options)
    table = "replay_property_" <> Integer.to_string(System.unique_integer([:positive]))

    try do
      Postgrex.query!(pool, Postgres.ddl(table), [])
      store = Postgres.store(pool, table: table)
      expiry = :atomics.new(1, [])
      :ok = :atomics.put(expiry, 1, 100)
      assert {:ok, 0} = Postgres.sweep(store.ref, 100, context())

      check all(
              nonce <- binary(min_length: 1, max_length: 32),
              max_runs: @runs,
              max_run_time: :infinity,
              initial_seed: @seed
            ) do
        retain_until = :atomics.add_get(expiry, 1, 1)
        Storm.assert_stale(store, nonce, retain_until - 1)
        same = Storm.storm(store, "shared", nonce, false, retain_until)
        distinct = Storm.storm(store, "distinct", nonce, true, retain_until)

        rows =
          Postgrex.query!(
            pool,
            "SELECT namespace, key, retain_until FROM #{table} WHERE namespace <> ''::bytea",
            []
          ).rows

        expected =
          for {ns, keys} <- [{"shared", same}, {"distinct", distinct}],
              key <- keys,
              do: [ns, key, retain_until]

        assert Enum.sort(rows) == Enum.sort(expected)
        assert {:ok, 0} = Postgres.sweep(store.ref, retain_until - 1, context())
        assert {:ok, 65} = Postgres.sweep(store.ref, retain_until, context())

        assert %{rows: [[0]]} =
                 Postgrex.query!(
                   pool,
                   "SELECT count(*) FROM #{table} WHERE namespace <> ''::bytea",
                   []
                 )

        # Real reclamation, including dead tuples and indexes; no synthetic allocator.
        Postgrex.query!(pool, "VACUUM #{table}", [])

        [[bytes]] =
          Postgrex.query!(pool, "SELECT pg_total_relation_size($1::text::regclass)", [table]).rows

        assert bytes <= 1_048_576
      end
    after
      try do
        Postgrex.query!(pool, "DROP TABLE IF EXISTS #{table}", [])
      after
        GenServer.stop(pool)
      end
    end
  end

  defp context,
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 10_000}
end
