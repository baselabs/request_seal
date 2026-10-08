defmodule RequestSeal.ReplayStormSupport do
  import ExUnit.Assertions
  alias RequestSeal.Replay
  alias RequestSeal.Replay.Claim

  def storm(store, namespace, nonce, distinct?) do
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
           Replay.claim(store, %Claim{namespace: namespace, key: key, retain_until: 101},
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
    {:ok, pid} = ETS.start_link(max_entries: 65)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    store = ETS.store(pid)
    table = :sys.get_state(pid).table
    baseline = :ets.info(table, :memory)

    check all(
            nonce <- binary(min_length: 1, max_length: 32),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      same = Storm.storm(store, "shared", nonce, false)
      distinct = Storm.storm(store, "distinct", nonce, true)
      assert :ets.info(table, :size) == 66
      assert :ets.lookup_element(table, :count, 2) == 65

      for {namespace, keys} <- [{"shared", same}, {"distinct", distinct}], key <- keys do
        assert [{{:claim, ^namespace, ^key}, 101}] = :ets.lookup(table, {:claim, namespace, key})

        assert :already_claimed =
                 Replay.claim(
                   store,
                   %Claim{namespace: namespace, key: key, retain_until: 102},
                   timeout: 10_000
                 )
      end

      assert {:ok, 0} = ETS.sweep(pid, 100)
      assert {:ok, 65} = ETS.sweep(pid, 101)
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

      check all(
              nonce <- binary(min_length: 1, max_length: 32),
              max_runs: @runs,
              max_run_time: :infinity,
              initial_seed: @seed
            ) do
        same = Storm.storm(store, "shared", nonce, false)
        distinct = Storm.storm(store, "distinct", nonce, true)
        rows = Postgrex.query!(pool, "SELECT namespace, key, retain_until FROM #{table}", []).rows

        expected =
          for {ns, keys} <- [{"shared", same}, {"distinct", distinct}],
              key <- keys,
              do: [ns, key, 101]

        assert Enum.sort(rows) == Enum.sort(expected)
        context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 10_000}
        assert {:ok, 0} = Postgres.sweep(store.ref, 100, context)
        assert {:ok, 65} = Postgres.sweep(store.ref, 101, context)
        assert [[0]] = Postgrex.query!(pool, "SELECT count(*) FROM #{table}", []).rows
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
end
