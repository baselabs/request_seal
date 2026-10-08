defmodule RequestSeal.ReplayPostgresTest do
  use ExUnit.Case, async: false
  @moduletag :postgres
  alias RequestSeal.Replay
  alias RequestSeal.Replay.{Claim, Postgres}
  alias RequestSeal.Custody.Context

  setup do
    {:ok, _} = Application.ensure_all_started(:postgrex)
    url = System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL")
    uri = URI.parse(url)
    [username, password] = String.split(uri.userinfo, ":", parts: 2)

    options = [
      hostname: uri.host,
      port: uri.port,
      username: username,
      password: password,
      database: String.trim_leading(uri.path, "/"),
      pool_size: 4
    ]

    {:ok, a} = Postgrex.start_link(options)
    {:ok, b} = Postgrex.start_link(options)
    {:ok, admin} = Postgrex.start_link(Keyword.put(options, :pool_size, 1))
    table = "replay_" <> Integer.to_string(System.unique_integer([:positive]))
    assert {:ok, _} = Postgrex.query(admin, Postgres.ddl(table), [])

    on_exit(fn ->
      {:ok, cleanup} = Postgrex.start_link(options)
      Postgrex.query!(cleanup, "DROP TABLE IF EXISTS #{table}", [])
      GenServer.stop(cleanup)
    end)

    %{
      a: a,
      b: b,
      admin: admin,
      table: table,
      options: options,
      store: Postgres.store(a, table: table)
    }
  end

  test "64 tasks across independent pools and a peer node produce one winner", ctx do
    {:ok, peer, _} = :peer.start_link(%{connection: :standard_io, args: [~c"+S", ~c"2"]})

    try do
      :ok = :peer.call(peer, :code, :add_paths, [:code.get_path()])
      assert {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:postgrex])

      {:ok, _bindings} =
        :peer.call(peer, Code, :eval_string, [
          "{:ok, pool} = Postgrex.start_link(options); Process.unlink(pool); :ok",
          [options: Keyword.put(ctx.options, :name, :replay_pg_peer)]
        ])

      assert {:ok, %{rows: [[1]]}} =
               :peer.call(peer, Postgrex, :query, [:replay_pg_peer, "SELECT 1", []])

      stores = [ctx.store, Postgres.store(ctx.b, table: ctx.table)]
      claim = claim("shared", "nonce", 100)
      gate = :atomics.new(1, [])

      tasks =
        for i <- 1..64 do
          Task.async(fn ->
            await_release(gate)
            Replay.claim(Enum.at(stores, rem(i, 2)), claim, timeout: 5000)
          end)
        end

      peer_task =
        Task.async(fn ->
          await_release(gate)

          :peer.call(peer, Replay, :claim, [
            Postgres.store(:replay_pg_peer, table: ctx.table),
            claim,
            [timeout: 5000]
          ])
        end)

      :atomics.put(gate, 1, 1)
      results = Enum.map(tasks ++ [peer_task], &Task.await(&1, 10_000))
      assert Enum.count(results, &(&1 == :claimed)) == 1
      assert Enum.count(results, &(&1 == :already_claimed)) == 64
      assert [[1]] = Postgrex.query!(ctx.admin, "SELECT count(*) FROM #{ctx.table}", []).rows
    after
      :peer.stop(peer)
    end
  end

  test "namespace separation duplicate retention and explicit sweep use real rows", ctx do
    assert :claimed = Replay.claim(ctx.store, claim("a", "nonce", 100), timeout: 2000)
    assert :claimed = Replay.claim(ctx.store, claim("b", "nonce", 100), timeout: 2000)
    assert :already_claimed = Replay.claim(ctx.store, claim("a", "nonce", 200), timeout: 2000)
    assert {:ok, 0} = Postgres.sweep(ctx.store.ref, 99, context())
    assert {:ok, 2} = Postgres.sweep(ctx.store.ref, 100, context())
    assert :claimed = Replay.claim(ctx.store, claim("a", "nonce", 101), timeout: 2000)
    assert [[101]] = Postgrex.query!(ctx.admin, "SELECT retain_until FROM #{ctx.table}", []).rows
    rendered = inspect(ctx.store)
    refute rendered =~ ctx.table

    for name <- ["", "x; DROP TABLE x", "public.x", String.duplicate("x", 64)] do
      assert {:error, %{reason: :invalid_store}} = Postgres.store(ctx.a, table: name)
      assert {:error, %{reason: :invalid_store}} = Postgres.ddl(name)
    end
  end

  test "primary key lock blocks until deadline without authenticated success", ctx do
    holder =
      Task.async(fn ->
        Postgrex.transaction(ctx.b, fn conn ->
          Postgrex.query!(conn, "INSERT INTO #{ctx.table} VALUES ($1,$2,$3)", ["a", "nonce", 100])
          send(ctx.test_pid, :locked)

          receive do
            :release -> :ok
          end
        end)
      end)

    assert_receive :locked, 1000

    try do
      assert {:error, %{reason: :store_timeout, retryable: false}} =
               Replay.claim(ctx.store, claim("a", "nonce", 100), timeout: 80)
    after
      send(holder.pid, :release)
      Task.await(holder)
    end

    assert :already_claimed = Replay.claim(ctx.store, claim("a", "nonce", 100), timeout: 2000)
    refute_receive {_, :claimed}, 100
  end

  test "terminated backend mid-call table outage and stopped connection fail closed", ctx do
    {:ok, dedicated} = Postgrex.start_link(Keyword.put(ctx.options, :pool_size, 1))
    [[backend]] = Postgrex.query!(dedicated, "SELECT pg_backend_pid()", []).rows

    holder =
      Task.async(fn ->
        Postgrex.transaction(ctx.b, fn conn ->
          Postgrex.query!(conn, "INSERT INTO #{ctx.table} VALUES ($1,$2,$3)", ["a", "nonce", 100])
          send(ctx.test_pid, :locked)

          receive do
            :release -> :ok
          end
        end)
      end)

    assert_receive :locked, 1000

    task =
      Task.async(fn ->
        Replay.claim(Postgres.store(dedicated, table: ctx.table), claim("a", "nonce", 100),
          timeout: 3000
        )
      end)

    try do
      wait_for_lock(ctx.admin, backend, System.monotonic_time(:millisecond) + 2000)

      assert [[true]] =
               Postgrex.query!(ctx.admin, "SELECT pg_terminate_backend($1)", [backend]).rows

      assert {:error, %{reason: :store_failed, retryable: false}} = Task.await(task)
    after
      send(holder.pid, :release)
      Task.await(holder)
      GenServer.stop(dedicated)
    end

    Postgrex.query!(ctx.admin, "DROP TABLE #{ctx.table}", [])

    assert {:error, %{reason: :store_failed}} =
             Replay.claim(ctx.store, claim("a", "nonce", 100), timeout: 2000)

    GenServer.stop(ctx.a)

    assert {:error, %{reason: :store_unavailable}} =
             Replay.claim(ctx.store, claim("a", "nonce", 100), timeout: 2000)
  end

  test "database rows survive replacement of caller pools", ctx do
    assert :claimed = Replay.claim(ctx.store, claim("a", "nonce", 100), timeout: 2000)
    GenServer.stop(ctx.a)
    {:ok, replacement} = Postgrex.start_link(ctx.options)

    try do
      assert :already_claimed =
               Replay.claim(
                 Postgres.store(replacement, table: ctx.table),
                 claim("a", "nonce", 100),
                 timeout: 2000
               )

      assert [[100]] =
               Postgrex.query!(ctx.admin, "SELECT retain_until FROM #{ctx.table}", []).rows
    after
      GenServer.stop(replacement)
    end
  end

  @tag :postgres_restart
  @tag timeout: 180_000
  test "database server restart preserves commitments and accepts new claims", ctx do
    original = claim("restart", "nonce", System.os_time(:second) + 300)
    assert :claimed = Replay.claim(ctx.store, original, timeout: 2000)

    cmd = System.fetch_env!("REQUESTSEAL_REPLAY_PG_RESTART_CMD")
    {_output, exit_code} = System.cmd("sh", ["-c", cmd])
    assert exit_code == 0

    stores = [ctx.store, Postgres.store(ctx.b, table: ctx.table)]
    wait_for_restart(ctx.options, stores, original, System.monotonic_time(:millisecond) + 120_000)

    assert :already_claimed = Replay.claim(ctx.store, original, timeout: 2000)

    replay = %{
      namespace: original.namespace,
      commitment: fn identifier -> {:ok, identifier} end,
      store: ctx.store,
      timeout: 2000
    }

    assert {:error, %RequestSeal.Error{reason: :replayed, layer: :replay, retryable: false}} =
             Replay.commit(replay, original.key, original.retain_until)

    assert :claimed = Replay.claim(ctx.store, %{original | key: "new-nonce"}, timeout: 2000)
  end

  setup do: %{test_pid: self()}
  defp claim(ns, key, until), do: struct(Claim, namespace: ns, key: key, retain_until: until)
  defp context, do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 2000}

  defp await_release(gate) do
    if :atomics.get(gate, 1) == 0 do
      Process.sleep(1)
      await_release(gate)
    end
  end

  defp wait_for_lock(conn, backend, deadline) do
    [[event]] =
      Postgrex.query!(conn, "SELECT wait_event FROM pg_stat_activity WHERE pid=$1", [backend]).rows

    if event != "transactionid" do
      assert System.monotonic_time(:millisecond) < deadline
      Process.sleep(5)
      wait_for_lock(conn, backend, deadline)
    end
  end

  defp wait_for_restart(options, stores, original, deadline) do
    poll_started = System.monotonic_time(:millisecond)
    assert poll_started < deadline, "Postgres did not recover within 120 seconds"

    results =
      Enum.map(stores, fn store ->
        remaining = deadline - System.monotonic_time(:millisecond)
        assert remaining > 0, "Postgres did not recover within 120 seconds"
        result = Replay.claim(store, original, timeout: min(200, remaining))

        case result do
          :already_claimed ->
            :ok

          {:error, %Replay.Error{reason: reason, retryable: false}} ->
            assert reason in [:store_unavailable, :store_timeout, :store_failed]

          other ->
            flunk("existing pools returned an unsafe restart result: #{inspect(other)}")
        end

        result
      end)

    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0, "Postgres did not recover within 120 seconds"
    probe = Task.async(fn -> fresh_connection?(options) end)
    connected = Task.yield(probe, min(5_000, remaining)) || Task.shutdown(probe, :brutal_kill)

    unless connected == {:ok, true} and Enum.all?(results, &(&1 == :already_claimed)) do
      now = System.monotonic_time(:millisecond)
      assert now < deadline, "Postgres did not recover within 120 seconds"
      Process.sleep(min(max(poll_started + 1000 - now, 0), deadline - now))
      wait_for_restart(options, stores, original, deadline)
    end
  end

  defp fresh_connection?(options) do
    {:ok, conn} =
      Postgrex.start_link(Keyword.merge(options, pool_size: 1, connect_timeout: 2_000))

    try do
      match?({:ok, %{rows: [[1]]}}, Postgrex.query(conn, "SELECT 1", [], timeout: 2_000))
    after
      GenServer.stop(conn, :normal, 100)
    end
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end
end
