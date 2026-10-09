if Code.ensure_loaded?(AshOnetime.Transaction) do
  defmodule RequestSeal.ReplayAshOnetimeTest do
    use ExUnit.Case, async: false
    @moduletag :postgres
    alias RequestSeal.{OwnedDatabase, OwnedRepo, Replay}
    alias RequestSeal.Replay.{AshOnetime, Claim, Error}
    alias RequestSeal.Custody.Context

    setup_all do
      prefix = OwnedDatabase.start()
      on_exit(fn -> OwnedDatabase.drop(prefix) end)
      %{prefix: prefix}
    end

    defp claim do
      %Claim{
        namespace: :binary.copy(<<255, 0>>, 128),
        key: :crypto.strong_rand_bytes(256),
        retain_until: System.system_time(:second) + 120
      }
    end

    test "claim, duplicate, binary identity, retention, partition isolation and external cleanup",
         %{prefix: prefix} do
      c = claim()
      store = AshOnetime.store(OwnedRepo, partition: "receiver", prefix: prefix)
      assert :claimed = Replay.claim(store, c, timeout: 5_000)
      assert :already_claimed = Replay.claim(store, c, timeout: 5_000)

      assert :claimed =
               Replay.claim(AshOnetime.store(OwnedRepo, partition: "other", prefix: prefix), c,
                 timeout: 5_000
               )

      assert %{rows: [[retention]]} =
               OwnedRepo.query!(
                 "SELECT retain_until FROM #{prefix}.ash_onetime_nonce_claims WHERE logical_partition = 'receiver'"
               )

      assert DateTime.to_unix(retention) >= c.retain_until
      context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 1_000}
      assert {:error, :externally_managed} = AshOnetime.sweep(store.ref, c.retain_until, context)
      assert {:error, %Error{reason: :invalid_store}} = AshOnetime.store(OwnedRepo, partition: "")
    end

    test "64 real concurrent claimers have exactly one winner", %{prefix: prefix} do
      store = AshOnetime.store(OwnedRepo, partition: "storm", prefix: prefix)
      c = claim()

      results =
        1..64
        |> Task.async_stream(fn _ -> Replay.claim(store, c, timeout: 10_000) end,
          max_concurrency: 64,
          timeout: 15_000
        )
        |> Enum.map(fn {:ok, r} -> r end)

      assert Enum.count(results, &(&1 == :claimed)) == 1
      assert Enum.count(results, &(&1 == :already_claimed)) == 63
      IO.puts("STORM: 64 claimers, 1 claimed, 63 already_claimed")
    end

    test "an unavailable real repo fails closed", %{prefix: prefix} do
      pid = Process.whereis(OwnedRepo)
      assert is_pid(pid)

      stopped =
        start_supervised!(
          {RequestSeal.StoppedOwnedRepo,
           url: System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"), log: false}
        )

      assert Process.alive?(stopped)
      stop_supervised!(RequestSeal.StoppedOwnedRepo)
      refute Process.alive?(stopped)
      # The real repo's stopped pool is an unavailable database boundary.
      store = AshOnetime.store(RequestSeal.StoppedOwnedRepo, partition: "outage", prefix: prefix)

      assert {:error, %Error{reason: :store_unavailable}} =
               Replay.claim(store, claim(), timeout: 1_000)
    end

    test "expired and lock-blocked deadlines fail closed", %{prefix: prefix} do
      store = AshOnetime.store(OwnedRepo, partition: "deadline", prefix: prefix)
      c = claim()
      expired = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) - 1}
      assert {:error, :timeout} = AshOnetime.claim(store.ref, c, expired)
      owner = self()

      lock =
        Task.async(fn ->
          OwnedRepo.transaction(fn ->
            OwnedRepo.query!(
              "LOCK TABLE #{prefix}.ash_onetime_nonce_claims IN ACCESS EXCLUSIVE MODE"
            )

            send(owner, :locked)

            receive do
              :unlock -> :ok
            end
          end)
        end)

      assert_receive :locked, 5_000
      assert {:error, %Error{reason: :store_timeout}} = Replay.claim(store, c, timeout: 50)
      send(lock.pid, :unlock)
      Task.await(lock)
      assert :claimed = Replay.claim(store, c, timeout: 5_000)
    end
  end

  defmodule RequestSeal.StoppedOwnedRepo do
    @moduledoc false
    use Ecto.Repo, otp_app: :request_seal, adapter: Ecto.Adapters.Postgres
  end
end
