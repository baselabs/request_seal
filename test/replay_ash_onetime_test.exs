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

    test "invalid claim bytes and deterministic arguments are failures", %{prefix: prefix} do
      store = AshOnetime.store(OwnedRepo, partition: "invalid", prefix: prefix)
      context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}

      for invalid <- [
            %{claim() | key: :not_binary},
            %{claim() | namespace: :not_binary},
            %{claim() | key: ""}
          ] do
        assert {:error, :failure} = AshOnetime.claim(store.ref, invalid, context)
      end

      assert {:error, :failure} = AshOnetime.claim({String, "invalid", prefix}, claim(), context)
    end

    test "issuance uses the database transaction clock and retention survives immediate cleanup",
         %{prefix: prefix} do
      store = AshOnetime.store(OwnedRepo, partition: "db-clock", prefix: prefix)

      for horizon <- [
            System.system_time(:second) - 60,
            System.system_time(:second),
            System.system_time(:second) + 120
          ] do
        c = %{claim() | retain_until: horizon}
        assert :claimed = Replay.claim(store, c, timeout: 5_000)

        assert %{rows: [[issued, admitted, retention]]} =
                 OwnedRepo.query!(
                   "SELECT issued_at, admitted_at, retain_until FROM #{prefix}.ash_onetime_nonce_claims WHERE logical_partition = 'db-clock' ORDER BY admitted_at DESC LIMIT 1"
                 )

        assert issued == admitted
        assert DateTime.compare(retention, admitted) == :gt
        assert DateTime.to_unix(retention) >= horizon
        OwnedRepo.query!("SELECT #{prefix}.ash_onetime_cleanup_nonce(100)")
        assert :already_claimed = Replay.claim(store, c, timeout: 5_000)
      end
    end

    test "a timeout after the actual commit leaves a spent nonce", %{prefix: prefix} do
      store = AshOnetime.store(OwnedRepo, partition: "committed-timeout", prefix: prefix)
      c = claim()
      id = {__MODULE__, make_ref()}

      :ok =
        :telemetry.attach(
          id,
          [:request_seal, :owned_repo, :query],
          &__MODULE__.delay_commit_reply/4,
          self()
        )

      on_exit(fn -> :telemetry.detach(id) end)
      attempt = Task.async(fn -> Replay.claim(store, c, timeout: 500) end)
      assert_receive :claim_committed, 5_000
      assert {:error, %Error{reason: :store_timeout}} = Task.await(attempt, 5_000)
      :telemetry.detach(id)

      assert %{rows: [[1]]} =
               OwnedRepo.query!(
                 "SELECT count(*) FROM #{prefix}.ash_onetime_nonce_claims WHERE logical_partition = 'committed-timeout'"
               )

      assert :already_claimed = Replay.claim(store, c, timeout: 5_000)
    end

    def delay_commit_reply(_event, _measurements, metadata, owner) do
      if String.downcase(metadata.query) == "commit" do
        send(owner, :claim_committed)

        receive do
          :release_commit_reply -> :ok
        after
          5_000 -> :ok
        end
      end
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
