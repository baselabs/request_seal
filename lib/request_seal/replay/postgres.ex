if Code.ensure_loaded?(Postgrex) do
  defmodule RequestSeal.Replay.Postgres do
    @moduledoc """
    Optional Postgrex atomic replay adapter. The caller owns connections and DDL.

    Prefer `RequestSeal.Replay.AshOnetime` for durable replay with ash_onetime's
    retention guards and externally managed cleanup. This Postgrex-only adapter
    remains available for callers selecting its explicit table contract.

    The optional dependency has `runtime: false`; callers explicitly start the
    Postgrex application and their connection/pool. `store/2` takes that existing
    connection/pool and an explicit table name.
    `ddl/1` returns SQL for a bytea namespace/key primary key and bigint retention
    end; the caller executes it. Names contain only lowercase ASCII letters,
    digits, and underscores, begin with a letter, and occupy 1..63 bytes.
    Queries propagate the remaining operation deadline. Errors expose no SQL,
    connection, namespace, key, or backend exception. Conflicts never update
    retention and claims never evict. Required claims fail closed on outages.

    `sweep/3` accepts explicit Unix seconds. For production, the caller obtains
    this value from its trusted store clock and reconciles it with verification
    clocks; injected historical verification clocks require matching sweep times.
    Sweep deletes only entries whose exclusive retention end is at or before now.
    Multi-node operators sweep at `now - max_internode_skew` to preserve claims
    while any verifier still accepts the authenticated input.
    One namespace should use one freshness bound because duplicates never extend retention.
    PostgreSQL persistence follows the caller's database/storage configuration;
    this adapter does not start a database, pool, timer, or supervisor.
    """
    @behaviour RequestSeal.Replay
    alias RequestSeal.Custody.Context
    alias RequestSeal.Replay.{Claim, Error, Store}

    @doc "Reference an existing caller connection and explicit replay table."
    @spec store(term(), keyword()) :: Store.t() | {:error, Error.t()}
    def store(conn, [{:table, name}]) do
      if table?(name), do: %Store{adapter: __MODULE__, ref: {conn, name}}, else: invalid()
    end

    def store(_, _), do: invalid()

    @doc "SQL the caller executes to create the replay table."
    @spec ddl(binary()) :: binary() | {:error, Error.t()}
    def ddl(name) do
      if table?(name) do
        "CREATE TABLE \"#{name}\" (namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY (namespace, key))"
      else
        invalid()
      end
    end

    @impl RequestSeal.Replay
    def claim({conn, table}, %Claim{} = claim, context) do
      if table?(table) and Claim.valid?(claim) do
        sql =
          "INSERT INTO \"#{table}\" (namespace, key, retain_until) VALUES ($1, $2, $3) ON CONFLICT (namespace, key) DO NOTHING"

        case query(conn, sql, [claim.namespace, claim.key, claim.retain_until], context) do
          {:ok, %{num_rows: 1}} -> :claimed
          {:ok, %{num_rows: 0}} -> :already_claimed
          {:error, reason} -> {:error, reason}
          _ -> {:error, :failure}
        end
      else
        {:error, :failure}
      end
    end

    def claim(_, _, _), do: {:error, :failure}

    @impl RequestSeal.Replay
    def sweep({conn, table}, now, context) when is_integer(now) do
      if table?(table) do
        case query(conn, "DELETE FROM \"#{table}\" WHERE retain_until <= $1", [now], context) do
          {:ok, %{num_rows: count}} -> {:ok, count}
          error -> error
        end
      else
        {:error, :failure}
      end
    end

    def sweep(_, _, _), do: {:error, :failure}

    defp query(conn, sql, params, context) do
      remaining = Context.remaining(context)

      if remaining == 0 do
        {:error, :timeout}
      else
        case Postgrex.query(conn, sql, params, timeout: remaining) do
          {:ok, result} -> {:ok, result}
          {:error, _} -> {:error, :failure}
        end
      end
    rescue
      _ -> {:error, :failure}
    catch
      :exit, {:noproc, _} -> {:error, :unavailable}
      :exit, {:timeout, _} -> {:error, :timeout}
      _, _ -> {:error, :failure}
    end

    defp table?(name),
      do:
        is_binary(name) and byte_size(name) in 1..63 and
          Regex.match?(~r/\A[a-z][a-z0-9_]*\z/, name)

    defp invalid, do: {:error, Error.new(:invalid_store)}
  end
end
