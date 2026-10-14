if Code.ensure_loaded?(Postgrex) do
  defmodule RequestSeal.Replay.Postgres do
    @moduledoc """
    Optional Postgrex atomic replay adapter. The caller owns connections and DDL.

    Prefer `RequestSeal.Replay.AshOnetime` for durable replay with ash_onetime's
    retention guards and externally managed cleanup. This Postgrex-only adapter
    remains available for callers selecting its explicit table contract.

    The optional dependency has `runtime: false`; callers explicitly start the
    Postgrex application and their connection/pool, then pass it to `store/2`
    with an explicit table name. The caller executes the SQL from `ddl/1`.
    Queries propagate the remaining operation deadline. Errors expose no SQL,
    connection, namespace, key, or backend exception. Conflicts never update
    retention and claims never evict. Required claims fail closed on outages.

    For production, the caller obtains the `sweep/3` time from its trusted store
    clock and reconciles it with verification clocks; injected historical
    verification clocks require matching sweep times.
    Multi-node operators sweep at `now - max_internode_skew` to preserve claims
    while any verifier still accepts the authenticated input.
    One namespace should use one freshness bound because duplicates never extend retention.
    PostgreSQL persistence follows the caller's database/storage configuration;
    this adapter does not start a database, pool, timer, or supervisor.
    """
    @behaviour RequestSeal.Replay
    alias RequestSeal.Custody.Context
    alias RequestSeal.Replay.{Claim, Error, Store}

    @doc """
    Reference an existing caller connection or pool and an explicit replay table.

    Building the reference does not contact the database or check that the table exists.

    ## Parameters

      * `conn` - a running Postgrex connection or pool: a pid or registered name.
      * `opts` - keyword list; see Options.

    ## Options

      * `:table` - required, and the only accepted option: the table name. Names
        contain only lowercase ASCII letters, digits, and underscores, begin with a
        letter, and occupy 1..63 bytes.

    ## Returns

      * `RequestSeal.Replay.Store` - adapter `RequestSeal.Replay.Postgres` with
        `{conn, table}` as its reference.
      * `{:error, %RequestSeal.Replay.Error{}}` - reason `:invalid_store` for a
        missing, extra or malformed option. Meanings: `RequestSeal.Replay.Error`.

    ## Examples

        iex> store = RequestSeal.Replay.Postgres.store(:replay_db, table: "replay_claims")
        iex> store.adapter
        RequestSeal.Replay.Postgres
        iex> RequestSeal.Replay.Postgres.store(:replay_db, table: "Replay-Claims")
        {:error, %RequestSeal.Replay.Error{reason: :invalid_store, retryable: false}}
    """
    @spec store(term(), keyword()) :: Store.t() | {:error, Error.t()}
    def store(conn, [{:table, name}]) do
      if table?(name), do: %Store{adapter: __MODULE__, ref: {conn, name}}, else: invalid()
    end

    def store(_, _), do: invalid()

    @doc """
    Return the SQL the caller executes to create the replay table.

    The table has a bytea namespace/key primary key and a bigint retention end.
    This function only builds the statement; it does not run it.

    ## Parameters

      * `name` - the table name, under the same rules as the `:table` option of `store/2`.

    ## Returns

      * `binary()` - one `CREATE TABLE` statement with the name double-quoted.
      * `{:error, %RequestSeal.Replay.Error{}}` - reason `:invalid_store` for a
        malformed name. Meanings: `RequestSeal.Replay.Error`.

    ## Examples

        iex> RequestSeal.Replay.Postgres.ddl("replay_claims")
        ~S|CREATE TABLE "replay_claims" (namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY (namespace, key))|
        iex> RequestSeal.Replay.Postgres.ddl("1_claims")
        {:error, %RequestSeal.Replay.Error{reason: :invalid_store, retryable: false}}
    """
    @spec ddl(binary()) :: binary() | {:error, Error.t()}
    def ddl(name) do
      if table?(name) do
        "CREATE TABLE \"#{name}\" (namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY (namespace, key))"
      else
        invalid()
      end
    end

    @doc """
    Atomically insert `claim` unless the table already holds its namespace and key.

    Implements `c:RequestSeal.Replay.claim/3`; most callers use
    `RequestSeal.Replay.claim/3` with the store from `store/2`. The insert uses
    `ON CONFLICT (namespace, key) DO NOTHING`, so a duplicate never updates retention.

    ## Parameters

      * `ref` - `{conn, table}`, the reference built by `store/2`.
      * `claim` - a `RequestSeal.Replay.Claim`.
      * `context` - a `RequestSeal.Custody.Context`; its remaining time is the query timeout.

    ## Returns

      * `:claimed` - one row was inserted.
      * `:already_claimed` - the namespace and key were already stored.
      * `{:error, :timeout}` - the deadline had expired before the query; or,
        from 0.5.0 (unreleased), the query ran past the deadline (the pool closed the
        connection at the client timeout), the pool dropped the queued request
        (DBConnection `:queue_timeout`), or the server canceled the statement or
        could not take a lock (`query_canceled`, `lock_not_available`). The claim
        may have committed.
      * `{:error, :unavailable}` - the connection process is not running or
        exited; or, from 0.5.0 (unreleased), the connection was lost before the deadline or
        the server is shutting down or
        refusing connections (`admin_shutdown`, `crash_shutdown`,
        `cannot_connect_now`, `too_many_connections`).
      * `{:error, :failure}` - an invalid table name or claim, any other
        database error, or any other failure.

    ## Examples

        iex> context = %RequestSeal.Custody.Context{
        ...>   owner: self(),
        ...>   deadline: System.monotonic_time(:millisecond) + 1_000
        ...> }
        iex> claim = %RequestSeal.Replay.Claim{namespace: "orders", key: "", retain_until: 100}
        iex> RequestSeal.Replay.Postgres.claim({:replay_db, "replay_claims"}, claim, context)
        {:error, :failure}

    Fragment (requires a running PostgreSQL connection and the `ddl/1` table; not executed here):

        {:ok, conn} = Postgrex.start_link(database: "replay", hostname: "db.example")
        store = RequestSeal.Replay.Postgres.store(conn, table: "replay_claims")
        claim = %RequestSeal.Replay.Claim{namespace: "orders", key: "nonce-7f3a", retain_until: 1_900_000_000}
        :claimed = RequestSeal.Replay.claim(store, claim, timeout: 2_000)
        :already_claimed = RequestSeal.Replay.claim(store, claim, timeout: 2_000)
    """
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

    @doc """
    Delete rows whose exclusive retention end is at or before `now`.

    Implements `c:RequestSeal.Replay.sweep/3`. The caller schedules sweeps; this
    adapter never sweeps on its own.

    ## Parameters

      * `ref` - `{conn, table}`, the reference built by `store/2`.
      * `now` - Unix seconds from 0 through 253,402,300,799.
      * `context` - a `RequestSeal.Custody.Context`; its remaining time is the query timeout.

    ## Returns

      * `{:ok, removed}` - the number of rows deleted.
      * `{:error, :timeout}` - the deadline had expired before the query; or,
        from 0.5.0 (unreleased), the query ran past the deadline (the pool closed the
        connection at the client timeout), the pool dropped the queued request
        (DBConnection `:queue_timeout`), or the server canceled the statement or
        could not take a lock (`query_canceled`, `lock_not_available`). The sweep's deletions
        were not committed when the statement was canceled or never sent, and may
        or may not have committed when the connection closed at the deadline; a
        later sweep with the same `now` removes whatever remains.
      * `{:error, :unavailable}` - the connection process is not running or
        exited; or, from 0.5.0 (unreleased), the connection was lost before the deadline or
        the server is shutting down or
        refusing connections (`admin_shutdown`, `crash_shutdown`,
        `cannot_connect_now`, `too_many_connections`).
      * `{:error, :failure}` - `now` is outside the range, the table name is
        invalid, any other database error, or any other failure.

    ## Examples

        iex> context = %RequestSeal.Custody.Context{
        ...>   owner: self(),
        ...>   deadline: System.monotonic_time(:millisecond) + 1_000
        ...> }
        iex> RequestSeal.Replay.Postgres.sweep({:replay_db, "replay_claims"}, -1, context)
        {:error, :failure}

    Fragment (requires a running PostgreSQL connection and the `ddl/1` table; not executed here):

        context = %RequestSeal.Custody.Context{
          owner: self(),
          deadline: System.monotonic_time(:millisecond) + 5_000
        }

        {:ok, removed} =
          RequestSeal.Replay.Postgres.sweep({conn, "replay_claims"}, trusted_now, context)
    """
    @impl RequestSeal.Replay
    def sweep({conn, table}, now, context) when is_integer(now) and now in 0..253_402_300_799 do
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
          {:error, error} -> query_error(error, context)
        end
      end
    rescue
      error in [DBConnection.ConnectionError, Postgrex.Error] -> query_error(error, context)
      _ -> {:error, :failure}
    catch
      :exit, {:noproc, _} -> {:error, :unavailable}
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, _ -> {:error, :unavailable}
      _, _ -> {:error, :failure}
    end

    # The same classification as RequestSeal.Replay.AshOnetime: connection loss
    # and server shutdown are unavailability; cancellation and lock waits are
    # timeouts (indeterminate); other database errors remain failures.
    # DBConnection 2.10 marks a dropped queued request with reason :queue_timeout.
    # A client timeout closes the connection (reason :closed or :error, no
    # timeout marker); the expired deadline we passed as the query timeout is
    # the signal that distinguishes it from a lost connection.
    defp query_error(%DBConnection.ConnectionError{reason: :queue_timeout}, _),
      do: {:error, :timeout}

    defp query_error(%DBConnection.ConnectionError{}, context) do
      if Context.remaining(context) == 0, do: {:error, :timeout}, else: {:error, :unavailable}
    end

    defp query_error(error, _context), do: query_error(error)

    defp query_error(%Postgrex.Error{postgres: %{code: code}})
         when code in [:query_canceled, :lock_not_available],
         do: {:error, :timeout}

    defp query_error(%Postgrex.Error{postgres: %{code: code}})
         when code in [
                :admin_shutdown,
                :crash_shutdown,
                :cannot_connect_now,
                :too_many_connections
              ],
         do: {:error, :unavailable}

    defp query_error(_), do: {:error, :failure}

    defp table?(name),
      do:
        is_binary(name) and byte_size(name) in 1..63 and
          Regex.match?(~r/\A[a-z][a-z0-9_]*\z/, name)

    defp invalid, do: {:error, Error.new(:invalid_store)}
  end
end
