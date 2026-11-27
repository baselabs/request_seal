if Code.ensure_loaded?(Postgrex) do
  defmodule RequestSeal.Replay.Postgres do
    @moduledoc """
    Optional Postgrex atomic replay adapter. The caller owns connections and DDL.

    Prefer `RequestSeal.Replay.AshOnetime` for durable replay with ash_onetime's
    retention guards and externally managed cleanup. This Postgrex-only adapter
    remains available for callers selecting its explicit table contract.

    The optional dependency has `runtime: false`; callers explicitly start the
    Postgrex application and their connection/pool, then pass it to `store/2`
    with an explicit table name. The caller executes the SQL from `ddl/1` and
    `ddl_index/1`.
    Queries propagate the remaining operation deadline. Errors expose no SQL,
    connection, namespace, key, or backend exception. Conflicts never update
    retention and claims never evict. Required claims fail closed on outages.

    For production, the caller obtains the `sweep/3` time from its trusted store
    clock and reconciles it with verification clocks; injected historical
    verification clocks require matching sweep times.
    Multi-node operators sweep at `now - max_internode_skew` to preserve claims
    while any verifier still accepts the authenticated input.
    A reserved row stores the greatest successful sweep cutoff. Claims lock
    that row before inserting. Sweeps advance it before deleting eligible
    claims in the same READ COMMITTED transaction.
    One namespace should use one freshness bound because duplicates never extend retention.
    PostgreSQL persistence follows the caller's database/storage configuration;
    this adapter does not start a database, pool, timer, or supervisor.
    """
    @behaviour RequestSeal.Replay
    alias RequestSeal.Custody.Context
    alias RequestSeal.Replay.{Claim, Error, Store}

    defguardp connection_ref?(conn)
              when is_pid(conn) or (is_atom(conn) and conn != nil) or
                     (is_tuple(conn) and tuple_size(conn) == 2 and is_atom(elem(conn, 0)) and
                        (elem(conn, 0) == :global or is_atom(elem(conn, 1)))) or
                     (is_tuple(conn) and tuple_size(conn) == 3 and elem(conn, 0) == :via and
                        is_atom(elem(conn, 1)))

    @typep connection_ref :: GenServer.server()

    @doc """
    Reference an existing caller connection or pool and an explicit replay table.

    Building the reference does not contact the database or check that the table exists.
    Checked-out transaction handles are refused. A connection or pool process
    lets the adapter own the transaction through commit.

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
    @spec store(connection_ref(), keyword()) :: Store.t() | {:error, Error.t()}
    def store(conn, [{:table, name}]) when connection_ref?(conn) do
      if table?(name), do: %Store{adapter: __MODULE__, ref: {conn, name}}, else: invalid()
    end

    def store(_, _), do: invalid()

    @doc """
    Return the SQL the caller executes to create and initialize a new replay table.

    The table has a bytea namespace/key primary key and a bigint retention end.
    The adapter reserves the pair of empty byte strings for the sweep cutoff.
    Creation and initialization run in one statement. For an existing table,
    use `cutoff_ddl/2` instead. This function only builds the statement.

    ## Parameters

      * `name` - the table name, under the same rules as the `:table` option of `store/2`.

    ## Returns

      * `binary()` - one PostgreSQL block with the name double-quoted.
      * `{:error, %RequestSeal.Replay.Error{}}` - reason `:invalid_store` for a
        malformed name. Meanings: `RequestSeal.Replay.Error`.

    ## Examples

        iex> sql = RequestSeal.Replay.Postgres.ddl("replay_claims")
        iex> String.contains?(sql, ~s(CREATE TABLE "replay_claims"))
        true
        iex> RequestSeal.Replay.Postgres.ddl("1_claims")
        {:error, %RequestSeal.Replay.Error{reason: :invalid_store, retryable: false}}
    """
    @spec ddl(binary()) :: binary() | {:error, Error.t()}
    def ddl(name) do
      if table?(name) do
        """
        DO $replay$
        BEGIN
          CREATE TABLE "#{name}" (
            namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL,
            PRIMARY KEY (namespace, key), CHECK ((namespace = ''::bytea) = (key = ''::bytea))
          );
          INSERT INTO "#{name}" VALUES (''::bytea, ''::bytea, -1);
        END;
        $replay$
        """
      else
        invalid()
      end
    end

    @doc """
    Return the migration SQL for an existing replay table and a trusted
    upper bound on every prior sweep, including sweeps that removed zero rows.

    Quiesce all claim writers and sweepers before establishing the bound and
    executing this statement. If the bound is unknown, keep the existing table
    closed to admission. Repeating the migration preserves a greater cutoff.
    The adapter rejects claims and sweeps until the cutoff row is initialized.
    """
    @spec cutoff_ddl(binary(), 0..253_402_300_799) :: binary() | {:error, Error.t()}
    def cutoff_ddl(name, swept_through)
        when is_integer(swept_through) and swept_through in 0..253_402_300_799 do
      if table?(name) do
        """
        INSERT INTO "#{name}" AS replay (namespace, key, retain_until)
        VALUES (''::bytea, ''::bytea, #{swept_through})
        ON CONFLICT (namespace, key) DO UPDATE
          SET retain_until = GREATEST(replay.retain_until, EXCLUDED.retain_until)
        """
      else
        invalid()
      end
    end

    def cutoff_ddl(_, _), do: invalid()

    @doc """
    Return the SQL the caller executes to index the replay table for sweeps.

    The primary key from `ddl/1` serves claims; `sweep/3` deletes by
    `retain_until`, which without this index is a full-table scan that grows
    with the table. The index excludes the cutoff row. Execute this once beside
    `ddl/1`. An existing full retention index can continue to serve sweeps.

    ## Parameters

      * `name` - the table name, under the same rules as the `:table` option of
        `store/2`, with one further bound: at most 46 bytes, so the derived
        `<table>_retain_until_idx` identifier (17 more bytes) fits PostgreSQL's
        63-byte name limit without server-side truncation.

    ## Returns

      * `binary()` - one `CREATE INDEX` statement with the name double-quoted.
      * `{:error, %RequestSeal.Replay.Error{}}` - reason `:invalid_store` for a
        malformed or over-long name. Meanings: `RequestSeal.Replay.Error`.

    ## Examples

        iex> sql = RequestSeal.Replay.Postgres.ddl_index("replay_claims")
        iex> String.ends_with?(sql, "WHERE namespace <> ''::bytea")
        true
        iex> RequestSeal.Replay.Postgres.ddl_index("1_claims")
        {:error, %RequestSeal.Replay.Error{reason: :invalid_store, retryable: false}}
        iex> RequestSeal.Replay.Postgres.ddl_index(String.duplicate("x", 47))
        {:error, %RequestSeal.Replay.Error{reason: :invalid_store, retryable: false}}
    """
    @spec ddl_index(binary()) :: binary() | {:error, Error.t()}
    def ddl_index(name) do
      if table?(name) and byte_size(name) <= 46 do
        "CREATE INDEX \"#{name}_retain_until_idx\" ON \"#{name}\" (retain_until) " <>
          "WHERE namespace <> ''::bytea"
      else
        invalid()
      end
    end

    @doc """
    Atomically insert `claim` unless the table already holds its namespace and key.

    Implements `c:RequestSeal.Replay.claim/3`; most callers use
    `RequestSeal.Replay.claim/3` with the store from `store/2`. The insert uses
    `ON CONFLICT (namespace, key) DO NOTHING`, so a duplicate never updates retention.
    The admission check and insert share a lock on the cutoff row through commit.

    ## Parameters

      * `ref` - `{conn, table}`, the reference built by `store/2`.
      * `claim` - a `RequestSeal.Replay.Claim`.
      * `context` - a `RequestSeal.Custody.Context`; its remaining time is the query timeout.

    ## Returns

      * `:claimed` - one row was inserted.
      * `:already_claimed` - the namespace and key were already stored.
      * `{:error, :timeout}` - the deadline had expired before the query; or
        the query ran past the deadline (the pool closed the
        connection at the client timeout), the pool dropped the queued request
        (DBConnection `:queue_timeout`), or the server canceled the statement or
        could not take a lock (`query_canceled`, `lock_not_available`). The claim
        may have committed.
      * `{:error, :unavailable}` - the connection process is not running or
        exited; or the connection was lost before the deadline or
        the server is shutting down or
        refusing connections (`admin_shutdown`, `crash_shutdown`,
        `cannot_connect_now`, `too_many_connections`).
      * `{:error, :failure}` - an invalid table name or claim, retention at or
        before the sweep cutoff, any other
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
    @spec claim({connection_ref(), binary()}, Claim.t(), Context.t()) ::
            :claimed | :already_claimed | {:error, :failure | :timeout | :unavailable}
    def claim({conn, table}, %Claim{} = claim, context) when connection_ref?(conn) do
      if table?(table) and Claim.valid?(claim) do
        transaction(conn, context, fn tx -> claim_row(tx, table, claim, context) end)
      else
        {:error, :failure}
      end
    end

    def claim(_, _, _), do: {:error, :failure}

    defp claim_row(tx, table, claim, context) do
      cutoff_sql = """
      SELECT retain_until FROM "#{table}"
      WHERE namespace = ''::bytea AND key = ''::bytea FOR SHARE
      """

      with {:ok, %{rows: [[cutoff]]}} when is_integer(cutoff) and cutoff in -1..253_402_300_799 <-
             query(tx, cutoff_sql, [], context),
           true <- cutoff == -1 or claim.retain_until > cutoff do
        sql = """
        INSERT INTO "#{table}" (namespace, key, retain_until) VALUES ($1, $2, $3)
        ON CONFLICT (namespace, key) DO NOTHING
        """

        case query(tx, sql, [claim.namespace, claim.key, claim.retain_until], context) do
          {:ok, %{num_rows: 1}} -> :claimed
          {:ok, %{num_rows: 0}} -> :already_claimed
          {:error, _} = error -> error
          _ -> {:error, :failure}
        end
      else
        {:error, _} = error -> error
        _ -> {:error, :failure}
      end
    end

    @doc """
    Delete rows whose exclusive retention end is at or before `now`.

    Implements `c:RequestSeal.Replay.sweep/3`. The caller schedules sweeps; this
    adapter never sweeps on its own. A successful sweep advances the cutoff
    even if no claims are deleted.

    ## Parameters

      * `ref` - `{conn, table}`, the reference built by `store/2`.
      * `now` - Unix seconds from 0 through 253,402,300,799.
      * `context` - a `RequestSeal.Custody.Context`; its remaining time is the query timeout.

    ## Returns

      * `{:ok, removed}` - the number of rows deleted.
      * `{:error, :timeout}` - the deadline had expired before the query; or
        the query ran past the deadline (the pool closed the
        connection at the client timeout), the pool dropped the queued request
        (DBConnection `:queue_timeout`), or the server canceled the statement or
        could not take a lock (`query_canceled`, `lock_not_available`). The sweep's deletions
        were not committed when the statement was canceled or never sent, and may
        or may not have committed when the connection closed at the deadline; a
        later sweep with the same `now` removes whatever remains.
      * `{:error, :unavailable}` - the connection process is not running or
        exited; or the connection was lost before the deadline or
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
    @spec sweep({connection_ref(), binary()}, integer(), Context.t()) ::
            {:ok, non_neg_integer()} | {:error, :failure | :timeout | :unavailable}
    def sweep({conn, table}, now, context)
        when connection_ref?(conn) and is_integer(now) and now in 0..253_402_300_799 do
      if table?(table) do
        transaction(conn, context, fn tx -> sweep_rows(tx, table, now, context) end)
      else
        {:error, :failure}
      end
    end

    def sweep(_, _, _), do: {:error, :failure}

    defp sweep_rows(tx, table, now, context) do
      cutoff_sql = """
      UPDATE "#{table}" SET retain_until = GREATEST(retain_until, $1)
      WHERE namespace = ''::bytea AND key = ''::bytea AND retain_until BETWEEN -1 AND 253402300799
      """

      # Read a new snapshot after taking the cutoff lock. Claims that committed
      # while the sweep was waiting are then visible to the deletion.
      delete_sql = """
      DELETE FROM "#{table}" WHERE namespace <> ''::bytea AND retain_until <= $1
      """

      with {:ok, %{num_rows: 1}} <- query(tx, cutoff_sql, [now], context),
           {:ok, %{num_rows: count}} <- query(tx, delete_sql, [now], context) do
        {:ok, count}
      else
        {:error, _} = error -> error
        _ -> {:error, :failure}
      end
    end

    defp transaction(conn, context, operation) do
      bounded(context, fn remaining ->
        result =
          Postgrex.transaction(
            conn,
            fn tx ->
              outcome =
                with {:ok, _} <-
                       query(tx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED", [], context) do
                  operation.(tx)
                end

              case outcome do
                {:error, _} = error ->
                  Postgrex.rollback(tx, error)

                result ->
                  if Context.remaining(context) == 0,
                    do: Postgrex.rollback(tx, {:error, :timeout}),
                    else: result
              end
            end,
            timeout: remaining
          )

        case result do
          {:ok, outcome} -> outcome
          {:error, {:error, _} = error} -> error
          {:error, error} -> query_error(error, context)
        end
      end)
    end

    defp query(conn, sql, params, context) do
      bounded(context, fn remaining ->
        case Postgrex.query(conn, sql, params, timeout: remaining) do
          {:ok, result} -> {:ok, result}
          {:error, error} -> query_error(error, context)
        end
      end)
    end

    defp bounded(context, callback) do
      remaining = Context.remaining(context)

      if remaining == 0 do
        {:error, :timeout}
      else
        callback.(remaining)
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
