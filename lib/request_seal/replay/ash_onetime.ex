if Code.ensure_loaded?(AshOnetime.Transaction) do
  defmodule RequestSeal.Replay.AshOnetime do
    @moduledoc """
    Recommended durable replay store over `AshOnetime.Transaction.nonce/2`.

    Requires optional ash_onetime 1.9.2 or newer within 1.x, and Elixir 1.20.
    The caller owns the existing Ecto repo, PostgreSQL database, and ash_onetime
    installation migrations. Install `cleanup_guard_ddl/2` in the same schema
    after the ash_onetime migrations. Namespace and commitment bytes are
    base64url encoded into scope and key.

    Each claim owns a READ COMMITTED transaction under the remaining deadline.
    Direct calls inside an already open transaction for the repo are refused.
    This transaction commits independently of the verifier's application effect.
    To spend a nonce together with an effect, verify with replay explicitly
    `:not_required`, then use ash_onetime in the application's transaction.
    No timeout or failure permits automatic retry: the claim may have committed.

    The delegate owns nonce uniqueness and cleanup eligibility. A statement
    trigger records its greatest successful cleanup transaction timestamp,
    including cleanup that deletes zero rows. Before commit the adapter locks
    that cutoff and checks the claim against it and the current database clock.
    Admission at or before either boundary fails and leaves no new nonce.
    Duplicate claims never extend retention.

    `sweep/3` never deletes anything. Cleanup belongs to
    `mix ash_onetime.prune` or `AshOnetime.Oban.CleanupWorker`; this adapter never
    calls ash_onetime's internal store APIs or starts any process. The cutoff
    trigger runs in the delegate's cleanup transaction.
    """
    @behaviour RequestSeal.Replay
    alias RequestSeal.Custody.Context
    alias RequestSeal.Replay.{Claim, Error, Store}

    @context_size map_size(%Context{})
    @type ref :: {module(), binary(), binary() | nil}

    @doc """
    Reference an existing repo with an explicit logical partition and optional schema prefix.

    Building the reference does not contact the database; the repo module must be
    loaded and export `transaction/2` and `in_transaction?/0`.

    ## Parameters

      * `repo` - the caller's Ecto repo module.
      * `opts` - keyword list without duplicate keys; see Options.

    ## Options

      * `:partition` - required: the ash_onetime logical partition, a valid UTF-8
        string of 1–255 bytes without NUL bytes.
      * `:prefix` - optional schema prefix, a valid UTF-8 string of 1–63 bytes
        without NUL bytes. Default `nil` (the repo's default schema).

    ## Returns

      * `RequestSeal.Replay.Store` - adapter `RequestSeal.Replay.AshOnetime` with
        `{repo, partition, prefix}` as its reference.
      * `{:error, %RequestSeal.Replay.Error{}}` - reason `:invalid_store` for an
        unknown, duplicate or malformed option, or a repo module that is not
        loaded or lacks `transaction/2`. Meanings: `RequestSeal.Replay.Error`.

    ## Examples

        iex> RequestSeal.Replay.AshOnetime.store(Example.Repo, partition: "")
        {:error, %RequestSeal.Replay.Error{reason: :invalid_store, retryable: false}}

    Fragment (requires a running Ecto repo with the ash_onetime migrations; not executed here):

        store = RequestSeal.Replay.AshOnetime.store(Example.Repo, partition: "webhooks")
        claim = %RequestSeal.Replay.Claim{namespace: "orders", key: "nonce-7f3a", retain_until: 1_900_000_000}
        :claimed = RequestSeal.Replay.claim(store, claim, timeout: 2_000)
        :already_claimed = RequestSeal.Replay.claim(store, claim, timeout: 2_000)
    """
    @spec store(module(), keyword()) :: Store.t() | {:error, Error.t()}
    def store(repo, opts) when is_atom(repo) and is_list(opts) do
      if Keyword.keyword?(opts) and
           length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
           Enum.all?(Keyword.keys(opts), &(&1 in [:partition, :prefix])) and
           valid_ref?(repo, opts[:partition], opts[:prefix]) do
        %Store{adapter: __MODULE__, ref: {repo, opts[:partition], opts[:prefix]}}
      else
        {:error, Error.new(:invalid_store)}
      end
    end

    def store(_, _), do: {:error, Error.new(:invalid_store)}

    @doc """
    Return the SQL to install the delegated cleanup cutoff in `prefix`.

    Run these statements in order in one migration transaction after installing
    ash_onetime. Use the same schema as the store. With `nil`, the migration
    and store use the repo's default schema. The installed trigger runs on each
    nonce DELETE statement, including empty cleanup batches. Pass `0` for a
    fresh schema with no prior cleanup. For a used schema, quiesce claim
    writers and cleanup, and supply a trusted upper bound on prior cleanup
    timestamps. If that bound is unknown, keep admission closed. Installation
    keeps the greater of the supplied bound and the current database time.
    Grant the claim and cleanup database roles permission to lock and update
    the cutoff row.
    This function builds SQL and does not execute it.
    """
    @spec cleanup_guard_ddl(binary() | nil, 0..253_402_300_799) ::
            [binary()] | {:error, Error.t()}
    def cleanup_guard_ddl(prefix, swept_through)
        when is_integer(swept_through) and swept_through in 0..253_402_300_799 do
      if prefix == nil or text?(prefix, 63) do
        cutoff = relation(prefix, "request_seal_replay_cutoff")
        function = relation(prefix, "request_seal_record_replay_cleanup")
        nonce_claims = relation(prefix, "ash_onetime_nonce_claims")

        [
          """
          CREATE TABLE #{cutoff} (
            singleton boolean PRIMARY KEY CHECK (singleton),
            swept_through bigint NOT NULL
          )
          """,
          """
          INSERT INTO #{cutoff} VALUES (
            true,
            GREATEST(
              #{swept_through}, floor(extract(epoch FROM transaction_timestamp()))::bigint
            )
          )
          """,
          """
          CREATE FUNCTION #{function}() RETURNS trigger LANGUAGE plpgsql AS $cutoff$
          DECLARE updated bigint;
          BEGIN
            EXECUTE format(
              'UPDATE %I.request_seal_replay_cutoff
               SET swept_through = GREATEST(swept_through, $1) WHERE singleton',
              TG_TABLE_SCHEMA
            ) USING floor(extract(epoch FROM transaction_timestamp()))::bigint;
            GET DIAGNOSTICS updated = ROW_COUNT;
            IF updated <> 1 THEN
              RAISE EXCEPTION 'replay cleanup cutoff row is missing';
            END IF;
            RETURN NULL;
          END;
          $cutoff$
          """,
          """
          CREATE TRIGGER request_seal_record_replay_cleanup AFTER DELETE ON #{nonce_claims}
          FOR EACH STATEMENT EXECUTE FUNCTION #{function}()
          """
        ]
      else
        {:error, Error.new(:invalid_store)}
      end
    end

    def cleanup_guard_ddl(_, _), do: {:error, Error.new(:invalid_store)}

    @doc """
    Atomically claim an envelope in an independently committed transaction.

    Implements `c:RequestSeal.Replay.claim/3`; most callers use
    `RequestSeal.Replay.claim/3` with the store from `store/2`. The transaction and
    its queries use the remaining time of `context` as their timeout.

    ## Parameters

      * `ref` - `{repo, partition, prefix}`, the reference built by `store/2`.
      * `claim` - a `RequestSeal.Replay.Claim`.
      * `context` - a `RequestSeal.Custody.Context`.

    ## Returns

      * `:claimed` - ash_onetime admitted the nonce.
      * `:already_claimed` - ash_onetime reported `:nonce_already_used`.
      * `{:error, :timeout}` - the deadline had expired before the transaction; a
        lock or cancellation; a pool queue timeout (DBConnection
        `:queue_timeout`) or any failure observed after the deadline, such as a transaction rolled
        back when the pool closed the connection at the client timeout. The claim
        may have committed.
      * `{:error, :unavailable}` - the repo is not running, a connection could not
        be checked out, or the database is shutting down or refusing connections.
      * `{:error, :failure}` - an invalid claim, reference or context, an enclosing
        repo transaction, a retention end at or before the database clock or
        cleanup cutoff, or any other failure.

    ## Examples

        iex> context = %RequestSeal.Custody.Context{
        ...>   owner: self(),
        ...>   deadline: System.monotonic_time(:millisecond) + 1_000
        ...> }
        iex> claim = %RequestSeal.Replay.Claim{namespace: "orders", key: "", retain_until: 100}
        iex> RequestSeal.Replay.AshOnetime.claim({Example.Repo, "webhooks", nil}, claim, context)
        {:error, :failure}
    """
    @impl true
    @spec claim(ref(), Claim.t(), Context.t()) ::
            :claimed | :already_claimed | {:error, :unavailable | :timeout | :failure}
    def claim(
          {repo, partition, prefix} = ref,
          %Claim{} = claim,
          %Context{owner: owner, deadline: deadline} = context
        )
        when map_size(context) in [3, @context_size] and is_pid(owner) and is_integer(deadline) do
      case attempt(ref, claim, context) do
        # A client timeout surfaces as a rolled-back transaction or a closed
        # connection with no timeout marker; the expired deadline that bounded
        # the transaction is the signal that the outcome is indeterminate.
        {:error, reason} when reason in [:unavailable, :failure] ->
          if valid_ref?(repo, partition, prefix) and Claim.valid?(claim) and
               Context.remaining(context) == 0,
             do: {:error, :timeout},
             else: {:error, reason}

        outcome ->
          outcome
      end
    end

    def claim(_, _, _), do: {:error, :failure}

    defp attempt({repo, partition, prefix}, claim, context) do
      cond do
        not Claim.valid?(claim) or not valid_ref?(repo, partition, prefix) ->
          {:error, :failure}

        Context.remaining(context) == 0 ->
          {:error, :timeout}

        not running_repo?(repo) ->
          {:error, :unavailable}

        repo.in_transaction?() ->
          {:error, :failure}

        true ->
          key = Base.url_encode64(claim.key, padding: false)
          scope = Base.url_encode64(claim.namespace, padding: false)

          repo.transaction(
            fn ->
              # The same PostgreSQL transaction timestamp anchors ash_onetime's
              # admitted_at and cleanup floor, even when the host clock differs.
              %{rows: [[now]]} =
                Ecto.Adapters.SQL.query!(repo, "SELECT transaction_timestamp()", [],
                  timeout: Context.remaining(context)
                )

              with true <- claim.retain_until > DateTime.to_unix(now),
                   {:ok, verified} <-
                     AshOnetime.Verified.new(
                       key: key,
                       issued_at: now,
                       verifier_id: "request_seal.replay.v1"
                     ) do
                outcome =
                  AshOnetime.Transaction.nonce(repo,
                    operation: {__MODULE__, :claim},
                    partition: partition,
                    prefix: prefix,
                    scope: scope,
                    key: key,
                    verified: [verified],
                    max_age: claim.retain_until - DateTime.to_unix(now),
                    clock_skew: 1
                  )

                if outcome == :ok or
                     match?({:error, %AshOnetime.Error{code: :nonce_already_used}}, outcome) do
                  check_cutoff(outcome, repo, prefix, claim.retain_until, context)
                else
                  outcome
                end
              else
                _ -> repo.rollback(:invalid_claim)
              end
            end,
            timeout: Context.remaining(context)
          )
          |> result()
      end
    rescue
      error in DBConnection.ConnectionError -> connection_error(error)
      error in Postgrex.Error -> database_error(error)
      _ -> {:error, :failure}
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :unavailable}
      :exit, _ -> {:error, :unavailable}
      _, _ -> {:error, :failure}
    end

    defp check_cutoff(outcome, repo, prefix, retain_until, context) do
      table = relation(prefix, "request_seal_replay_cutoff")

      # Cleanup locks the nonce rows before the cutoff. Take locks in that
      # same order and roll back the nonce if the cutoff advanced during admission.
      %{rows: [[cutoff]]} =
        Ecto.Adapters.SQL.query!(
          repo,
          "SELECT swept_through FROM #{table} WHERE singleton FOR SHARE",
          [],
          timeout: Context.remaining(context)
        )

      %{rows: [[now]]} =
        Ecto.Adapters.SQL.query!(repo, "SELECT clock_timestamp()", [],
          timeout: Context.remaining(context)
        )

      true = is_integer(cutoff)

      if retain_until > max(cutoff, DateTime.to_unix(now)),
        do: outcome,
        else: repo.rollback(:invalid_claim)
    end

    defp relation(nil, table), do: table

    defp relation(prefix, table),
      do: "\"" <> String.replace(prefix, "\"", "\"\"") <> "\"." <> table

    defp valid_ref?(repo, partition, prefix) do
      is_atom(repo) and Code.ensure_loaded?(repo) and function_exported?(repo, :transaction, 2) and
        function_exported?(repo, :in_transaction?, 0) and
        text?(partition, 255) and (prefix == nil or text?(prefix, 63))
    end

    defp running_repo?(repo) do
      Ecto.Repo.Registry.lookup(repo.get_dynamic_repo())
      true
    rescue
      _ -> false
    end

    # DBConnection 2.10 marks a dropped queued request with reason :queue_timeout.
    defp connection_error(%DBConnection.ConnectionError{reason: :queue_timeout}),
      do: {:error, :timeout}

    defp connection_error(_), do: {:error, :unavailable}

    defp database_error(%Postgrex.Error{postgres: %{code: code}})
         when code in [:query_canceled, :lock_not_available], do: {:error, :timeout}

    defp database_error(%Postgrex.Error{postgres: %{code: code}})
         when code in [
                :admin_shutdown,
                :crash_shutdown,
                :cannot_connect_now,
                :too_many_connections
              ],
         do: {:error, :unavailable}

    defp database_error(_), do: {:error, :failure}

    @doc """
    Refuse to sweep: cleanup is externally managed by ash_onetime's prune task or Oban worker.

    Implements `c:RequestSeal.Replay.sweep/3` without touching the database.
    The database trigger advances the cutoff when the delegate runs cleanup.

    ## Parameters

      * `ref` - ignored.
      * `now` - ignored.
      * `context` - ignored.

    ## Returns

      * `{:error, :externally_managed}` - always.

    ## Examples

        iex> context = %RequestSeal.Custody.Context{
        ...>   owner: self(),
        ...>   deadline: System.monotonic_time(:millisecond) + 1_000
        ...> }
        iex> RequestSeal.Replay.AshOnetime.sweep({Example.Repo, "webhooks", nil}, 1_900_000_000, context)
        {:error, :externally_managed}
    """
    @impl true
    @spec sweep(ref(), integer(), Context.t()) :: {:error, :externally_managed}
    def sweep(_ref, _now, _context), do: {:error, :externally_managed}

    defp result({:ok, :ok}), do: :claimed

    defp result({:ok, {:error, %AshOnetime.Error{code: :nonce_already_used}}}),
      do: :already_claimed

    defp result({:ok, {:error, %AshOnetime.Error{code: code}}}), do: error(code)
    defp result({:error, _}), do: {:error, :failure}
    defp result(_), do: {:error, :failure}

    defp error(code) when code in [:checkout_unavailable, :admission_unavailable, :disconnected],
      do: {:error, :unavailable}

    defp error(code) when code in [:lock_timeout, :dispatched_unknown], do: {:error, :timeout}
    defp error(_), do: {:error, :failure}

    defp text?(s, max),
      do:
        is_binary(s) and byte_size(s) in 1..max and String.valid?(s) and
          not String.contains?(s, <<0>>)
  end
end
