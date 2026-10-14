if Code.ensure_loaded?(AshOnetime.Transaction) do
  defmodule RequestSeal.Replay.AshOnetime do
    @moduledoc """
    Recommended durable replay store over `AshOnetime.Transaction.nonce/2`.

    Requires optional ash_onetime 1.5 and Elixir 1.20. The caller owns the
    existing Ecto repo, PostgreSQL database, and ash_onetime installation
    migrations. Namespace and commitment bytes are base64url encoded into scope and key;
    they never become SQL identifiers or logical partitions.

    Each claim owns a READ COMMITTED transaction under the remaining deadline.
    This transaction commits independently of the verifier's application effect.
    To spend a nonce together with an effect, verify with replay explicitly
    `:not_required`, then use ash_onetime in the application's transaction.
    No timeout or failure permits automatic retry: the claim may have committed.

    Facts use PostgreSQL's transaction clock, read in the same transaction as
    admission. Max age is derived from `retain_until`; one second of rounding
    headroom and ash_onetime's cleanup margin keep retention beyond that horizon
    without relying on application/database clock synchronization. ash_onetime's
    freshness check can still reject clock skew; rejection never spends a nonce.
    Past or current retention horizons still block an immediate duplicate.
    Historical verification clocks do not move the database's cleanup clock.
    Duplicate claims do not
    extend retention; use one freshness bound per namespace.

    `sweep/3` never deletes anything. Cleanup belongs to
    `mix ash_onetime.prune` or `AshOnetime.Oban.CleanupWorker`; this adapter never
    calls ash_onetime's internal store APIs or starts any process.
    """
    @behaviour RequestSeal.Replay
    alias RequestSeal.Custody.Context
    alias RequestSeal.Replay.{Claim, Error, Store}
    @type ref :: {module(), binary(), binary() | nil}

    @doc """
    Reference an existing repo with an explicit logical partition and optional schema prefix.

    Building the reference does not contact the database; the repo module must be
    loaded and export `transaction/2`.

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
           text?(opts[:partition], 255) and (opts[:prefix] == nil or text?(opts[:prefix], 63)) and
           Code.ensure_loaded?(repo) and function_exported?(repo, :transaction, 2) do
        %Store{adapter: __MODULE__, ref: {repo, opts[:partition], opts[:prefix]}}
      else
        {:error, Error.new(:invalid_store)}
      end
    end

    def store(_, _), do: {:error, Error.new(:invalid_store)}

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
        lock or cancellation; and, from 0.5.0 (unreleased), a pool queue timeout (DBConnection
        `:queue_timeout`) or any failure observed after the deadline, such as a transaction rolled
        back when the pool closed the connection at the client timeout. The claim
        may have committed.
      * `{:error, :unavailable}` - the repo is not running, a connection could not
        be checked out, or the database is shutting down or refusing connections.
      * `{:error, :failure}` - an invalid claim or reference, any other ash_onetime
        error code, or any other failure.

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
    def claim({repo, partition, prefix} = ref, %Claim{} = claim, %Context{} = context) do
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

              with {:ok, verified} <-
                     AshOnetime.Verified.new(
                       key: key,
                       issued_at: now,
                       verifier_id: "request_seal.replay.v1"
                     ) do
                AshOnetime.Transaction.nonce(repo,
                  operation: {__MODULE__, :claim},
                  partition: partition,
                  prefix: prefix,
                  scope: scope,
                  key: key,
                  verified: [verified],
                  max_age: max(claim.retain_until - DateTime.to_unix(now), 0),
                  clock_skew: 1
                )
              else
                _ -> {:error, :invalid_claim}
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

    defp valid_ref?(repo, partition, prefix) do
      is_atom(repo) and Code.ensure_loaded?(repo) and function_exported?(repo, :transaction, 2) and
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
