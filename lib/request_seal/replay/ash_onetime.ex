if Code.ensure_loaded?(AshOnetime.Transaction) do
  defmodule RequestSeal.Replay.AshOnetime do
    @moduledoc """
    Recommended durable replay store over `AshOnetime.Transaction.nonce/2`.

    Requires optional ash_onetime 1.5 and Elixir 1.20. The caller owns the
    existing Ecto repo, PostgreSQL database, and ash_onetime installation
    migrations. `store/2` selects a logical partition and optional schema prefix.
    Namespace and commitment bytes are base64url encoded into scope and key;
    they never become SQL identifiers or logical partitions.

    Each claim owns a READ COMMITTED transaction under the remaining deadline.
    This transaction commits independently of the verifier's application effect.
    To spend a nonce together with an effect, verify with replay explicitly
    `:not_required`, then use ash_onetime in the application's transaction.
    No timeout or failure permits automatic retry: the claim may have committed.

    Facts are anchored to the current wall clock, with max age derived from
    `retain_until` and one second of clock skew. ash_onetime adds its cleanup
    safety margin, so retention is never shorter than the requested horizon.
    Keep database and application clocks synchronized. Historical verification
    clocks do not move ash_onetime's cleanup clock. Duplicate claims do not
    extend retention; use one freshness bound per namespace.

    `sweep/3` returns `{:error, :externally_managed}`. Cleanup belongs to
    `mix ash_onetime.prune` or `AshOnetime.Oban.CleanupWorker`; this adapter never
    calls ash_onetime's internal store APIs or starts any process.
    """
    @behaviour RequestSeal.Replay
    alias RequestSeal.Custody.Context
    alias RequestSeal.Replay.{Claim, Error, Store}
    @type ref :: {module(), binary(), binary() | nil}

    @doc "Reference an existing repo with an explicit logical partition and optional prefix."
    @spec store(module(), keyword()) :: Store.t() | {:error, Error.t()}
    def store(repo, opts) when is_atom(repo) and is_list(opts) do
      if Keyword.keyword?(opts) and
           length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
           Enum.all?(Keyword.keys(opts), &(&1 in [:partition, :prefix])) and
           text?(opts[:partition], 255) and (opts[:prefix] == nil or text?(opts[:prefix], 255)) and
           Code.ensure_loaded?(repo) and function_exported?(repo, :transaction, 2) do
        %Store{adapter: __MODULE__, ref: {repo, opts[:partition], opts[:prefix]}}
      else
        {:error, Error.new(:invalid_store)}
      end
    end

    def store(_, _), do: {:error, Error.new(:invalid_store)}

    @doc "Atomically claim an envelope in an independently committed transaction."
    @impl true
    @spec claim(ref(), Claim.t(), Context.t()) ::
            :claimed | :already_claimed | {:error, :unavailable | :timeout | :failure}
    def claim({repo, partition, prefix}, %Claim{} = claim, %Context{} = context) do
      remaining = Context.remaining(context)

      if remaining == 0 do
        {:error, :timeout}
      else
        now = DateTime.utc_now() |> DateTime.truncate(:second)
        key = Base.url_encode64(claim.key, padding: false)

        with true <- Claim.valid?(claim),
             {:ok, verified} <-
               AshOnetime.Verified.new(
                 key: key,
                 issued_at: now,
                 verifier_id: "request_seal.replay.v1"
               ) do
          repo.transaction(
            fn ->
              AshOnetime.Transaction.nonce(repo,
                operation: {__MODULE__, :claim},
                partition: partition,
                prefix: prefix,
                scope: Base.url_encode64(claim.namespace, padding: false),
                key: key,
                verified: [verified],
                max_age: max(claim.retain_until - DateTime.to_unix(now), 0),
                clock_skew: 1
              )
            end,
            timeout: remaining
          )
          |> result()
        else
          _ -> {:error, :failure}
        end
      end
    rescue
      _ -> {:error, :unavailable}
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :unavailable}
      :exit, _ -> {:error, :unavailable}
      _, _ -> {:error, :failure}
    end

    def claim(_, _, _), do: {:error, :failure}

    @doc "Cleanup is externally managed by ash_onetime's prune task or Oban worker."
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
