defmodule RequestSeal.Replay.Error do
  @moduledoc """
  Bounded replay boundary failures, without adapter diagnostics or caller bytes.

  `retryable` is always false: a timeout may have committed and is indeterminate.

  Reasons:

    * `:invalid_store` - the store is not a `RequestSeal.Replay.Store` whose
      loaded adapter exports `claim/3` and `sweep/3`, or an adapter's `store/2`
      or `ddl/1` rejected its arguments.
    * `:invalid_claim` - the claim fails `RequestSeal.Replay.Claim.valid?/1`.
    * `:invalid_options` - the options are not exactly `timeout: 1..300_000`.
    * `:store_unavailable` - the adapter reported that the store is unreachable.
    * `:store_timeout` - the adapter reported a timeout, or the operation deadline
      expired; the claim may have been committed.
    * `:store_full` - the adapter reported that the store is at capacity.
    * `:store_failed` - the adapter reported any other failure or returned an
      unexpected value, or the operation worker exited.
  """
  defstruct [:reason, retryable: false]

  @type reason ::
          :invalid_store
          | :invalid_claim
          | :invalid_options
          | :store_unavailable
          | :store_timeout
          | :store_full
          | :store_failed
  @type t :: %__MODULE__{reason: reason(), retryable: false}
  @doc false
  def new(reason), do: %__MODULE__{reason: reason}
end
