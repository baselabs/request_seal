defmodule RequestSeal.Replay.Error do
  @moduledoc """
  Bounded replay boundary failures, without adapter diagnostics or caller bytes.

  Reasons: `:invalid_store`, `:invalid_claim`, `:invalid_options`,
  `:store_unavailable`, `:store_timeout`, `:store_full`, `:store_failed`.
  `retryable` is always false: a timeout may have committed and is indeterminate.
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
