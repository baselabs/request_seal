defmodule RequestSeal.Idempotency.Error do
  @moduledoc """
  A bounded request recovery failure. Inspection and telemetry carry no request
  or response bytes. Store timeouts can leave the reservation or write committed.
  """
  defstruct [:reason]

  @type reason ::
          :invalid_options
          | :invalid_message
          | :missing_idempotency_key
          | :invalid_idempotency_key
          | :invalid_policy
          | :invalid_record
          | :record_expired
          | :invalid_response
          | :store_unavailable
          | :store_timeout
          | :store_full
          | :store_failed

  @type t :: %__MODULE__{reason: reason()}
end
