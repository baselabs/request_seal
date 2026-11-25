defmodule RequestSeal.Idempotency.Reservation do
  @moduledoc """
  The current reservation to pass to `RequestSeal.Idempotency.store/4`.
  Adapters fence completion with the token so a replaced lease cannot write.
  """
  alias RequestSeal.Idempotency.Record

  @derive {Inspect, only: []}
  @enforce_keys [:record, :token]
  defstruct @enforce_keys
  @type t :: %__MODULE__{record: Record.t(), token: <<_::128>>}
end
