defmodule RequestSeal.Message.Error do
  @moduledoc """
  Bounded message-construction errors. No supplied bytes appear in errors.

  Reasons are `:invalid_message`, `:invalid_field`, `:invalid_body`, and
  `:invalid_transport`. They indicate invalid shapes, unknown options, missing
  required evidence, inconsistent states, or exceeded documented bounds in that
  layer. Correct the input before retrying; no authentication has taken place.
  """
  @enforce_keys [:reason]
  defstruct [:reason]

  @type t :: %__MODULE__{
          reason: :invalid_message | :invalid_field | :invalid_body | :invalid_transport
        }
end
