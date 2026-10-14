defmodule RequestSeal.Message.Error do
  @moduledoc """
  Bounded message-construction errors. No supplied bytes appear in errors.

  Each reason names the layer that rejected the input:

    * `:invalid_message` - message attributes, builder options, or a builder URL.
    * `:invalid_field` - a field or trailer occurrence, or the combined field bound.
    * `:invalid_body` - a body availability snapshot.
    * `:invalid_transport` - transport declarations.

  They indicate invalid shapes, unknown keys or options, missing required values,
  inconsistent states, or exceeded documented bounds in that layer. Correct the
  input before retrying; no authentication has taken place.
  """
  @enforce_keys [:reason]
  defstruct [:reason]

  @type t :: %__MODULE__{
          reason: :invalid_message | :invalid_field | :invalid_body | :invalid_transport
        }
end
