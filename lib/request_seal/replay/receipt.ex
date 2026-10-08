defmodule RequestSeal.Replay.Receipt do
  @moduledoc "Successful atomic claim; contains no namespace, uniqueness value, or store reference."
  defstruct [:store, :retain_until]
  @type t :: %__MODULE__{store: module(), retain_until: integer()}
end
