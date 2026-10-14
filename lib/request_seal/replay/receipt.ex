defmodule RequestSeal.Replay.Receipt do
  @moduledoc """
  Successful atomic claim; contains no namespace, uniqueness value, or store reference.

  `store` is the adapter module that stored the claim, and `retain_until` is the
  claim's exclusive retention end in Unix seconds.
  """
  defstruct [:store, :retain_until]
  @type t :: %__MODULE__{store: module(), retain_until: integer()}
end
