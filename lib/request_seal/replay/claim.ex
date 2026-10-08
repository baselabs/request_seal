defmodule RequestSeal.Replay.Claim do
  @moduledoc "Bounded caller uniqueness and exclusive retention end in Unix seconds."
  @derive {Inspect, only: [:retain_until]}
  defstruct [:namespace, :key, :retain_until]
  @type t :: %__MODULE__{namespace: binary(), key: binary(), retain_until: integer()}
  @doc false
  def valid?(%__MODULE__{namespace: namespace, key: key, retain_until: until} = claim),
    do:
      map_size(claim) == 4 and bounded?(namespace) and bounded?(key) and
        is_integer(until) and until in -9_223_372_036_854_775_808..9_223_372_036_854_775_807

  def valid?(_), do: false
  @doc false
  def bounded?(bytes), do: is_binary(bytes) and byte_size(bytes) in 1..256
end
