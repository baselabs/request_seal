defmodule RequestSeal.Replay.Claim do
  @moduledoc """
  Bounded caller uniqueness and exclusive retention end in Unix seconds.

  Retention ends above 253,402,300,799 reject because no accepted sweep clock
  can evict them. Stores reject invalid claims with their existing failure.
  """
  @derive {Inspect, only: [:retain_until]}
  defstruct [:namespace, :key, :retain_until]
  @type t :: %__MODULE__{namespace: binary(), key: binary(), retain_until: integer()}
  @doc """
  Validate the bounded shape of a replay claim without claiming or storing it.

  Requires exactly a `RequestSeal.Replay.Claim` struct with `namespace` and `key`
  binaries of 1–256 bytes each and `retain_until` from -9,223,372,036,854,775,808
  through 253,402,300,799. Negative ends remain valid already-expired claims.
  Binaries need not be UTF-8. Other values, maps, and structs with extra fields
  return false. Validation does not check a clock, require a future retention
  end, derive uniqueness, or establish replay protection. Stores enforce the
  exclusive Unix-second retention end when claiming.

      iex> claim = %RequestSeal.Replay.Claim{namespace: "scope", key: "nonce", retain_until: 0}
      iex> RequestSeal.Replay.Claim.valid?(claim)
      true
      iex> RequestSeal.Replay.Claim.valid?(%{claim | key: ""})
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{namespace: namespace, key: key, retain_until: until} = claim),
    do:
      map_size(claim) == 4 and bounded?(namespace) and bounded?(key) and
        is_integer(until) and until in -9_223_372_036_854_775_808..253_402_300_799

  def valid?(_), do: false
  @doc false
  def bounded?(bytes), do: is_binary(bytes) and byte_size(bytes) in 1..256
end
