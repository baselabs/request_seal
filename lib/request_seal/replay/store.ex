defmodule RequestSeal.Replay.Store do
  @moduledoc """
  Caller-owned replay adapter and reference. Importing it starts nothing.

  `adapter` is a module implementing the `RequestSeal.Replay` callbacks and `ref`
  is that adapter's reference. Stores enforce a monotonic sweep cutoff within
  their storage authority, returning `{:error, :failure}` for a claim whose
  exclusive retention end is at or before that cutoff. The cutoff check and
  claim admission are atomic with respect to sweeps. Build stores with
  `RequestSeal.Replay.ETS.store/1`, `RequestSeal.Replay.Postgres.store/2` or
  `RequestSeal.Replay.AshOnetime.store/2`.
  Use `RequestSeal.Replay.Pair.store/2` during a migration.
  """
  @derive {Inspect, only: [:adapter]}
  defstruct [:adapter, :ref]
  @type t :: %__MODULE__{adapter: module(), ref: term()}

  @doc false
  def valid?(%__MODULE__{adapter: adapter} = store) do
    map_size(store) == 3 and is_atom(adapter) and Code.ensure_loaded?(adapter) and
      function_exported?(adapter, :claim, 3) and function_exported?(adapter, :sweep, 3)
  end

  def valid?(_), do: false
end
