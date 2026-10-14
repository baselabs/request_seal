defmodule RequestSeal.Replay.Store do
  @moduledoc """
  Caller-owned replay adapter and reference. Importing it starts nothing.

  `adapter` is a module implementing the `RequestSeal.Replay` callbacks and `ref`
  is that adapter's reference. Build stores with `RequestSeal.Replay.ETS.store/1`,
  `RequestSeal.Replay.Postgres.store/2` or `RequestSeal.Replay.AshOnetime.store/2`.
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
