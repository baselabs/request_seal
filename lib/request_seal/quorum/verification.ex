defmodule RequestSeal.Quorum.Verification do
  @moduledoc """
  An admitted quorum. `assignments` maps configured slots to their
  successful single-signature results. `count` measures the configured unit,
  which can differ from the number of filled slots. `replay` is the one
  composite claim receipt. Authorization and principal attribution stay with
  the caller. `negotiation` describes whether supplied signature requests were fulfilled.
  """
  alias RequestSeal.Replay.Receipt

  @derive {Inspect, only: [:count, :replay, :authorization]}
  @enforce_keys [:assignments, :count, :replay]
  defstruct @enforce_keys ++
              [
                negotiation: :not_requested,
                principal: :unattributed,
                authorization: :not_evaluated
              ]

  @type t :: %__MODULE__{
          assignments: %{atom() => RequestSeal.Verification.t()},
          count: 1..16,
          replay: Receipt.t(),
          negotiation: :not_requested | :fulfilled,
          principal: :unattributed,
          authorization: :not_evaluated
        }
end
