defmodule RequestSeal.WebBotAuth.Verification do
  @moduledoc """
  Complete protocol-00 envelope facts after every selected signature succeeds.

  `signatures` maps labels to `RequestSeal.Verification`; each records the exact
  profile revision and either an agent principal with trusted source provenance
  or a held-key thumbprint. `evidence` records inner labels whose entire component
  sets the outer signature covers, without implying delegation or authorization.
  `ignored` contains labels outside this profile. `replay` is one whole-envelope
  receipt or `:not_required`; authorization is always `:not_evaluated`.
  Inspection omits principals, key IDs, parameters, and source URLs.
  """
  defstruct [
    :profile,
    :signatures,
    :evidence,
    ignored: [],
    replay: :not_required,
    authorization: :not_evaluated
  ]

  @type t :: %__MODULE__{
          profile: map(),
          signatures: %{binary() => RequestSeal.Verification.t()},
          evidence: %{binary() => [binary()]},
          ignored: [binary()],
          replay: :not_required | RequestSeal.Replay.Receipt.t(),
          authorization: :not_evaluated
        }
end

defimpl Inspect, for: RequestSeal.WebBotAuth.Verification do
  import Inspect.Algebra

  def inspect(value, opts) do
    labels =
      if is_map(value.signatures), do: value.signatures |> Map.keys() |> Enum.sort(), else: []

    facts = [
      profile: value.profile,
      labels: labels,
      replay: value.replay,
      authorization: value.authorization
    ]

    concat(["#RequestSeal.WebBotAuth.Verification<", to_doc(facts, opts), ">"])
  end
end
