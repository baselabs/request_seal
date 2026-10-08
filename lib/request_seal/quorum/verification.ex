defmodule RequestSeal.Quorum.Verification do
  @moduledoc """
  Complete composite verification facts, returned only after all selected checks.

  `mode` and `unit` preserve the configured policy; `required` lists only required
  slot IDs, while `satisfied` includes assigned required and optional slots in
  configured order. `count` counts deduplicated trusted units, never labels. `qualifying` records label/slot and caller counting
  bindings (principal/role); these are not authenticated attribution. `signatures`
  is a label-keyed map of assigned single-label results and their independent
  coverage. A negotiated label can fulfill a challenge without being assigned;
  such a label is absent from this map and `qualifying`.
  `nonqualifying` records bounded reason/layer atoms for ignored labels and failed
  slot attempts. No key material or KeyIdentity is retained.

  `bindings` is `:not_required` or satisfied binding entries. `negotiation` is
  `:not_requested` or `:fulfilled`. `replay` stays `:not_required`, `principal`
  stays `:unattributed`, and `authorization` stays `:not_evaluated`.
  Default inspection includes required/satisfied slot IDs and count but omits
  signature labels, counting bindings, signature metadata, and negotiation details.
  """
  @derive {Inspect,
           only: [
             :profile,
             :mode,
             :unit,
             :required,
             :satisfied,
             :count,
             :replay,
             :principal,
             :authorization
           ]}
  defstruct [
    :profile,
    :mode,
    :unit,
    :required,
    :satisfied,
    :count,
    :qualifying,
    :signatures,
    :nonqualifying,
    :bindings,
    :negotiation,
    replay: :not_required,
    principal: :unattributed,
    authorization: :not_evaluated
  ]

  @type t :: %__MODULE__{
          profile: %{name: :rfc9421},
          mode: term(),
          unit: term(),
          required: [atom()],
          satisfied: [atom()],
          count: non_neg_integer(),
          qualifying: [map()],
          signatures: %{binary() => RequestSeal.Verification.t()},
          nonqualifying: [map()],
          bindings: :not_required | [term()],
          negotiation: :not_requested | :fulfilled,
          replay: :not_required,
          principal: :unattributed,
          authorization: :not_evaluated
        }
end
