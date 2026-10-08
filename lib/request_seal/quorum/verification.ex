defmodule RequestSeal.Quorum.Verification do
  @moduledoc """
  Complete composite verification facts, returned only after all selected checks.

  `mode`, `unit`, and `required` preserve the configured policy; `satisfied`
  lists qualifying slots in configured order. `count` counts deduplicated trusted
  units, never labels. `qualifying` records label/slot and caller counting
  bindings (principal/role); these are not authenticated attribution. `signatures`
  retains each qualifying single-label result and its independent coverage.
  `nonqualifying` records bounded reason/layer atoms for ignored labels and failed
  slot attempts. No key material or KeyIdentity is retained.

  `bindings` is `:not_required` or satisfied binding entries. `negotiation` is
  `:not_requested` or `:fulfilled`. `replay` stays `:not_required`, `principal`
  stays `:unattributed`, and `authorization` stays `:not_evaluated`.
  Default inspection omits labels, counting bindings, and signature metadata.
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
