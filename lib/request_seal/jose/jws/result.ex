defmodule RequestSeal.JOSE.JWS.Result do
  @moduledoc "Verified compact JWS. Header, protected segment and payload require explicit access."
  @derive {Inspect, only: [:algorithm, :crypto, :principal, :authorization]}
  defstruct [
    :algorithm,
    :header,
    :protected,
    :payload,
    crypto: :valid,
    principal: :unattributed,
    authorization: :not_evaluated
  ]

  @type t :: %__MODULE__{
          algorithm: binary(),
          header: map(),
          protected: binary(),
          payload: binary(),
          crypto: :valid,
          principal: :unattributed,
          authorization: :not_evaluated
        }
end
