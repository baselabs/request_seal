defmodule RequestSeal.JOSE.JWE.Result do
  @moduledoc "Authenticated compact JWE plaintext. Recipient integrity establishes no origin or principal."
  @derive {Inspect,
           only: [
             :algorithm,
             :encryption,
             :recipient_integrity,
             :origin,
             :principal,
             :authorization
           ]}
  defstruct [
    :algorithm,
    :encryption,
    :header,
    :protected,
    :plaintext,
    recipient_integrity: :valid,
    origin: :unbound,
    principal: :unattributed,
    authorization: :not_evaluated
  ]

  @type t :: %__MODULE__{
          algorithm: binary(),
          encryption: binary(),
          header: map(),
          protected: binary(),
          plaintext: binary(),
          recipient_integrity: :valid,
          origin: :unbound,
          principal: :unattributed,
          authorization: :not_evaluated
        }
end
