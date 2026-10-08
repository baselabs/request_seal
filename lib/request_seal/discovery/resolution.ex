defmodule RequestSeal.Discovery.Resolution do
  @moduledoc """
  Public key and explicit discovery provenance. `key_id` is the selected
  lookup ID; `thumbprint` is always the computed cryptographic identity. `algorithm` is the selected
  cryptographic algorithm; `asserted_algorithm` is the source's HTTP token, if
  present. Neither the source nor a possession proof establishes a principal or
  authorizes an operation. Default inspection hides key material and provenance.
  `revision` is the resolved KeySet's SHA-256 revision, propagated by lookup.
  `expires_at` bounds the key/proof lifetime; KeySet separately bounds HTTP cache
  freshness. Access fields explicitly when applying caller trust policy.
  """
  @derive {Inspect, only: [:algorithm, :source_type, :proof]}
  defstruct [
    :key,
    :key_id,
    :thumbprint,
    :algorithm,
    :asserted_algorithm,
    :origin,
    :source_type,
    :location,
    :fetched_at,
    :expires_at,
    :proof,
    :revision
  ]

  @type t :: %__MODULE__{
          key: RequestSeal.PublicKey.t(),
          key_id: binary(),
          thumbprint: binary(),
          algorithm: RequestSeal.Crypto.algorithm(),
          asserted_algorithm: binary() | nil,
          origin: binary(),
          source_type: :directory | :jwks_uri | :cimd,
          location: binary(),
          fetched_at: integer(),
          expires_at: integer(),
          proof: :signed | :unsigned | :not_applicable,
          revision: binary() | nil
        }
end
