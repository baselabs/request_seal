defmodule RequestSeal.Custody.DeriveRequest do
  @moduledoc """
  A custody-only derivation request with a caller-owned, uncommitted child.

  `target` fixes the algorithm and, for ECDH-ES, the curve. `domain` is 1–255
  bytes and `capabilities` narrows the target family's defaults. The custodian
  gives the child its final `owner` immediately and the context's absolute
  commit deadline. No operation is usable before atomic `commit/3` succeeds.
  `token` is a 32-byte commitment capability, never key material. Inspection is
  redacted. Callers use `RequestSeal.Custody.derive/4`, not this callback input.
  """
  @derive {Inspect, only: []}
  defstruct [:target, :domain, :capabilities, :owner, :token]

  @type t :: %__MODULE__{
          target: %{
            algorithm: RequestSeal.Custody.algorithm(),
            curve: nil | binary()
          },
          domain: binary(),
          capabilities: [RequestSeal.Custody.capability()],
          owner: pid(),
          token: <<_::256>>
        }
end
