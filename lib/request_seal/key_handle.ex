defmodule RequestSeal.KeyHandle do
  @moduledoc """
  Caller-owned, algorithm-bound signing or secret-bearing verification capability.

  Construct handles through a custodian such as `RequestSeal.Custody.Local` or
  `RequestSeal.Custody.SSHAgent`. Only that custodian interprets `ref`. Local
  references contain only a holder PID and token, never key material. The holder
  is sensitive and lives until `RequestSeal.Custody.Local.release/1` or creator exit,
  including after handle transfer. Dropping a handle does not stop its holder.
  A long-lived owner such as a GenServer must release handles it no longer needs,
  or create handles once at startup and reuse them for its lifetime.

  Loading the library starts no process or store. Local construction starts one
  holder per handle. An asymmetric public key is obtained through
  `RequestSeal.Custody.public_key/1`; HMAC has no public export.
  """
  @derive {Inspect, only: [:custodian, :algorithm, :capabilities]}
  defstruct [:custodian, :algorithm, :capabilities, :ref]

  @type t :: %__MODULE__{
          custodian: module(),
          algorithm: RequestSeal.Crypto.algorithm(),
          capabilities: [:sign | :verify],
          ref: (-> term())
        }
end
