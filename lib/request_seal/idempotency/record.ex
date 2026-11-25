defmodule RequestSeal.Idempotency.Record do
  @moduledoc """
  Scoped request fingerprint and exclusive lease and retention ends, in Unix
  seconds. Build records through `RequestSeal.Idempotency.prepare/4`.
  """
  alias RequestSeal.Replay.Claim

  @derive {Inspect, only: [:lease_until, :retain_until]}
  @enforce_keys [:namespace, :principal, :key, :fingerprint, :now, :lease_until, :retain_until]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          namespace: binary(),
          principal: binary(),
          key: binary(),
          fingerprint: <<_::256>>,
          now: non_neg_integer(),
          lease_until: pos_integer(),
          retain_until: pos_integer()
        }

  @doc false
  def valid?(%__MODULE__{} = record) do
    map_size(record) == 8 and Claim.bounded?(record.namespace) and
      Claim.bounded?(record.principal) and
      Claim.bounded?(record.key) and match?(<<_::256>>, record.fingerprint) and
      is_integer(record.now) and is_integer(record.lease_until) and
      is_integer(record.retain_until) and
      record.now >= 0 and (record.lease_until - record.now) in 1..300 and
      record.lease_until <= record.retain_until and record.retain_until <= 253_402_300_799
  end

  def valid?(_), do: false

  @doc false
  def key(record), do: {record.namespace, record.principal, record.key}
end
