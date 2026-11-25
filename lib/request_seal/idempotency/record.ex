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
  def valid?(
        %__MODULE__{
          namespace: namespace,
          principal: principal,
          key: key,
          fingerprint: <<_::256>>,
          now: now,
          lease_until: lease_until,
          retain_until: retain_until
        } = record
      ) do
    map_size(record) == 8 and Claim.bounded?(namespace) and Claim.bounded?(principal) and
      Claim.bounded?(key) and is_integer(now) and is_integer(lease_until) and
      is_integer(retain_until) and now >= 0 and (lease_until - now) in 1..300 and
      lease_until <= retain_until and retain_until <= 253_402_300_799
  end

  def valid?(_), do: false

  @doc false
  def key(record), do: {record.namespace, record.principal, record.key}
end
