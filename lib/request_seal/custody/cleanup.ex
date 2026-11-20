defmodule RequestSeal.Custody.Cleanup do
  @moduledoc """
  Caller-owned release capability for a possibly committed child.

  Returned only when a lost commit result is followed by unconfirmed destruction.
  Call `RequestSeal.Custody.cleanup/2` until it returns `:ok`; success confirms
  the child is destroyed or never existed. This grants no signing, verification,
  wrapping, unwrapping, derivation, or public metadata access. Inspection shows
  only `#RequestSeal.Custody.Cleanup<>`, with no custodian or reference.
  """
  defstruct [:custodian, :ref]
  @opaque t :: %__MODULE__{custodian: module(), ref: term()}
end

defimpl Inspect, for: RequestSeal.Custody.Cleanup do
  def inspect(_, _), do: "#RequestSeal.Custody.Cleanup<>"
end
