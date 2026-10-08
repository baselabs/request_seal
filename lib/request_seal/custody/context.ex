defmodule RequestSeal.Custody.Context do
  @moduledoc """
  Absolute monotonic millisecond deadline and original caller PID.

  Custodians propagate `deadline` to all external work and honor caller death as
  cancellation. The custody boundary also terminates its worker on either event.
  Closing a client connection does not undo a signature already produced by a peer.
  """
  defstruct [:deadline, :owner]
  @type t :: %__MODULE__{deadline: integer(), owner: pid()}
  @doc "Remaining operation milliseconds; zero means the deadline has expired."
  @spec remaining(t()) :: non_neg_integer()
  def remaining(%__MODULE__{deadline: deadline}),
    do: max(0, deadline - System.monotonic_time(:millisecond))
end
