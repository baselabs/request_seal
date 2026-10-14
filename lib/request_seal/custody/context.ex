defmodule RequestSeal.Custody.Context do
  @moduledoc """
  Absolute monotonic millisecond deadline and original caller PID.

  Custodians propagate `deadline` to all external work and honor caller death as
  cancellation. The custody boundary also terminates its worker on either event.
  Closing a client connection does not undo a signature already produced by a peer.
  """
  defstruct [:deadline, :owner]
  @type t :: %__MODULE__{deadline: integer(), owner: pid()}
  @doc """
  Remaining operation milliseconds; zero means the deadline has expired.

  ## Parameters

    * `context` - a `t:t/0` whose `deadline` is an integer in
      `System.monotonic_time(:millisecond)` units.

  ## Returns

    * a non-negative integer: `deadline` minus the current monotonic time in
      milliseconds, or `0` once the deadline has passed. This function returns
      no error tuple; an argument that is not a context struct raises
      `FunctionClauseError`.

  ## Examples

      iex> context = %RequestSeal.Custody.Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
      iex> RequestSeal.Custody.Context.remaining(context) in 1..5_000
      true
      iex> expired = %RequestSeal.Custody.Context{owner: self(), deadline: System.monotonic_time(:millisecond) - 10}
      iex> RequestSeal.Custody.Context.remaining(expired)
      0
  """
  @spec remaining(t()) :: non_neg_integer()
  def remaining(%__MODULE__{deadline: deadline}),
    do: max(0, deadline - System.monotonic_time(:millisecond))
end
