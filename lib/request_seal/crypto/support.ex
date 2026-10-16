defmodule RequestSeal.Crypto.Support do
  @moduledoc false
  alias RequestSeal.Crypto.Error

  def ensure(true, _reason), do: :ok
  def ensure(_, reason), do: throw({:crypto_error, reason})

  # Only OTP's own argument/runtime error classes map to the bounded reason.
  # Logic-defect classes (match/case/function-clause/key) and exits propagate to
  # the entry-point fault envelope instead of masking as input reasons.
  def safe(reason, fun) do
    fun.()
  rescue
    _error in [ArgumentError, ErlangError] -> {:error, %Error{reason: reason}}
  catch
    {:crypto_error, failure} -> {:error, %Error{reason: failure}}
  end

  def bounded_binary?(bytes, min, max),
    do: is_binary(bytes) and byte_size(bytes) >= min and byte_size(bytes) <= max
end
