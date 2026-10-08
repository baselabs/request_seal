defmodule RequestSeal.Crypto.Support do
  @moduledoc false
  alias RequestSeal.Crypto.Error
  def ensure(true, _reason), do: :ok
  def ensure(_, reason), do: throw({:crypto_error, reason})

  def safe(reason, fun) do
    fun.()
  rescue
    _ -> {:error, %Error{reason: reason}}
  catch
    {:crypto_error, failure} -> {:error, %Error{reason: failure}}
    _, _ -> {:error, %Error{reason: reason}}
  end

  def bounded_binary?(bytes, min, max),
    do: is_binary(bytes) and byte_size(bytes) >= min and byte_size(bytes) <= max
end
