defmodule RequestSeal.Custody.Support do
  @moduledoc false
  alias RequestSeal.Custody.Error
  def ensure(true, _), do: :ok
  def ensure(_, reason), do: throw({:custody_error, reason})

  def safe(fun, fallback \\ :invalid_key) do
    fun.()
  rescue
    _ -> {:error, Error.new(fallback)}
  catch
    {tag, reason} when tag in [:custody_error, :crypto_error] -> {:error, Error.new(reason)}
    _, _ -> {:error, Error.new(fallback)}
  end

  def unwrap({:ok, value}), do: value
  def unwrap(:ok), do: :ok
  def unwrap({:error, %{reason: reason}}), do: ensure(false, reason)
  def unwrap({:error, reason}) when is_atom(reason), do: ensure(false, reason)

  def options(opts, allowed) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options
    )

    opts
  end

  def timeout(opts, allowed \\ [:timeout]) do
    options(opts, allowed)
    value = Keyword.get(opts, :timeout, 5_000)
    ensure(is_integer(value) and value in 1..300_000, :invalid_options)
    value
  end

  def max_bytes(opts) do
    options(opts, [:timeout, :max_bytes])
    value = Keyword.get(opts, :max_bytes, 1_048_576)

    ensure(
      is_integer(value) and value in 1..RequestSeal.Crypto.max_bytes_ceiling(),
      :invalid_options
    )

    value
  end
end
