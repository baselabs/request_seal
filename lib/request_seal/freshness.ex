defmodule RequestSeal.Freshness do
  @moduledoc false

  @max_second 253_402_300_799

  def read(clock) do
    interval(clock.())
  catch
    _, _ -> {:error, :invalid_clock}
  end

  def interval(now) when is_integer(now) and now in 0..@max_second, do: {:ok, {now, now}}

  def interval({lower, upper} = bounds)
      when is_integer(lower) and is_integer(upper) and lower >= 0 and upper <= @max_second and
             lower <= upper,
      do: {:ok, bounds}

  def interval(_), do: {:error, :invalid_clock}

  def check(params, policy, {lower, upper}) do
    created = params["created"]
    expires = params["expires"]
    earliest = max(upper - policy.skew, created || upper - policy.skew)

    # Creation is hardest to satisfy at the lower endpoint. Expiration and
    # maximum age are hardest at the upper endpoint, even with clock skew.
    cond do
      policy.max_age != nil and created == nil ->
        {:error, :missing_created}

      policy.require_expires and expires == nil ->
        {:error, :missing_expires}

      created != nil and created > lower + policy.skew ->
        {:error, :created_in_future}

      expires != nil and expires <= earliest ->
        {:error, :expired}

      policy.max_age != nil and earliest > created + policy.max_age ->
        {:error, :too_old}

      true ->
        {:ok,
         %{
           now: upper,
           created: created,
           expires: expires,
           max_age: policy.max_age,
           skew: policy.skew
         }}
    end
  end
end
