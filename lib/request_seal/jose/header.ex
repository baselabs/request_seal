defmodule RequestSeal.JOSE.Header do
  @moduledoc false
  import RequestSeal.JOSE.Support

  def parse(segment) do
    ensure(byte_size(segment) <= 21_846, :limit)
    bytes = decode(segment)
    json(bytes)
  end

  def json(bytes) do
    h = json_object(bytes)
    reject(h)
    h
  end

  def from_pairs(pairs) do
    ensure(is_list(pairs) and length(pairs) <= 64, :limit)

    h =
      Enum.reduce(pairs, %{}, fn
        {k, v}, acc when is_binary(k) ->
          ensure(not Map.has_key?(acc, k), :duplicate_member)
          Map.put(acc, k, v)

        _, _ ->
          fail(:invalid_header)
      end)

    structural_depth(h, 0)
    tree(h)
    reject(h)
    h
  end

  defp structural_depth(v, d) when is_map(v) or is_list(v) do
    ensure(d < 4, :limit)
    values = if is_map(v), do: Map.values(v), else: v
    Enum.each(values, &structural_depth(&1, d + 1))
  end

  defp structural_depth(_, _), do: :ok

  def serialize(pairs) do
    h = from_pairs(pairs)
    parts = Enum.map(pairs, fn {k, v} -> [json_value(k), ":", json_value(v)] end)
    # Compact JSON serialization preserves caller member order.
    bytes = IO.iodata_to_binary(["{", Enum.intersperse(parts, ","), "}"])
    ensure(byte_size(bytes) <= 16_384, :limit)
    {b64(bytes), h}
  end

  defp json_value(v), do: :json.encode(json_null(v))
  defp json_null(nil), do: :null
  defp json_null(v) when is_map(v), do: Map.new(v, fn {k, x} -> {k, json_null(x)} end)
  defp json_null(v) when is_list(v), do: Enum.map(v, &json_null/1)
  defp json_null(v), do: v

  defp reject(h) do
    ensure(not Map.has_key?(h, "zip"), :compression_unsupported)
    ensure(not Map.has_key?(h, "crit"), :unsupported_critical_header)
    ensure(not Enum.any?(~w(jku x5u jwk b64), &Map.has_key?(h, &1)), :unsupported_header)
    ensure(is_binary(h["alg"]), :invalid_header)
  end
end
