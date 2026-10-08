defmodule RequestSeal.Message.Validation do
  @moduledoc false
  alias RequestSeal.Message.Error

  def error(reason), do: {:error, %Error{reason: reason}}

  def construct(attrs, module, required, reason) when is_map(attrs) do
    keys = Map.keys(module.__struct__()) -- [:__struct__]

    if not is_struct(attrs) and map_size(attrs) <= length(keys) and
         Enum.all?(Map.keys(attrs), &(&1 in keys)) and
         Enum.all?(required, &Map.has_key?(attrs, &1)) do
      value = struct(module, attrs)

      case module.validate(value) do
        :ok -> {:ok, value}
        error -> error
      end
    else
      error(reason)
    end
  end

  def construct(_, _, _, reason), do: error(reason)

  def exact_struct?(value, module), do: Map.keys(value) == Map.keys(module.__struct__())

  def token?(value, max) when is_binary(value) and byte_size(value) in 1..max//1,
    do: token_bytes?(value)

  def token?(_, _), do: false
  defp token_bytes?(<<>>), do: true

  defp token_bytes?(<<c, rest::binary>>)
       when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in ~c"!#$%&'*+-.^_`|~",
       do: token_bytes?(rest)

  defp token_bytes?(_), do: false

  def field_value?(value) when is_binary(value) and byte_size(value) <= 65_536,
    do: field_bytes?(value)

  def field_value?(_), do: false
  defp field_bytes?(<<>>), do: true

  defp field_bytes?(<<c, rest::binary>>) when c == 9 or c in 32..126 or c in 128..255,
    do: field_bytes?(rest)

  defp field_bytes?(_), do: false

  # RFC 3986 URI characters and pct-encoded octets, checked without decoding.
  def uri_bytes?(<<>>), do: true

  def uri_bytes?(<<?%, a, b, rest::binary>>) when a in ?0..?9 or a in ?a..?f or a in ?A..?F do
    (b in ?0..?9 or b in ?a..?f or b in ?A..?F) and uri_bytes?(rest)
  end

  def uri_bytes?(<<c, rest::binary>>)
      when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in ~c"-._~:/?[]@!$&'()*+,;=",
      do: uri_bytes?(rest)

  def uri_bytes?(_), do: false

  def scheme?(scheme) when is_binary(scheme) and byte_size(scheme) in 1..64,
    do: Regex.match?(~r/\A[A-Za-z][A-Za-z0-9+.-]*\z/, scheme)

  def scheme?(_), do: false

  def authority?(value, require_port \\ false)

  def authority?(value, require_port) when is_binary(value) and byte_size(value) in 1..1024 do
    case Regex.run(~r/\A(\[[^\]]+\]|[^:]+)(?::([0-9]+))?\z/, value) do
      [_, host, port] ->
        host?(host) and byte_size(port) <= 5 and String.to_integer(port) <= 65_535

      [_, host] ->
        not require_port and host?(host)

      _ ->
        false
    end
  end

  def authority?(_, _), do: false

  defp host?("[" <> rest) when byte_size(rest) >= 2 do
    if :binary.last(rest) == ?] do
      address = binary_part(rest, 0, byte_size(rest) - 1)

      match?({:ok, _}, :inet.parse_ipv6_address(:binary.bin_to_list(address))) or
        Regex.match?(~r/\Av[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+\z/, address)
    else
      false
    end
  end

  defp host?("[" <> _), do: false

  defp host?(host),
    do: Regex.match?(~r/\A(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+\z/, host)
end
