defmodule RequestSeal.Discovery.Address do
  @moduledoc false
  import Bitwise
  # Conservative denial of IANA special-purpose allocations (including globally
  # reachable special allocations), multicast and unallocated IPv6 space.
  @v4 [
    {0x00000000, 8},
    {0x0A000000, 8},
    {0x64400000, 10},
    {0x7F000000, 8},
    {0xA9FE0000, 16},
    {0xAC100000, 12},
    {0xC0000000, 24},
    {0xC0000200, 24},
    {0xC01FC400, 24},
    {0xC034C100, 24},
    {0xC0586300, 24},
    {0xC0A80000, 16},
    {0xC0AF3000, 24},
    {0xC6120000, 15},
    {0xC6336400, 24},
    {0xCB007100, 24},
    {0xE0000000, 4},
    {0xF0000000, 4}
  ]
  @v6 [
    {0x20010000000000000000000000000000, 23},
    {0x20010DB8000000000000000000000000, 32},
    {0x2620004F800000000000000000000000, 48},
    {0x3FFF0000000000000000000000000000, 20}
  ]
  def valid?(ip) when is_tuple(ip) and tuple_size(ip) in [4, 8] do
    max = if tuple_size(ip) == 4, do: 255, else: 65_535
    ip |> Tuple.to_list() |> Enum.all?(&(is_integer(&1) and &1 in 0..max))
  end

  def valid?(_), do: false

  def allowed?(ip, permitted) do
    valid?(ip) and (ip in permitted or public?(ip))
  end

  defp public?(ip) when tuple_size(ip) == 4 do
    n = number(ip, 8)
    not Enum.any?(@v4, fn {base, bits} -> prefix?(n, base, bits, 32) end)
  end

  defp public?({0, 0, 0, 0, 0, 0xFFFF, hi, lo}), do: public?(embedded(hi, lo))
  defp public?({0x64, 0xFF9B, 0, 0, 0, 0, hi, lo}), do: public?(embedded(hi, lo))
  defp public?({0x2002, hi, lo, _, _, _, _, _}), do: public?(embedded(hi, lo))

  defp public?(ip) do
    n = number(ip, 16)

    prefix?(n, 0x20000000000000000000000000000000, 3, 128) and
      not Enum.any?(@v6, fn {base, bits} -> prefix?(n, base, bits, 128) end)
  end

  defp embedded(hi, lo), do: {hi >>> 8, hi &&& 255, lo >>> 8, lo &&& 255}

  defp number(ip, width),
    do: ip |> Tuple.to_list() |> Enum.reduce(0, fn n, acc -> (acc <<< width) + n end)

  defp prefix?(n, base, bits, width), do: n >>> (width - bits) == base >>> (width - bits)
end
