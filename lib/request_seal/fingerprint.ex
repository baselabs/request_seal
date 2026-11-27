defmodule RequestSeal.Fingerprint do
  @moduledoc """
  SHA-256 over a domain followed by an ordered sequence of length-prefixed fields.
  Choose one domain per application purpose and keep the field order fixed.
  Framing commits to byte boundaries. A digest alone supplies no authentication.
  """

  @max_field 1_048_576

  @doc """
  Hash a printable ASCII domain of 1–64 bytes followed by 1–256 binary fields.
  Each field is at most 1 MiB. The prefix of each field is its unsigned 32-bit
  big-endian byte count. Invalid domains or fields return `{:error, :invalid_input}`.

      iex> alias RequestSeal.Fingerprint
      iex> {:ok, digest} = Fingerprint.digest("example v1", ["ab", "c"])
      iex> digest == :crypto.hash(:sha256, ["example v1", <<2::32, "ab", 1::32, "c">>])
      true
  """
  @spec digest(binary(), [binary()]) :: {:ok, <<_::256>>} | {:error, :invalid_input}
  def digest(domain, fields) do
    with true <- domain?(domain),
         {:ok, data} <- frame(fields, 256 * @max_field) do
      {:ok, :crypto.hash(:sha256, [domain | data])}
    else
      _ -> {:error, :invalid_input}
    end
  end

  @doc """
  Prefix a binary of up to 2^32 - 1 bytes with its unsigned big-endian byte count.
  """
  @spec prefixed(binary()) :: binary()
  def prefixed(bytes) when is_binary(bytes) and byte_size(bytes) <= 0xFFFF_FFFF,
    do: <<byte_size(bytes)::32, bytes::binary>>

  @doc """
  Read one prefixed field with a caller-selected maximum size (default 1 MiB).
  Returns the decoded field and remaining bytes, or `:error` for invalid input.
  """
  @spec read_prefixed(binary(), non_neg_integer()) :: {:ok, binary(), binary()} | :error
  def read_prefixed(bytes, max \\ @max_field)

  def read_prefixed(<<size::32, rest::binary>>, max)
      when is_integer(max) and size <= max and byte_size(rest) >= size do
    <<field::binary-size(^size), tail::binary>> = rest
    {:ok, field, tail}
  end

  def read_prefixed(_, _), do: :error

  @doc false
  def domain?(domain) when is_binary(domain) and byte_size(domain) in 1..64,
    do: Enum.all?(:binary.bin_to_list(domain), &(&1 in 32..126))

  def domain?(_), do: false

  @doc false
  def mac_label?(label) do
    domain?(label) and :binary.match(label, " ") != :nomatch and
      not String.starts_with?(label, [~s["], "request-seal "])
  end

  @doc false
  def frame(fields, max_total), do: frame(fields, max_total, 256, [])

  defp frame([], _, _, [_ | _] = framed), do: {:ok, Enum.reverse(framed)}

  defp frame([field | rest], remaining, count, framed)
       when count > 0 and is_binary(field) and byte_size(field) <= @max_field and
              byte_size(field) <= remaining do
    size = byte_size(field)
    frame(rest, remaining - size, count - 1, [[<<size::32>>, field] | framed])
  end

  defp frame(_, _, _, _), do: :error
end
