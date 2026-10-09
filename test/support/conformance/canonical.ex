defmodule RequestSeal.Conformance.Canonical do
  @moduledoc false
  # RFC 8785's I-JSON string/array/object encoding, with the corpus's explicit
  # number tags. Bare host numbers cannot silently become wire values.
  def encode(nil), do: "null"
  def encode(true), do: "true"
  def encode(false), do: "false"

  def encode(value) when is_binary(value) do
    true = String.valid?(value)
    :json.encode(value) |> IO.iodata_to_binary()
  end

  def encode(value) when is_list(value), do: "[" <> Enum.map_join(value, ",", &encode/1) <> "]"

  def encode(value) when is_map(value) and not is_struct(value) do
    entries =
      Enum.sort_by(value, fn {key, _} ->
        :unicode.characters_to_binary(key, :utf8, {:utf16, :big})
      end)

    "{" <> Enum.map_join(entries, ",", fn {k, v} -> encode(k) <> ":" <> encode(v) end) <> "}"
  end

  def encode(value), do: raise(ArgumentError, "corpus numbers require tags: #{inspect(value)}")
end
