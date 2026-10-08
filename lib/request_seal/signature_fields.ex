defmodule RequestSeal.SignatureFields do
  @moduledoc false
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}
  alias RequestSeal.Message.Validation

  @derived ~w(@method @target-uri @authority @scheme @request-target @path @query @query-param @status)

  def schema(type, items \\ [:string], inner \\ true),
    do: %Schema{
      revision: :rfc8941,
      type: type,
      item_types: items,
      parameter_types: Schema.types(:rfc8941),
      inner_lists: inner
    }

  def algorithm?(algorithm) do
    algorithm in RequestSeal.Crypto.algorithms() or
      (is_tuple(algorithm) and tuple_size(algorithm) == 2 and elem(algorithm, 0) == :jws and
         elem(algorithm, 1) in ~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA))
  end

  def label?(label),
    do:
      is_binary(label) and byte_size(label) in 1..256 and
        Regex.match?(~r/\A[a-z*][a-z0-9_.*-]*\z/, label)

  def field_name?(name), do: Validation.token?(name, 256) and name == String.downcase(name)

  def inner(bytes) when is_binary(bytes) do
    case SF.parse(bytes, schema(:list)) do
      {:ok, %Value{value: [%Value{type: :inner_list} = value]}} -> inner(value)
      {:error, _} = error -> error
      _ -> :error
    end
  end

  def inner(%Value{type: :inner_list} = value) do
    case SF.serialize(%Value{type: :list, value: [value]}, schema(:list)) do
      {:ok, _} -> if valid_inner?(value), do: {:ok, value}, else: :error
      error -> error
    end
  end

  def inner(_), do: :error

  def valid_inner?(%Value{type: :inner_list, value: items, parameters: params}) do
    is_list(items) and length(items) <= 256 and Enum.all?(items, &component?/1) and
      length(identities(items)) == length(Enum.uniq(identities(items))) and
      Enum.all?(params, fn
        {key, {type, _}} when key in ["created", "expires"] -> type == :integer
        {key, {type, _}} when key in ["nonce", "alg", "keyid", "tag"] -> type == :string
        _ -> true
      end)
  end

  def valid_inner?(_), do: false

  defp component?(%Value{type: :item, value: {:string, name}, parameters: params}) do
    allowed =
      if name in @derived,
        do: if(name == "@query-param", do: ["req", "name"], else: ["req"]),
        else: ["sf", "key", "bs", "tr", "req"]

    (name in @derived or field_name?(name)) and
      Enum.all?(params, fn
        {key, {:boolean, true}} -> key in allowed and key in ["sf", "bs", "tr", "req"]
        {key, {:string, _}} -> key in allowed and key in ["key", "name"]
        _ -> false
      end) and (name != "@query-param" or List.keymember?(params, "name", 0)) and
      not (List.keymember?(params, "bs", 0) and
             (List.keymember?(params, "sf", 0) or List.keymember?(params, "key", 0)))
  end

  defp component?(_), do: false

  def identities(items),
    do:
      Enum.map(items, fn %Value{value: {:string, name}, parameters: params} ->
        {name, Enum.sort(params)}
      end)

  def identifiers(items),
    do:
      Enum.map(items, fn item ->
        {:ok, wire} = SF.serialize(item, schema(:item, [:string], false))
        wire
      end)

  def parameters(value), do: Map.new(value.parameters, fn {key, {_, value}} -> {key, value} end)
end
