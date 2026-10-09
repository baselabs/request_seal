defmodule RequestSeal.Conformance.StructuredFields do
  @moduledoc false
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}
  @types [:integer, :decimal, :string, :token, :bytes, :boolean, :date, :display_string]

  def schema(type, revision \\ "rfc9651") do
    revision = String.to_existing_atom(revision)

    {:ok, s} =
      Schema.new(%{
        type: String.to_existing_atom(type),
        revision: revision,
        item_types:
          if(revision == :rfc8941, do: @types -- [:date, :display_string], else: @types),
        inner_lists: true
      })

    s
  end

  def item(v, pins) do
    s = schema(v["header_type"])
    choice = if v["can_fail"] == true, do: Map.fetch!(pins, v["name"])["outcome"]

    parsing =
      if Map.has_key?(v, "raw") do
        result = SF.parse(Enum.join(v["raw"], ", "), s)

        cond do
          v["must_fail"] == true or choice == "reject" ->
            error?(result)

          true ->
            case result do
              {:ok, value} ->
                equivalent(value, expected(v["expected"], v["header_type"])) and
                  SF.serialize(value, s) ==
                    {:ok, Enum.join(Map.get(v, "canonical", v["raw"]), ", ")}

              _ ->
                false
            end
        end
      else
        true
      end

    serialization =
      if Map.has_key?(v, "expected") do
        actual = SF.serialize(expected(v["expected"], v["header_type"]), s)

        if v["must_fail"] == true,
          do: error?(actual),
          else: actual == {:ok, Enum.join(Map.get(v, "canonical", Map.get(v, "raw", [])), ", ")}
      else
        true
      end

    parsing and serialization
  end

  defp error?({:error, %SF.Error{}}), do: true
  defp error?(_), do: false

  def expected(values, "dictionary"),
    do: %Value{type: :dictionary, value: Enum.map(values, fn [k, v] -> {k, member(v)} end)}

  def expected(values, "list"), do: %Value{type: :list, value: Enum.map(values, &member/1)}
  def expected(value, "item"), do: member(value)

  defp member([values, params]) when is_list(values),
    do: %Value{
      type: :inner_list,
      value: Enum.map(values, &member/1),
      parameters: parameters(params)
    }

  defp member([value, params]),
    do: %Value{type: :item, value: bare(value), parameters: parameters(params)}

  defp parameters(params), do: Enum.map(params, fn [k, v] -> {k, bare(v)} end)

  def bare(%{"__type" => "binary", "value" => value}),
    do: {:bytes, Base.decode32!(value, padding: true)}

  def bare(%{"__type" => "displaystring", "value" => value}), do: {:display_string, value}
  def bare(%{"__type" => type, "value" => value}), do: {String.to_existing_atom(type), value}
  def bare(value) when is_boolean(value), do: {:boolean, value}
  def bare(value) when is_integer(value), do: {:integer, value}
  def bare(value) when is_binary(value), do: {:string, value}

  def bare(value) when is_float(value) do
    [mantissa | exponent] = String.split(Float.to_string(value), "e")

    exponent =
      case exponent do
        [] -> 0
        [n] -> String.to_integer(n)
      end

    [whole, fractional] = String.split(mantissa, ".")
    coefficient = String.to_integer(whole <> fractional)
    scale = byte_size(fractional) - exponent

    {:decimal,
     if(scale < 0, do: {coefficient * Integer.pow(10, -scale), 0}, else: {coefficient, scale})}
  end

  defp equivalent(%Value{type: t, value: a, parameters: ap}, %Value{
         type: t,
         value: b,
         parameters: bp
       }),
       do: equivalent(a, b) and equivalent(ap, bp)

  defp equivalent({:decimal, {a, x}}, {:decimal, {b, y}}),
    do: a * Integer.pow(10, y) == b * Integer.pow(10, x)

  defp equivalent({k, a}, {k, b}), do: equivalent(a, b)

  defp equivalent(a, b) when is_list(a) and is_list(b),
    do: length(a) == length(b) and Enum.zip(a, b) |> Enum.all?(fn {x, y} -> equivalent(x, y) end)

  defp equivalent(a, b), do: a == b
end
