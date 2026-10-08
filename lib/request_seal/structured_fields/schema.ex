defmodule RequestSeal.StructuredFields.Schema do
  @moduledoc """
  Explicit field type restrictions and RFC revision (RFC 9651 Section 2).

  `new/1` requires a map containing `:revision` (`:rfc8941` or `:rfc9651`),
  `:type` (`:item`, `:list`, or `:dictionary`), and nonempty `:item_types`.
  Bare types are `:integer`, `:decimal`, `:string`, `:token`, `:bytes`, and
  `:boolean`; RFC 9651 additionally allows `:date` and `:display_string`.
  `:inner_lists` defaults to false. `:parameter_types` defaults to all types
  in the selected revision. These restrictions apply to every item, including
  inner-list items, and every parameter, respectively. Unknown options reject.

  This is a type schema, not a complete field protocol or profile. The caller
  selects it from the field's normative specification and checks any additional
  semantic rules. No field name or recognized syntax selects a newer revision.
  Directly constructed schemas undergo the same validation at each entry point.
  """
  alias RequestSeal.StructuredFields.Error
  defstruct [:revision, :type, :item_types, :parameter_types, inner_lists: false]

  @type bare_type ::
          :integer | :decimal | :string | :token | :bytes | :boolean | :date | :display_string
  @type t :: %__MODULE__{
          revision: :rfc8941 | :rfc9651,
          type: :item | :list | :dictionary,
          item_types: [bare_type()],
          parameter_types: [bare_type()],
          inner_lists: boolean()
        }
  @base [:integer, :decimal, :string, :token, :bytes, :boolean]
  @doc "Types defined by the selected revision; invalid revisions return an empty list."
  def types(:rfc8941), do: @base
  def types(:rfc9651), do: @base ++ [:date, :display_string]
  def types(_), do: []

  @doc "Construct an explicit type schema; no revision or item-type defaults."
  @spec new(map()) :: {:ok, t()} | {:error, Error.t()}
  def new(attrs) when is_map(attrs) do
    if Enum.all?([:revision, :type, :item_types], &Map.has_key?(attrs, &1)) and
         Enum.all?(
           Map.keys(attrs),
           &(&1 in [:revision, :type, :item_types, :parameter_types, :inner_lists])
         ) do
      schema = struct(__MODULE__, Map.put_new(attrs, :parameter_types, types(attrs.revision)))

      case validate(schema) do
        :ok -> {:ok, schema}
        error -> error
      end
    else
      {:error, %Error{reason: :invalid_schema}}
    end
  end

  def new(_), do: {:error, %Error{reason: :invalid_schema}}

  @doc "Validate revision, top-level type, and all bare-type restrictions."
  @spec validate(term()) :: :ok | {:error, Error.t()}
  def validate(%__MODULE__{} = s) do
    allowed = types(Map.get(s, :revision))

    if Enum.sort(Map.keys(s)) == Enum.sort(Map.keys(%__MODULE__{})) and allowed != [] and
         s.type in [:item, :list, :dictionary] and
         is_boolean(s.inner_lists) and type_list?(s.item_types, allowed, false) and
         type_list?(s.parameter_types, allowed, true),
       do: :ok,
       else: {:error, %Error{reason: :invalid_schema}}
  end

  def validate(_), do: {:error, %Error{reason: :invalid_schema}}
  defp type_list?(list, allowed, empty), do: type_list?(list, allowed, empty, MapSet.new(), 0)
  defp type_list?([], _, empty, _, count), do: empty or count > 0

  defp type_list?([type | rest], allowed, empty, seen, count) when count < 8 do
    type in allowed and not MapSet.member?(seen, type) and
      type_list?(rest, allowed, empty, MapSet.put(seen, type), count + 1)
  end

  defp type_list?(_, _, _, _, _), do: false
end
