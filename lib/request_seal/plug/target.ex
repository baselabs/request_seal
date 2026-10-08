if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Target do
    @moduledoc false
    alias RequestSeal.{SignatureFields, StructuredFields}
    alias RequestSeal.StructuredFields.Value

    @dependent ~w(@request-target @target-uri @query)

    # Plug's split path/query values are usable for path derivation, but are
    # not evidence of the original target's form or empty query delimiter.
    def reconstruct(conn) do
      conn.request_path <>
        if(conn.query_string == "", do: "", else: "?" <> conn.query_string)
    end

    def verification_supported?(message, policy, label) do
      {:ok, required} = SignatureFields.inner(policy.components)

      not dependent?(required) and
        case StructuredFields.parse_field(
               message,
               "signature-input",
               SignatureFields.schema(:dictionary),
               :headers,
               unique_keys: :all,
               unique_parameters: true,
               max_members: policy.max_signatures
             ) do
          {:ok, inputs} -> not dependent?(List.keyfind(inputs.value, label, 0))
          # Invalid input still goes through the core's bounded field rejection.
          _ -> true
        end
    end

    def response_supported?(input) do
      not Enum.any?(input.value, fn item ->
        dependent_item?(item) and List.keymember?(item.parameters, "req", 0)
      end)
    end

    defp dependent?({_, input}), do: dependent?(input)

    defp dependent?(%Value{type: :inner_list, value: items}),
      do: Enum.any?(items, &dependent_item?/1)

    defp dependent?(_), do: false

    defp dependent_item?(%Value{value: {:string, name}}), do: name in @dependent
    defp dependent_item?(_), do: false
  end
end
