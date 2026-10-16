defmodule RequestSeal.SignatureFieldsTest do
  @moduledoc false
  use ExUnit.Case, async: true
  alias RequestSeal.SignatureFields
  alias RequestSeal.StructuredFields.Value

  test "inner/1 returns one error shape for every rejection" do
    # A well-formed but non-inner-list value: parse succeeds, shape rejects.
    assert {:error, %RequestSeal.StructuredFields.Error{}} =
             SignatureFields.inner(~s["just-an-item"])

    # A hand-built item where an inner list is required.
    assert {:error, %RequestSeal.StructuredFields.Error{}} =
             SignatureFields.inner(%Value{type: :item, value: {:string, "@method"}})

    # A parameter type an inner list never accepts.
    assert {:error, %RequestSeal.StructuredFields.Error{}} =
             SignatureFields.inner(%Value{
               type: :inner_list,
               value: [%Value{type: :item, value: {:integer, 7}}],
               parameters: []
             })

    # Non-value input.
    assert {:error, %RequestSeal.StructuredFields.Error{}} = SignatureFields.inner(:nope)

    # Serialization limits keep their :limit reason through the same shape.
    long = String.duplicate("x", 65_536)

    assert {:error, %RequestSeal.StructuredFields.Error{reason: :limit}} =
             SignatureFields.inner(%Value{
               type: :inner_list,
               value: [
                 %Value{type: :item, value: {:string, long}, parameters: []}
               ],
               parameters: []
             })
  end
end
