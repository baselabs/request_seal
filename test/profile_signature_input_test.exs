defmodule RequestSeal.ProfileSignatureInputTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Profile, StructuredFields}
  alias StructuredFields.{Schema, Value}

  test "validates parsed inner lists with the existing component rules" do
    for {wire, expected} <- [
          {~s[("@method" "content-digest";sf);created=1618884473;keyid="test-key-rsa"], true},
          {~s[()], true},
          {~s[("@query-param";name="id")], true},
          {~s[("@method" "@method")], false},
          {~s[("Content-Type")], false},
          {~s[("@unknown")], false},
          {~s[("@query-param")], false},
          {~s[("content-digest";bs;sf)], false},
          {~s[("@method");created="bad"], false},
          {~s[("@method");nonce=123], false},
          {~s[("@method");extension=?1], true},
          {~s[("@method";req)], true},
          {~s[("@method";sf)], false},
          {~s[("content-digest";sf=?0)], false}
        ] do
      {:ok, %Value{value: [input]}} =
        StructuredFields.parse(wire, %Schema{
          revision: :rfc8941,
          type: :list,
          item_types: [:string],
          parameter_types: Schema.types(:rfc8941),
          inner_lists: true
        })

      assert Profile.valid_signature_input?(input) == expected

      assert Profile.valid_signature_input?(input) ==
               RequestSeal.SignatureFields.valid_inner?(input)
    end
  end

  test "component ceiling distinguishes 256 unique components from 257" do
    components =
      Enum.map(1..257, fn n ->
        %Value{type: :item, value: {:string, "x-field-#{n}"}}
      end)

    assert Profile.valid_signature_input?(%Value{
             type: :inner_list,
             value: Enum.take(components, 256)
           })

    refute Profile.valid_signature_input?(%Value{type: :inner_list, value: components})
  end

  test "rejects non-inner lists, malformed structures and excess components" do
    item = %Value{type: :item, value: {:string, "@method"}}

    for input <- [
          nil,
          "(\"@method\")",
          %{},
          item,
          %Value{type: :list, value: [item]},
          %Value{type: :inner_list, value: nil},
          %Value{type: :inner_list, value: [item], parameters: nil},
          %Value{type: :inner_list, value: List.duplicate(item, 257)}
        ] do
      refute Profile.valid_signature_input?(input)
    end
  end

  for kind <- [:error, :throw, :exit] do
    test "returns false when a parameter enumerable raises #{kind}" do
      parameters =
        Stream.map([:parameter], fn _ ->
          case unquote(kind) do
            :error -> raise "invalid parameter enumeration"
            :throw -> throw(:invalid_parameter_enumeration)
            :exit -> exit(:invalid_parameter_enumeration)
          end
        end)

      assert Profile.valid_signature_input?(%Value{
               type: :inner_list,
               value: [],
               parameters: parameters
             }) == false
    end
  end
end
