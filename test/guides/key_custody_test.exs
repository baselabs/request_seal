defmodule RequestSeal.GuideKeyCustodyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []
    code = ~S'
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
'
    binding = E.eval(code, binding)
    code = ~S'
{:ok, signature} = RequestSeal.Custody.sign(handle, "exact bytes", timeout: 5_000)
RequestSeal.Custody.verify(handle, "exact bytes", signature, timeout: 5_000)
# => :ok
RequestSeal.Custody.verify(handle, "changed bytes", signature)
# => {:error, %RequestSeal.Custody.Error{reason: :invalid_signature, ...}}
'
    {example_result, binding} = Code.eval_string(code, binding)
    assert {:error, %RequestSeal.Custody.Error{reason: :invalid_signature}} = example_result

    assert :ok =
             RequestSeal.Custody.verify(
               Keyword.fetch!(binding, :handle),
               "exact bytes",
               Keyword.fetch!(binding, :signature)
             )

    code = ~S'
RequestSeal.Custody.Local.release(handle)
# => :ok
RequestSeal.Custody.sign(handle, "exact bytes")
# => {:error, %RequestSeal.Custody.Error{reason: :key_not_found, ...}}
'
    {example_result, binding} = Code.eval_string(code, binding)
    assert {:error, %RequestSeal.Custody.Error{reason: :key_not_found}} = example_result
    assert is_list(binding)
  end
end
