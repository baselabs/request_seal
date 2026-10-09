defmodule RequestSeal.GuideJoseTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []
    code = ~S'
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, jose_handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
{:ok, jose_key} = RequestSeal.Custody.public_key(jose_handle)
{:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], "signed payload", jose_handle)
'
    binding = E.eval(code, binding)
    code = ~S'
jws_policy = %{
  algorithms: ["EdDSA"],
  timeout: 5_000,
  key_resolver: fn %{algorithm: "EdDSA"} ->
    {:ok, %{algorithm: "EdDSA", key: jose_key}}
  end
}

{:ok, result} = RequestSeal.JOSE.JWS.verify(token, jws_policy)
result.payload
# => "signed payload"
'
    binding = E.eval(code, binding)
    assert Keyword.fetch!(binding, :result).payload == "signed payload"
    code = ~S'
wrapping_key = {:aes, :crypto.strong_rand_bytes(32)}

wrap = fn algorithm, cek ->
  RequestSeal.JOSE.KeyManagement.wrap(algorithm, cek, %{}, wrapping_key)
end

{:ok, encrypted} =
  RequestSeal.JOSE.JWE.encrypt(
    [{"alg", "A256GCMKW"}, {"enc", "A256GCM"}],
    token,
    wrap
  )
'
    binding = E.eval(code, binding)
    code = ~S'
jwe_policy = %{
  algorithms: ["A256GCMKW"],
  encryption: ["A256GCM"],
  max_plaintext: 1_048_576,
  timeout: 5_000,
  key_resolver: fn %{algorithm: "A256GCMKW"} ->
    {:ok,
     %{
       algorithm: "A256GCMKW",
       unwrap: fn bytes, header ->
         RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", bytes, header, wrapping_key)
       end
     }}
  end
}

{:ok, decrypted} = RequestSeal.JOSE.JWE.decrypt(encrypted, jwe_policy)
{:ok, inner} = RequestSeal.JOSE.JWS.verify(decrypted.plaintext, jws_policy)
inner.payload
# => "signed payload"
'
    binding = E.eval(code, binding)
    assert Keyword.fetch!(binding, :decrypted).plaintext == Keyword.fetch!(binding, :token)
    assert Keyword.fetch!(binding, :inner).payload == "signed payload"
    token = Keyword.fetch!(binding, :token)
    [header, payload, signature] = String.split(token, ".")
    <<first, rest::binary>> = Base.url_decode64!(signature, padding: false)
    corrupt = Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)

    assert {:error, %RequestSeal.JOSE.Error{reason: :invalid_signature}} =
             RequestSeal.JOSE.JWS.verify(
               Enum.join([header, payload, corrupt], "."),
               Keyword.fetch!(binding, :jws_policy)
             )

    assert is_list(binding)
  end

  test "recipient handle example executes import health check decryption and release" do
    code = ~S'
private = :public_key.generate_key({:rsa, 2048, 65537})
pem = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, private)])
{:ok, recipient_handle} =
  RequestSeal.Custody.Local.import({:jwe, "RSA-OAEP-256"}, pem, :pem)

# Run this health check at startup, before accepting encrypted messages.
{:ok, recipient_public} = RequestSeal.Custody.public_key(recipient_handle)
{:ok, recipient_jwe} =
  RequestSeal.JOSE.JWE.encrypt(
    [{"alg", "RSA-OAEP-256"}, {"enc", "A256GCM"}],
    "recipient payload",
    recipient_public
  )

recipient_policy = %{
  algorithms: ["RSA-OAEP-256"],
  encryption: ["A256GCM"],
  max_plaintext: 1_048_576,
  timeout: 5_000,
  key_resolver: fn %{algorithm: "RSA-OAEP-256"} ->
    {:ok, %{algorithm: "RSA-OAEP-256", key: recipient_handle}}
  end
}

{:ok, recipient_result} = RequestSeal.JOSE.JWE.decrypt(recipient_jwe, recipient_policy)
recipient_result.plaintext
# => "recipient payload"
:ok = RequestSeal.Custody.Local.release(recipient_handle)
'
    {result, binding} = Code.eval_string(code)
    assert result == :ok
    assert Keyword.fetch!(binding, :recipient_result).plaintext == "recipient payload"
    handle = Keyword.fetch!(binding, :recipient_handle)

    assert {:error, %RequestSeal.Custody.Error{reason: :key_not_found}} =
             RequestSeal.Custody.public_key(handle)

    assert RequestSeal.JOSE.JWE.decrypt(
             Keyword.fetch!(binding, :recipient_jwe),
             Keyword.fetch!(binding, :recipient_policy)
           ) == {:error, RequestSeal.JOSE.Error.new(:decryption_failed, :crypto)}
  end
end
