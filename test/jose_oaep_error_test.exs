defmodule RequestSeal.JOSEOAEPErrorTest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.{Error, JWE, KeyManagement, Support}
  alias RequestSeal.PropertySupport, as: P

  test "OAEP padding and GCM authentication failures return identical complete errors" do
    private = :public_key.generate_key({:rsa, 2048, 65537})
    rsa_public = {:RSAPublicKey, elem(private, 2), elem(private, 3)}
    {:ok, public} = RequestSeal.PublicKey.import({:rsa, elem(private, 2), elem(private, 3)}, :raw)

    for algorithm <- ["RSA-OAEP", "RSA-OAEP-256"] do
      {:ok, token} =
        JWE.encrypt([{"alg", algorithm}, {"enc", "A256GCM"}], "authenticated plaintext", public)

      policy = %{
        algorithms: [algorithm],
        encryption: ["A256GCM"],
        max_plaintext: 1024,
        timeout: 5000,
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: algorithm,
             unwrap: fn ek, h -> KeyManagement.unwrap(algorithm, ek, h, {:rsa, private}) end
           }}
        end
      }

      assert {:ok, result} = JWE.decrypt(token, policy)
      assert result.plaintext == "authenticated plaintext"
      [h, ek, iv, ct, tag] = String.split(token, ".")

      encoded =
        :public_key.decrypt_private(Support.decode(ek), private, rsa_padding: :rsa_no_padding)

      for index <- [1, 32, 128, 200] do
        corrupt =
          :public_key.encrypt_public(P.change(encoded, index), rsa_public,
            rsa_padding: :rsa_no_padding
          )

        assert {:error, _} = KeyManagement.unwrap(algorithm, corrupt, %{}, {:rsa, private})
        padding = Enum.join([h, Support.b64(corrupt), iv, ct, tag], ".")
        tag_token = Enum.join([h, ek, iv, ct, Support.b64(P.change(Support.decode(tag), 0))], ".")

        assert {:error,
                %Error{
                  reason: :decryption_failed,
                  layer: :crypto,
                  retryable: false,
                  correlation: nil
                } = error} = JWE.decrypt(padding, policy)

        assert JWE.decrypt(tag_token, policy) == {:error, error}
      end
    end
  end
end
