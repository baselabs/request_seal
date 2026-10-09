defmodule RequestSeal.GuideKeyCustodyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
        ''',
        binding,
        "docs/guides/key-custody.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, signature} = RequestSeal.Custody.sign(handle, "exact bytes", timeout: 5_000)
        RequestSeal.Custody.verify(handle, "exact bytes", signature, timeout: 5_000)
        # => :ok
        RequestSeal.Custody.verify(handle, "changed bytes", signature)
        # => {:error, %RequestSeal.Custody.Error{reason: :invalid_signature, ...}}
        ''',
        binding,
        "docs/guides/key-custody.md",
        2
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert {:error, %RequestSeal.Custody.Error{reason: :invalid_signature}} = example_result

    assert :ok =
             RequestSeal.Custody.verify(
               Keyword.fetch!(binding, :handle),
               "exact bytes",
               Keyword.fetch!(binding, :signature)
             )

    binding =
      E.eval(
        ~S'''
        RequestSeal.Custody.Local.release(handle)
        # => :ok
        RequestSeal.Custody.sign(handle, "exact bytes")
        # => {:error, %RequestSeal.Custody.Error{reason: :key_not_found, ...}}
        ''',
        binding,
        "docs/guides/key-custody.md",
        3
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert {:error, %RequestSeal.Custody.Error{reason: :key_not_found}} = example_result
    assert is_list(binding)

    binding =
      E.eval(
        ~S'''
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
        ''',
        binding,
        "docs/guides/key-custody.md",
        4
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert example_result == :ok
    assert Keyword.fetch!(binding, :recipient_result).plaintext == "recipient payload"
    handle = Keyword.fetch!(binding, :recipient_handle)

    assert {:error, %RequestSeal.Custody.Error{reason: :key_not_found}} =
             RequestSeal.Custody.public_key(handle)

    assert RequestSeal.JOSE.JWE.decrypt(
             Keyword.fetch!(binding, :recipient_jwe),
             Keyword.fetch!(binding, :recipient_policy)
           ) == {:error, RequestSeal.JOSE.Error.new(:decryption_failed, :crypto)}

    E.assert_fences("docs/guides/key-custody.md", 4)
  end
end
