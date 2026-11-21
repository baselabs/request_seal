defmodule RequestSeal.GuideKeyGenerationAndDerivationTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute with real cryptography" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {:request_seal, "~> 2.0"}
        ''',
        binding,
        "docs/guides/key-generation-and-derivation.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, signer} = RequestSeal.Custody.Local.generate("ed25519", [])
        {:ok, public_key} = RequestSeal.Custody.public_key(signer)
        {:ok, signature} = RequestSeal.Custody.sign(signer, "exact bytes")
        :ok = RequestSeal.Crypto.verify("ed25519", "exact bytes", signature, public_key)
        {:error, %{reason: :invalid_signature}} = RequestSeal.Custody.verify(signer, "changed bytes", signature)
        :ok = RequestSeal.Custody.release(signer)
        {:error, %{reason: :key_not_found}} = RequestSeal.Custody.sign(signer, "exact bytes")
        ''',
        binding,
        "docs/guides/key-generation-and-derivation.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, recipient} = RequestSeal.Custody.Local.generate({:jwe, "RSA-OAEP-256"}, bits: 2048, timeout: 30_000)
        {:ok, agreement} = RequestSeal.Custody.Local.generate({:jwe, "ECDH-ES"}, curve: "X25519")
        {:ok, signing_only} = RequestSeal.Custody.Local.generate({:jws, "EdDSA"}, capabilities: [:sign])

        for handle <- [recipient, agreement, signing_only] do
          :ok = RequestSeal.Custody.release(handle)
        end

        {:error, %{reason: :invalid_options}} = RequestSeal.Custody.Local.generate("ed25519", bits: 2048)
        {:error, %{reason: :unsupported_algorithm}} = RequestSeal.Custody.Local.generate({:jwe, "dir"}, [])
        ''',
        binding,
        "docs/guides/key-generation-and-derivation.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        example_ikm = Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        {:ok, parent} = RequestSeal.Custody.Local.new({:derive, "hkdf-sha256"}, {:ikm, example_ikm})

        {:ok, child} = RequestSeal.Custody.derive(parent, "ed25519", "example/signing/v1", timeout: 5_000)
        {:ok, child_public} = RequestSeal.Custody.public_key(child)

        # Parent and committed child have independent lifetimes.
        :ok = RequestSeal.Custody.release(parent)
        {:ok, child_signature} = RequestSeal.Custody.sign(child, "derived-key example")
        :ok = RequestSeal.Crypto.verify("ed25519", "derived-key example", child_signature, child_public)
        :ok = RequestSeal.Custody.release(child)
        ''',
        binding,
        "docs/guides/key-generation-and-derivation.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        {:ok, root} = RequestSeal.Custody.Local.new({:derive, "hkdf-sha256"}, {:ikm, example_ikm})

        {:error, %{reason: :invalid_data}} =
          RequestSeal.Custody.derive(root, "ed25519", "", timeout: 5_000)
        {:error, %{reason: :invalid_options}} =
          RequestSeal.Custody.derive(root, "ed25519", "example/signing/v1", [])

        outcome =
          case RequestSeal.Custody.derive(root, {:jwe, "A256KW"}, "example/wrapping/v1", timeout: 5_000) do
            {:ok, wrapping_key} ->
              :ok = RequestSeal.Custody.release(wrapping_key)
              :ok

            {:error, error} ->
              {:error, error}

            {:cleanup_required, cleanup, error} ->
              case RequestSeal.Custody.cleanup(cleanup, timeout: 5_000) do
                :ok -> {:error, error}
                {:error, _} -> {:cleanup_required, cleanup, error}
              end
          end

        :ok = outcome
        :ok = RequestSeal.Custody.release(root)
        ''',
        binding,
        "docs/guides/key-generation-and-derivation.md",
        5
      )

    assert is_list(binding)
    E.assert_fences("docs/guides/key-generation-and-derivation.md", 5)
  end
end
