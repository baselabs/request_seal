defmodule RequestSeal.GuideKeyRotationTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {:ok, current_handle} = RequestSeal.Custody.Local.generate("ed25519", [])
        {:ok, next_handle} = RequestSeal.Custody.Local.generate("ed25519", [])
        ''',
        binding,
        "docs/guides/key-rotation.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, next_key} = RequestSeal.Custody.public_key(next_handle)
        {:ok, next_jwk} = RequestSeal.PublicKey.export(next_key, :jwk)
        {:ok, next_thumbprint} = RequestSeal.PublicKey.thumbprint(next_key)
        %{"kty" => "OKP", "crv" => "Ed25519"} = next_jwk
        ''',
        binding,
        "docs/guides/key-rotation.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, current_key} = RequestSeal.Custody.public_key(current_handle)
        components = ~s[("@method" "@scheme" "@authority" "@path")]

        policy_for = fn trusted ->
          {:ok, policy} =
            RequestSeal.Policy.new(%{
              algorithms: ["ed25519"],
              components: components,
              key_resolver: fn %{keyid: keyid} ->
                case Map.fetch(trusted, keyid) do
                  {:ok, key} -> {:ok, %{algorithm: "ed25519", key: key}}
                  :error -> :error
                end
              end,
              freshness: %{
                clock: fn -> System.system_time(:second) end,
                max_age: 60,
                skew: 5,
                require_expires: true
              },
              content: :not_required,
              replay: :not_required
            })

          policy
        end

        overlap_policy = policy_for.(%{"build-2" => current_key, "build-3" => next_key})
        ''',
        binding,
        "docs/guides/key-rotation.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        sign_with = fn handle, keyid ->
          {:ok, message} = RequestSeal.Message.request("POST", "https://ci.example.com/artifacts", [], nil)
          spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60, keyid: keyid}
          RequestSeal.sign(message, spec, handle)
        end

        {:ok, before_switch} = sign_with.(current_handle, "build-2")
        {:ok, after_switch} = sign_with.(next_handle, "build-3")
        {:ok, _} = RequestSeal.verify(before_switch, overlap_policy, label: "sig")
        {:ok, _} = RequestSeal.verify(after_switch, overlap_policy, label: "sig")
        ''',
        binding,
        "docs/guides/key-rotation.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        retired_policy = policy_for.(%{"build-3" => next_key})
        {:ok, _} = RequestSeal.verify(after_switch, retired_policy, label: "sig")

        {:error, %{reason: :unknown_key, layer: :key}} =
          RequestSeal.verify(before_switch, retired_policy, label: "sig")
        ''',
        binding,
        "docs/guides/key-rotation.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        :ok = RequestSeal.Custody.release(current_handle)
        {:error, %{reason: :signing_failed, source: %{reason: :key_not_found}}} =
          sign_with.(current_handle, "build-2")
        {:ok, _} = sign_with.(next_handle, "build-3")
        :ok = RequestSeal.Custody.release(next_handle)
        ''',
        binding,
        "docs/guides/key-rotation.md",
        6
      )

    assert Keyword.fetch!(binding, :next_thumbprint) |> byte_size() == 43

    assert {:error, %{reason: :key_not_found}} =
             RequestSeal.Custody.public_key(Keyword.fetch!(binding, :next_handle))

    E.assert_fences("docs/guides/key-rotation.md", 6)
  end
end
