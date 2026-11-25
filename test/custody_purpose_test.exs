defmodule RequestSeal.CustodyPurposeTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody, Message, Policy}
  alias RequestSeal.Custody.Local
  alias RequestSeal.JOSE.JWS

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed}, issued_for: :build)
    {:ok, message} = Message.request("GET", "https://example.test/builds", [], "")
    %{seed: seed, handle: handle, message: message}
  end

  test "a Local holder attests its own purpose and exact operation family", ctx do
    assert {:ok, binding} = Custody.binding(ctx.handle)
    assert binding.issued_for == :build
    assert binding.operation_family == :http
    assert binding.algorithm == "ed25519"
    assert is_binary(binding.thumbprint)

    assert {:ok, signature} = Custody.sign(ctx.handle, "payload", issued_for: :build)
    assert :ok = Custody.verify(ctx.handle, "payload", signature, issued_for: :build)

    assert {:error, %{reason: :issued_for_mismatch}} =
             Custody.sign(ctx.handle, "payload", issued_for: :audit)

    for forged <- [%{ctx.handle | issued_for: :audit}, %{ctx.handle | issued_for: nil}] do
      assert {:error, %{reason: :key_mismatch}} = Custody.sign(forged, "payload")
    end

    forged = %{ctx.handle | algorithm: {:jws, "EdDSA"}, operation_family: :jws}
    assert {:error, %{reason: :key_mismatch}} = Custody.sign(forged, "payload")
    assert {:error, %{reason: :invalid_handle}} =
             Custody.sign(%{ctx.handle | operation_family: :jws}, "payload")

    assert :ok = Local.release(ctx.handle)
    assert {:error, %{reason: :key_not_found}} = Custody.binding(ctx.handle)
  end

  test "generated custody retains purpose and symmetric identity exports no thumbprint" do
    {:ok, generated} = Local.generate("hmac-sha256", issued_for: :build)
    assert {:ok, %{issued_for: :build, thumbprint: nil}} = Custody.binding(generated)
    assert {:error, %{reason: :no_public_key}} = Custody.public_key(generated)
    assert {:error, %{reason: :invalid_options}} =
             Local.generate("hmac-sha256", issued_for: true)
  end

  test "both HTTP signing forms and verification use trusted assignment", ctx do
    explicit = %{
      label: "sig",
      signature_input: ~s[("@method" "@path");created=1700000000],
      algorithm: "ed25519",
      issued_for: :build
    }

    generated = %{
      label: "sig",
      components: ~s[("@method" "@path")],
      expires_in: 60,
      algorithm: "ed25519",
      issued_for: :build
    }

    for spec <- [explicit, generated] do
      assert {:ok, signed} = RequestSeal.sign(ctx.message, spec, ctx.handle)

      assert {:error, %{reason: :issued_for_mismatch, layer: :input}} =
               RequestSeal.sign(ctx.message, %{spec | issued_for: :audit}, ctx.handle)

      assert {:ok, _} = RequestSeal.verify(signed, policy(ctx.handle, :build), label: "sig")

      assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
               RequestSeal.verify(signed, policy(ctx.handle, :audit), label: "sig")

      {:ok, key} = Custody.public_key(ctx.handle)
      assert {:ok, _} =
               RequestSeal.verify(signed, policy(key, :build, %{issued_for: :build}), label: "sig")

      assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
               RequestSeal.verify(signed, policy(key, :build), label: "sig")

      assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
               RequestSeal.verify(
                 signed,
                 policy(ctx.handle, :audit, %{issued_for: :audit}),
                 label: "sig"
               )
    end
  end

  test "JWS enforces purpose in both signing forms", ctx do
    {:ok, handle} = Local.new({:jws, "EdDSA"}, {:ed25519, ctx.seed}, issued_for: :build)
    assert handle.operation_family == :jws
    assert {:ok, compact} = JWS.sign([{"alg", "EdDSA"}], "manifest", handle, issued_for: :build)

    assert {:ok, ^compact} =
             JWS.sign_protected(~s({"alg":"EdDSA"}), "manifest", handle, issued_for: :build)

    assert {:error, %{reason: :issued_for_mismatch, layer: :key}} =
             JWS.sign([{"alg", "EdDSA"}], "manifest", handle, issued_for: :audit)

    assert {:error, %{reason: :issued_for_mismatch, layer: :key}} =
             JWS.sign_protected(~s({"alg":"EdDSA"}), "manifest", handle, issued_for: :audit)
  end

  defp policy(key, purpose, extra \\ %{}) do
    entry = Map.merge(%{algorithm: "ed25519", key: key}, extra)

    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: ~s[("@method" "@path")],
        key_resolver: fn _ -> {:ok, entry} end,
        freshness: :not_evaluated,
        content: :not_required,
        replay: :not_required,
        require_issued_for: purpose
      })

    policy
  end
end
