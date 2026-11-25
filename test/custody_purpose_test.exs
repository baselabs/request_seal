defmodule RequestSeal.CustodyPurposeTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody, Message, Policy, SignatureBase}
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

    base = base(ctx.message)
    options = [issued_for: :build, operation: :http]
    assert {:ok, signature} = Custody.sign(ctx.handle, base, options)
    assert :ok = Custody.verify(ctx.handle, base, signature, options)

    for missing <- [[], [issued_for: nil], [issued_for: :audit]] do
      wrong = [operation: :http] ++ missing

      assert {:error, %{reason: :issued_for_mismatch}} = Custody.sign(ctx.handle, base, wrong)

      assert {:error, %{reason: :issued_for_mismatch}} =
               Custody.verify(ctx.handle, base, signature, wrong)
    end

    for forged <- [%{ctx.handle | issued_for: :audit}, %{ctx.handle | issued_for: nil}] do
      forged_options = [issued_for: forged.issued_for, operation: :http]
      assert {:error, %{reason: :key_mismatch}} = Custody.sign(forged, base, forged_options)
    end

    forged = %{ctx.handle | algorithm: {:jws, "EdDSA"}, operation_family: :jws}
    assert {:error, %{reason: :key_mismatch}} =
             Custody.sign(forged, base, issued_for: :build, operation: :jws)

    assert {:error, %{reason: :invalid_handle}} =
             Custody.sign(%{ctx.handle | operation_family: :jws}, base, options)

    assert :ok = Local.release(ctx.handle)
    assert {:error, %{reason: :key_not_found}} = Custody.binding(ctx.handle)
  end

  test "an unassigned key allows omitted and explicit nil purpose on raw operations", ctx do
    {:ok, handle} = Local.new("ed25519", {:ed25519, ctx.seed})

    for opts <- [[], [issued_for: nil]] do
      assert {:ok, signature} = Custody.sign(handle, "payload", opts)
      assert :ok = Custody.verify(handle, "payload", signature, opts)
    end
  end

  test "an assigned handle stays in its requested wire protocol", ctx do
    base = base(ctx.message)
    data = "arbitrary bytes"
    opts = [issued_for: :build, operation: :http]
    assert {:ok, signature} = Custody.sign(ctx.handle, base, opts)

    assert {:error, %{reason: :unsupported_operation}} =
             Custody.sign(ctx.handle, base, issued_for: :build)

    assert {:error, %{reason: :unsupported_operation}} =
             Custody.verify(ctx.handle, base, signature, issued_for: :build)

    assert {:error, %{reason: :invalid_data}} = Custody.sign(ctx.handle, data, opts)
    assert {:error, %{reason: :invalid_data}} = Custody.verify(ctx.handle, data, signature, opts)

    assert {:error, %{reason: :algorithm_mismatch}} =
             JWS.sign([{"alg", "EdDSA"}], "manifest", ctx.handle, issued_for: :build)

    {:ok, jws_key} = Local.new({:jws, "EdDSA"}, {:ed25519, ctx.seed}, issued_for: :build)

    for spec <- [
          %{signature_input: ~s[("@method");created=1700000000]},
          %{components: ~s[("@method")], expires_in: 60}
        ] do
      spec = Map.merge(spec, %{label: "sig", algorithm: {:jws, "EdDSA"}, issued_for: :build})

      assert {:error, %{reason: :signing_failed, source: %{reason: :unsupported_operation}}} =
               RequestSeal.sign(ctx.message, spec, jws_key)
    end

    assert {:error, %{reason: :unsupported_operation}} =
             Custody.sign(jws_key, base, issued_for: :build)
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

      for missing <- [Map.delete(spec, :issued_for), %{spec | issued_for: nil}] do
        assert {:error, %{reason: :issued_for_mismatch}} =
                 RequestSeal.sign(ctx.message, missing, ctx.handle)
      end

      assert {:ok, _} = RequestSeal.verify(signed, policy(ctx.handle, :build), label: "sig")

      assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
               RequestSeal.verify(signed, policy(ctx.handle, nil), label: "sig")

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

    assert {:error, %{reason: :issued_for_mismatch}} =
             JWS.sign([{"alg", "EdDSA"}], "manifest", handle)

    assert {:error, %{reason: :issued_for_mismatch}} =
             JWS.sign_protected(~s({"alg":"EdDSA"}), "manifest", handle, issued_for: nil)

    verify_policy = %{
      algorithms: ["EdDSA"],
      timeout: 1_000,
      key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: handle}} end,
      protected: %{embedded_key: :refuse, expected: %{}, permitted: []},
      require_issued_for: :build
    }

    assert {:ok, %{payload: "manifest"}} = JWS.verify(compact, verify_policy)
    assert {:error, %{reason: :issued_for_mismatch}} =
             JWS.verify(compact, Map.delete(verify_policy, :require_issued_for))
  end

  defp base(message) do
    {:ok, base} = SignatureBase.build(message, ~s[("@method" "@path");created=1700000000])
    base
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
