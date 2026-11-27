defmodule RequestSeal.CustodyPurposeTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody, DenySet, KeyHandle, Message, Policy, PublicKey, SignatureBase}
  alias RequestSeal.Custody.Local
  alias RequestSeal.JOSE.JWS

  defmodule PublicKeyCustodian do
    @moduledoc false
    @behaviour Custody

    @impl true
    def signing_assignment(ref, context), do: Local.signing_assignment(ref.().ref, context)

    @impl true
    def binding(ref, context), do: Local.binding(ref.().ref, context)

    @impl true
    def public_key(ref), do: Custody.public_key(ref.())

    @impl true
    def sign(_, _, _, _), do: {:error, :unsupported_operation}

    @impl true
    def identity(ref), do: Custody.identity(ref.())
  end

  defmodule RotatingVerificationCustodian do
    @behaviour Custody

    @impl true
    def binding(ref, context) do
      {key, _, observer} = ref.()
      send(observer, :binding_read)
      Local.binding(key.ref, context)
    end

    @impl true
    def public_key(ref) do
      {_, other, observer} = ref.()
      send(observer, :separate_public_read)
      {:ok, other}
    end

    @impl true
    def verify(ref, algorithm, bytes, signature, context) do
      {key, _, _} = ref.()
      Local.verify(key.ref, algorithm, bytes, signature, context)
    end

    @impl true
    def sign(_, _, _, _), do: {:error, :unsupported_operation}

    @impl true
    def identity(ref) do
      {key, _, _} = ref.()
      Custody.identity(key)
    end
  end

  for {name, binding?, assignment?, verify?} <- [
        {"BindingOnly", true, false, false},
        {"BindingWithVerifier", true, false, true},
        {"AssignmentOnly", false, true, false},
        {"AssignmentWithVerifier", false, true, true},
        {"Both", true, true, false},
        {"BothWithVerifier", true, true, true},
        {"Legacy", false, false, false},
        {"LegacyWithVerifier", false, false, true}
      ] do
    defmodule Module.concat(__MODULE__, name) do
      @moduledoc false
      @behaviour RequestSeal.Custody
      alias RequestSeal.Custody
      alias RequestSeal.Custody.Local

      @impl true
      def sign(ref, algorithm, bytes, context) do
        {key, observer} = ref.()
        send(observer, :provider_sign)
        Local.sign(key.ref, algorithm, bytes, context)
      end

      @impl true
      def public_key(ref), do: Custody.public_key(elem(ref.(), 0))

      @impl true
      def identity(ref), do: Custody.identity(elem(ref.(), 0))

      if binding? do
        @impl true
        def binding(ref, context) do
          {key, observer} = ref.()
          send(observer, :provider_binding)
          Local.binding(key.ref, context)
        end
      end

      if assignment? do
        @impl true
        def signing_assignment(ref, context) do
          {key, observer} = ref.()
          send(observer, :provider_assignment)
          Local.signing_assignment(key.ref, context)
        end
      end

      if verify? do
        @impl true
        def verify(ref, algorithm, bytes, signature, context) do
          {key, observer} = ref.()
          send(observer, :provider_verify)
          Local.verify(key.ref, algorithm, bytes, signature, context)
        end
      end
    end
  end

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
               RequestSeal.verify(signed, policy(key, :build, %{issued_for: :build}),
                 label: "sig"
               )

      assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
               RequestSeal.verify(signed, policy(key, :build), label: "sig")

      for purpose <- [:omitted, nil, :audit] do
        assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
                 RequestSeal.verify(
                   signed,
                   policy(key, purpose, %{issued_for: :build}),
                   label: "sig"
                 )
      end

      assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
               RequestSeal.verify(
                 signed,
                 policy(ctx.handle, :audit, %{issued_for: :audit}),
                 label: "sig"
               )
    end
  end

  test "Accept-Signature chooses the purpose locally, independent of the offered tag", ctx do
    alias RequestSeal.AcceptSignature

    {:ok, requests} =
      AcceptSignature.parse(~s[sig=("@method" "@path");tag="audit"], target: :request)

    for purpose <- [:build, :audit, nil] do
      chooser = fn _ ->
        {:ok, %{algorithm: "ed25519", created: nil, expires: nil, issued_for: purpose}}
      end

      result = AcceptSignature.fulfill(ctx.message, requests, chooser, [ctx.handle], [])

      if purpose == :build do
        assert {:ok, signed} = result
        assert {:ok, _} = RequestSeal.verify(signed, policy(ctx.handle, :build), label: "sig")
      else
        assert {:error, %{reason: :negotiation_unfulfillable, detail: :issued_for_mismatch}} =
                 result
      end
    end
  end

  test "Web Bot Auth passes the signing spec's trusted purpose to custody", ctx do
    {:ok, public} = Custody.public_key(ctx.handle)

    spec = %{
      label: "sig",
      agent: %{location: "https://crawler.example", type: :directory},
      key: public,
      algorithm: "ed25519",
      created: 1_700_000_000,
      expires: 1_700_000_060,
      nonce: "once",
      issued_for: :build
    }

    assert {:ok, signed} = RequestSeal.WebBotAuth.sign(ctx.message, spec, ctx.handle)
    assert Enum.any?(signed.fields, &(String.downcase(&1.name) == "signature"))

    for purpose <- [:audit, nil] do
      assert {:error, %{reason: :issued_for_mismatch}} =
               RequestSeal.WebBotAuth.sign(ctx.message, %{spec | issued_for: purpose}, ctx.handle)
    end
  end

  test "a pre-upgrade HTTP policy keeps unassigned semantics", ctx do
    spec = %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method" "@path")]}
    {:ok, handle} = Local.new("ed25519", {:ed25519, ctx.seed})
    assert {:ok, signed} = RequestSeal.sign(ctx.message, spec, handle)
    assert {:ok, key} = Custody.public_key(handle)
    legacy = Map.delete(policy(key, nil), :require_issued_for)
    assert {:ok, _} = RequestSeal.verify(signed, legacy, label: "sig")

    legacy_assigned =
      key
      |> policy(nil, %{issued_for: :build})
      |> Map.delete(:require_issued_for)

    assert {:error, %{reason: :key_issued_for_mismatch, layer: :key}} =
             RequestSeal.verify(signed, legacy_assigned, label: "sig")

    for malformed <- [Map.delete(legacy, :content), Map.put(legacy, :unknown, nil)] do
      assert {:error, %{reason: :invalid_policy, layer: :input}} =
               RequestSeal.verify(signed, malformed, label: "sig")
    end
  end

  test "public-key fallback checks retained assignment even when the claim is cleared", ctx do
    spec = %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method" "@path")]}

    assert {:ok, signed} =
             RequestSeal.sign(ctx.message, Map.put(spec, :issued_for, :build), ctx.handle)

    assert {:ok, bytes} = SignatureBase.build(ctx.message, spec.signature_input)

    assert {:ok, signature} =
             Custody.sign(ctx.handle, bytes, issued_for: :build, operation: :http)

    reference = %KeyHandle{
      custodian: PublicKeyCustodian,
      algorithm: "ed25519",
      capabilities: [:verify],
      issued_for: :build,
      ref: fn -> ctx.handle end
    }

    assert {:error, %{reason: :unsupported_operation}} =
             Custody.verify(reference, bytes, signature, issued_for: :build, operation: :http)

    cleared = %{reference | issued_for: nil}

    assert {:error, %{reason: :key_mismatch}} =
             Custody.verify(cleared, bytes, signature, operation: :http)

    assert {:error, %{reason: :verifier_failed, layer: :crypto}} =
             RequestSeal.verify(signed, policy(cleared, nil), label: "sig")

    assert {:ok, local} = Local.new("ed25519", {:ed25519, ctx.seed})
    unassigned = %{cleared | ref: fn -> local end}
    assert :ok = Custody.verify(unassigned, bytes, signature, operation: :http)
    assert {:ok, _} = RequestSeal.verify(signed, policy(unassigned, nil), label: "sig")
  end

  test "assigned JWS keys refuse HTTP verification in either representation", ctx do
    algorithm = {:jws, "EdDSA"}
    assert {:ok, unassigned} = Local.new(algorithm, {:ed25519, ctx.seed})
    assert {:ok, assigned} = Local.new(algorithm, {:ed25519, ctx.seed}, issued_for: :build)
    assert {:ok, public} = Custody.public_key(assigned)

    spec = %{label: "sig", algorithm: algorithm, signature_input: ~s[("@method" "@path")]}
    assert {:ok, signed} = RequestSeal.sign(ctx.message, spec, unassigned)

    for {key, extra} <- [{assigned, %{}}, {public, %{issued_for: :build}}] do
      assert {:error, %{reason: :algorithm_mismatch, layer: :key}} =
               RequestSeal.verify(signed, policy(key, :build, extra, algorithm), label: "sig")
    end

    for key <- [unassigned, public] do
      assert {:ok, _} = RequestSeal.verify(signed, policy(key, nil, %{}, algorithm), label: "sig")
    end
  end

  test "fallback verifies only with the key returned in the atomic assignment", ctx do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, unassigned} = Local.new("ed25519", {:ed25519, seed})
    bytes = base(ctx.message)
    opts = [issued_for: :build, operation: :http]
    assert {:ok, signature} = Custody.sign(ctx.handle, bytes, opts)
    observer = self()
    rotation = make_ref()

    reference = %KeyHandle{
      custodian: PublicKeyCustodian,
      algorithm: "ed25519",
      capabilities: [:verify],
      ref: fn ->
        send(observer, :reference_read)
        if Process.put(rotation, true), do: ctx.handle, else: unassigned
      end
    }

    assert {:error, %{reason: :invalid_signature}} = Custody.verify(reference, bytes, signature)
    assert_received :reference_read
    refute_received :reference_read
  end

  test "the optional callback matrix fails closed and prefers atomic binding", ctx do
    observer = self()
    {:ok, unassigned} = Local.new("ed25519", {:ed25519, ctx.seed})
    bytes = base(ctx.message)
    spec = %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method" "@path")]}

    for {provider, interface, verifies?} <- [
          {"BindingOnly", :binding, false},
          {"BindingWithVerifier", :binding, true},
          {"AssignmentOnly", :assignment, false},
          {"AssignmentWithVerifier", :assignment, true},
          {"Both", :binding, false},
          {"BothWithVerifier", :binding, true},
          {"Legacy", :legacy, false},
          {"LegacyWithVerifier", :legacy, true}
        ],
        key <- [unassigned, ctx.handle] do
      purpose = key.issued_for
      opts = [issued_for: purpose, operation: :http]
      {:ok, signature} = Custody.sign(key, bytes, opts)
      tagged = Map.put(spec, :issued_for, purpose)
      {:ok, signed} = RequestSeal.sign(ctx.message, tagged, key)

      handle = %KeyHandle{
        custodian: Module.concat(__MODULE__, provider),
        algorithm: "ed25519",
        capabilities: [:sign, :verify],
        issued_for: purpose,
        ref: fn -> {key, observer} end
      }

      if purpose == nil or interface != :legacy do
        assert {:ok, ^signature} = Custody.sign(handle, bytes, opts)
        assert_received :provider_sign
        assert_assignment_read(interface)
      else
        assert {:error, %{reason: :unsupported_operation}} = Custody.sign(handle, bytes, opts)
        refute_received :provider_sign
      end

      cond do
        verifies? and (purpose == nil or interface != :legacy) ->
          assert :ok = Custody.verify(handle, bytes, signature, opts)
          assert_received :provider_verify
          assert_assignment_read(interface)

        purpose == nil and interface in [:binding, :legacy] ->
          assert :ok = Custody.verify(handle, bytes, signature, opts)
          assert_assignment_read(interface)

        true ->
          assert {:error, %{reason: :unsupported_operation}} =
                   Custody.verify(handle, bytes, signature, opts)
      end

      if purpose != nil and interface != :legacy do
        cleared = %{handle | issued_for: nil}
        assert {:error, %{reason: :key_mismatch}} = Custody.sign(cleared, bytes, operation: :http)
        assert_assignment_read(interface)
        refute_received :provider_sign

        reason =
          if verifies? or interface == :binding, do: :key_mismatch, else: :unsupported_operation

        assert {:error, %{reason: ^reason}} =
                 Custody.verify(cleared, bytes, signature, operation: :http)

        if reason == :key_mismatch, do: assert_assignment_read(interface)
        refute_received :provider_verify
      end

      assert {:ok, public} = Custody.public_key(handle)
      assert {:error, %{reason: :invalid_options}} = RequestSeal.sign(ctx.message, tagged, public)
      assignment = %{issued_for: purpose}

      assert {:ok, _} =
               RequestSeal.verify(signed, policy(public, purpose, assignment), label: "sig")

      assert {:error, %{reason: :key_issued_for_mismatch}} =
               RequestSeal.verify(signed, policy(public, :other, assignment), label: "sig")
    end
  end

  defp assert_assignment_read(:binding) do
    assert_received :provider_binding
    refute_received :provider_assignment
  end

  defp assert_assignment_read(:assignment), do: assert_received(:provider_assignment)

  defp assert_assignment_read(:legacy) do
    refute_received :provider_assignment
    refute_received :provider_binding
  end

  test "screening and capture verify with the public key in the assignment", ctx do
    {:ok, other} = Local.generate("ed25519", [])
    {:ok, other_public} = Custody.public_key(other)
    {:ok, other_thumbprint} = PublicKey.thumbprint(other_public)
    {:ok, public} = Custody.public_key(ctx.handle)
    {:ok, thumbprint} = PublicKey.thumbprint(public)
    {:ok, deny_other} = DenySet.new([other_thumbprint])
    {:ok, deny_bound} = DenySet.new([thumbprint])
    observer = self()

    reference = %{
      ctx.handle
      | custodian: RotatingVerificationCustodian,
        ref: fn -> {ctx.handle, other_public, observer} end
    }

    spec = %{
      label: "sig",
      algorithm: "ed25519",
      signature_input: ~s[("@method" "@path")],
      issued_for: :build
    }

    {:ok, signed} = RequestSeal.sign(ctx.message, spec, ctx.handle)
    policy = policy(reference, :build)

    assert {:ok, _} = RequestSeal.verify(signed, %{policy | deny: deny_other}, label: "sig")
    assert_received :binding_read
    refute_received :binding_read
    refute_received :separate_public_read

    assert {:ok, %{signature: %{record_material: %{key: ^public}}}} =
             RequestSeal.verify(signed, policy, label: "sig", capture: true)

    assert_received :binding_read
    refute_received :binding_read
    refute_received :separate_public_read

    assert {:error, %{reason: :key_denied}} =
             RequestSeal.verify(signed, %{policy | deny: deny_bound}, label: "sig")

    assert_received :binding_read
    refute_received :separate_public_read
  end

  test "assignment-only custody refuses screening and capture but can verify", ctx do
    observer = self()

    reference = %{
      ctx.handle
      | custodian: __MODULE__.AssignmentWithVerifier,
        ref: fn -> {ctx.handle, observer} end
    }

    bytes = base(ctx.message)
    opts = [issued_for: :build, operation: :http]
    {:ok, signature} = Custody.sign(ctx.handle, bytes, opts)
    {:ok, deny} = DenySet.new([])

    for screening <- [nil, deny] do
      assert {:error, %{reason: :unsupported_operation}} =
               Custody.verify_bound(reference, bytes, signature, screening, opts)
    end

    refute_received :provider_assignment
    refute_received :provider_verify

    assert :ok = Custody.verify(reference, bytes, signature, opts)
    assert_received :provider_assignment
    assert_received :provider_verify
  end

  test "legacy screening uses one public key read for verification", ctx do
    {:ok, signer} = Local.new("ed25519", {:ed25519, ctx.seed})
    {:ok, public} = Custody.public_key(signer)
    observer = self()

    reference = %{
      signer
      | custodian: __MODULE__.Legacy,
        ref: fn ->
          send(observer, :public_key_read)
          {signer, observer}
        end
    }

    bytes = base(ctx.message)
    {:ok, signature} = Custody.sign(signer, bytes)
    {:ok, deny} = DenySet.new([])
    assert {:ok, ^public} = Custody.verify_bound(reference, bytes, signature, deny, [])
    assert_received :public_key_read
    refute_received :public_key_read
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

  defp policy(key, purpose, extra \\ %{}, algorithm \\ "ed25519") do
    entry = Map.merge(%{algorithm: algorithm, key: key}, extra)

    attrs = %{
      algorithms: [algorithm],
      components: ~s[("@method" "@path")],
      key_resolver: fn _ -> {:ok, entry} end,
      freshness: :not_evaluated,
      content: :not_required,
      replay: :not_required
    }

    attrs = if purpose == :omitted, do: attrs, else: Map.put(attrs, :require_issued_for, purpose)
    {:ok, policy} = Policy.new(attrs)
    policy
  end
end
