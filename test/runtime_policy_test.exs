Code.require_file("support/plug_transport_helper.exs", __DIR__)

defmodule RequestSeal.RuntimePolicyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.PlugTransport, as: T
  alias RequestSeal.Plug.Verify
  alias RequestSeal.Adapter.Error

  test "policy functions and MFAs resolve a valid policy on each real request" do
    policy = T.published_policy("B.2.6")
    RequestSeal.DocsExamples.configure(:request_seal, :runtime_policy, policy)

    for source <- [
          fn -> Application.fetch_env!(:request_seal, :runtime_policy) end,
          {Application, :fetch_env!, [:request_seal, :runtime_policy]}
        ] do
      options = Verify.init(policy: source, label: "sig-b26", on_reject: {:halt, 401})
      assert options[:policy] == source

      {origin, _} =
        T.start(
          owner: self(),
          policy: source,
          label: "sig-b26",
          origin: {:declared, "https", "example.com"},
          on_reject: {:halt, 401}
        )

      Application.put_env(:request_seal, :runtime_policy, policy)
      T.raw(origin, T.wire("B.2.6"))
      assert_receive {:first_verification, {:ok, %{signature: %{crypto: :valid}}}}
      assert_receive {:observed, _, _, {:ok, _}}

      Application.put_env(:request_seal, :runtime_policy, %{policy | components: "invalid"})
      assert T.raw(origin, T.wire("B.2.6")) =~ "HTTP/1.1 401"
      assert_receive {:first_verification, :error}
      assert_receive {:observed, conn, _, :error}

      assert {:error, %Error{reason: :invalid_options, source: nil}} =
               conn.private.request_seal.verification

      assert conn.halted
    end
  end

  test "JWS short specs omit alg through both adapters with real HTTP verification" do
    {:ok, handle} =
      RequestSeal.Custody.Local.import(
        {:jws, "EdDSA"},
        File.read!(Path.join(__DIR__, "fixtures/crypto/ed25519_private.pem")),
        :pem
      )

    on_exit(fn -> RequestSeal.Custody.Local.release(handle) end)
    start_supervised!({Finch, name: __MODULE__.Pool})
    components = ~s[("@method" "@authority" "@path")]
    policy = T.policy(components, algorithm: {:jws, "EdDSA"}, content: :not_required)
    {origin, _} = T.start(owner: self(), policy: policy)
    spec = %{label: "sig", algorithm: {:jws, "EdDSA"}, components: components, expires_in: 60}

    assert {:ok, request} =
             RequestSeal.Req.attach(
               Req.new(url: origin, finch: [name: __MODULE__.Pool], retry: false),
               sign: spec,
               signer: handle,
               verify: :none
             )

    assert {:ok, %{status: 200}} = Req.request(request)
    assert_receive {:observed, _, {:ok, captured}, {:ok, _}}
    input = Enum.find(captured.message.fields, &(&1.name == "signature-input")).value
    assert input =~ ";nonce="
    refute input =~ ";alg="

    assert {:ok, request} = RequestSeal.Finch.sign(Finch.build(:get, origin), spec, handle)
    assert {:ok, %{status: 200}} = Finch.request(request, __MODULE__.Pool)
    assert_receive {:observed, _, {:ok, captured}, {:ok, _}}
    input = Enum.find(captured.message.fields, &(&1.name == "signature-input")).value
    refute input =~ ";alg="
    assert input =~ ";created="
    assert input =~ ";expires="

    for bad <- [Map.put(spec, :alg, true), Map.put(spec, :unknown, true)] do
      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.Finch.sign(Finch.build(:get, origin), bad, handle)

      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.Req.attach(
                 Req.new(url: origin),
                 sign: bad,
                 signer: handle,
                 verify: :none
               )
    end
  end

  test "invalid policy sources reject during initialization" do
    for source <- [
          nil,
          %{},
          fn _ -> :error end,
          {Application, :fetch_env!, :bad},
          {Application, :not_exported, []},
          {nil, :fetch, []},
          {"module", :fetch, []}
        ] do
      assert_raise Error, fn ->
        Verify.init(policy: source, label: "sig", on_reject: :continue)
      end
    end
  end

  test "policy resolution failures are bounded and halt real requests" do
    for source <- [
          fn -> :invalid end,
          fn -> raise "policy-secret" end,
          fn -> throw("policy-secret") end,
          fn -> exit("policy-secret") end,
          {Application, :fetch_env!, [:request_seal, :unset_runtime_policy]}
        ] do
      {origin, _} =
        T.start(
          owner: self(),
          policy: source,
          label: "sig-b26",
          origin: {:declared, "https", "example.com"},
          on_reject: {:halt, 401},
          assign: :verified
        )

      assert T.raw(origin, T.wire("B.2.6")) =~ "HTTP/1.1 401"
      assert_receive {:observed, conn, _, :error}
      assert {:error, %Error{source: nil} = error} = conn.private.request_seal.verification
      assert error.reason in [:invalid_options, :response_rejected]
      refute inspect(error) =~ "policy-secret"
      refute Map.has_key?(conn.assigns, :verified)
      assert conn.halted
    end
  end

  test "missing capture and repeat attempts do not resolve runtime policy" do
    owner = self()

    source = fn ->
      send(owner, :policy_resolved)
      T.published_policy("B.2.6")
    end

    {origin, _} =
      T.start(
        owner: owner,
        policy: source,
        label: "sig-b26",
        twice: true,
        origin: {:declared, "https", "example.com"}
      )

    T.raw(origin, T.wire("B.2.6"))
    assert_receive :policy_resolved
    assert_receive {:observed, conn, _, :error}
    assert {:error, %Error{reason: :already_verified}} = conn.private.request_seal.verification
    refute_receive :policy_resolved

    options = Verify.init(policy: source, label: "sig", on_reject: :continue)
    conn = Verify.call(%Plug.Conn{}, options)
    assert {:error, %Error{reason: :not_captured}} = conn.private.request_seal.verification
    refute_receive :policy_resolved
  end
end
