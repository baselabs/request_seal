defmodule RequestSeal.ExplicitCustodySigningTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Custody, Error, KeyHandle}
  alias RequestSeal.Custody.Local

  defmodule BlockingCustodian do
    @moduledoc false
    @behaviour Custody
    @impl true
    def sign(ref, _, _, context) do
      send(ref.(), {:signing, self(), context})

      receive do
        :finish -> {:error, :custodian_rejected}
      end
    end

    @impl true
    def public_key(_), do: {:error, :unsupported_operation}
    @impl true
    def identity(_), do: %RequestSeal.KeyIdentity{kind: :unknown}
  end

  setup do
    # RFC 8032 Section 7.1, test 1: public independent Ed25519 seed.
    seed = Base.decode16!("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed})
    {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)

    spec = %{
      label: "sig",
      algorithm: "ed25519",
      signature_input: ~s[("@method" "@path");alg="ed25519"]
    }

    %{handle: handle, message: message, spec: spec}
  end

  test "explicit handle preserves function-signer wire bytes", c do
    assert {:ok, expected} =
             RequestSeal.sign(c.message, c.spec, fn _, base -> Custody.sign(c.handle, base) end)

    assert {:ok, actual} = RequestSeal.sign(c.message, c.spec, c.handle)
    assert actual == expected

    assert {:ok, ^actual} =
             RequestSeal.sign(c.message, c.spec, c.handle, signing_timeout: 300_000)
  end

  test "released explicit handle retains the bounded custody source", c do
    assert :ok = Local.release(c.handle)

    assert {:error,
            %{
              reason: :signing_failed,
              layer: :crypto,
              source: %Custody.Error{reason: :key_not_found}
            }} =
             RequestSeal.sign(c.message, c.spec, c.handle)
  end

  test "blocking explicit custodian expires and its worker exits", c do
    parent = self()

    handle = %KeyHandle{
      custodian: BlockingCustodian,
      algorithm: "ed25519",
      capabilities: [:sign],
      ref: fn -> parent end
    }

    started = System.monotonic_time(:millisecond)

    assert {:error,
            %{
              reason: :signing_failed,
              source: %Custody.Error{reason: :deadline_exceeded, retryable: true},
              retryable: false
            }} =
             RequestSeal.sign(c.message, c.spec, handle, signing_timeout: 50)

    assert System.monotonic_time(:millisecond) - started < 1_000
    assert_received {:signing, runner, _context}
    refute Process.alive?(runner)
  end

  test "explicit deadline above the default permits a real delayed signature", c do
    {holder, _} = c.handle.ref.()
    parent = self()

    timer =
      Task.async(fn ->
        :erlang.suspend_process(holder)
        send(parent, :holder_suspended)
        Process.sleep(5_500)
        :erlang.resume_process(holder)
      end)

    assert_receive :holder_suspended
    started = System.monotonic_time(:millisecond)

    try do
      assert {:ok, actual} = RequestSeal.sign(c.message, c.spec, c.handle, signing_timeout: 6_000)
      assert System.monotonic_time(:millisecond) - started >= 5_000
      assert {:ok, ^actual} = RequestSeal.sign(c.message, c.spec, c.handle)
    after
      Task.await(timer, 7_000)
    end
  end

  test "malformed signing output has a signing-output reason on both forms", c do
    for output <- [<<>>, :not_bytes, :binary.copy(<<1>>, 1_025)] do
      handle = transformed_handle(c.handle, fn {:ok, _signature} -> {:ok, output} end)

      for spec <- [c.spec, generated_spec()] do
        assert {:error,
                %Error{
                  reason: :signing_failed,
                  layer: :crypto,
                  source: %Custody.Error{reason: :invalid_signing_output, retryable: false}
                }} =
                 RequestSeal.sign(c.message, spec, handle)
      end
    end
  end

  test "malformed custody errors agree on reason and source on both forms", c do
    handle =
      transformed_handle(c.handle, fn {:ok, _signature} -> {:error, {:private, "untrusted"}} end)

    for spec <- [c.spec, generated_spec()] do
      assert {:error,
              %Error{
                reason: :signing_failed,
                layer: :crypto,
                source: %Custody.Error{reason: :custodian_failure, retryable: false}
              }} =
               RequestSeal.sign(c.message, spec, handle)
    end
  end

  defp generated_spec do
    %{label: "sig", algorithm: "ed25519", components: ~s[("@method")], expires_in: 60}
  end

  # Perform real local signing, then corrupt its result to exercise the caller
  # callback boundary. This makes no external conformance claim.
  defp transformed_handle(local, transform) do
    %KeyHandle{
      custodian: RequestSeal.Signing.FunctionCustodian,
      algorithm: local.algorithm,
      capabilities: [:sign],
      ref: fn -> fn _, base -> transform.(Custody.sign(local, base)) end end
    }
  end

  test "algorithm mismatch has a stable distinct reason and message", c do
    assert {:ok, other} = Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)})

    assert {:error,
            %{
              reason: :signer_algorithm_mismatch,
              layer: :input,
              message: "signer algorithm does not match signature specification"
            }} =
             RequestSeal.sign(c.message, c.spec, other)
  end

  test "invalid explicit deadlines reject before invoking custody", c do
    for timeout <- [0, -1, 300_001, 1.0, :infinity, nil] do
      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.sign(c.message, c.spec, c.handle, signing_timeout: timeout)
    end

    for opts <- [[signing_timeout: 1, signing_timeout: 2], [unknown: true]] do
      assert {:error, %Error{reason: :invalid_options}} =
               RequestSeal.sign(c.message, c.spec, c.handle, opts)
    end
  end

  test "function signers still execute synchronously with their existing errors", c do
    owner = self()

    signer = fn _, base ->
      assert self() == owner
      Custody.sign(c.handle, base)
    end

    assert {:ok, _} = RequestSeal.sign(c.message, c.spec, signer)

    assert {:error, %Error{reason: :signer_failed}} =
             RequestSeal.sign(c.message, c.spec, fn _, _ -> raise "private" end)
  end

  test "generated signing specs also preserve custody errors", c do
    :ok = Local.release(c.handle)

    for spec <- [generated_spec(), RequestSeal.Signing.normalize_spec!(generated_spec())] do
      assert {:error,
              %Error{
                reason: :signing_failed,
                layer: :crypto,
                retryable: false,
                source: %Custody.Error{reason: :key_not_found, retryable: false}
              }} = RequestSeal.sign(c.message, spec, c.handle)
    end
  end
end
