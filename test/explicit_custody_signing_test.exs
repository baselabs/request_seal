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

    assert {:error,
            %{reason: :signing_failed, source: %Custody.Error{reason: :deadline_exceeded}}} =
             RequestSeal.sign(c.message, c.spec, handle, signing_timeout: 50)

    assert_received {:signing, runner, _context}
    refute Process.alive?(runner)
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
    spec = %{label: "sig", algorithm: "ed25519", components: ~s[("@method")], expires_in: 60}

    assert {:error, %{reason: :signing_failed, source: %Custody.Error{reason: :key_not_found}}} =
             RequestSeal.sign(c.message, spec, c.handle)
  end
end
