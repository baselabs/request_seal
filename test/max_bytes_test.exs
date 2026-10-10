defmodule RequestSeal.MaxBytesTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Crypto, Custody}
  alias RequestSeal.Custody.{Context, Local, Support}

  # A real Local custodian with only the required callbacks: verification must
  # resolve its actual public key through Custody's optional-callback fallback.
  defmodule PublicKeyFallback do
    @behaviour RequestSeal.Custody
    defdelegate sign(ref, algorithm, bytes, context), to: RequestSeal.Custody.Local
    defdelegate public_key(ref), to: RequestSeal.Custody.Local
    defdelegate identity(ref), to: RequestSeal.Custody.Local
  end

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed})
    on_exit(fn -> Local.release(handle) end)
    {:ok, handle: handle, seed: seed}
  end

  test "one public ceiling names the inclusive 16 MiB bound" do
    assert Crypto.max_bytes_ceiling() == 16_777_216
  end

  for operation <- [:sign, :verify] do
    test "#{operation} rejects invalid max_bytes before an invalid handle" do
      assert_reason(call(unquote(operation), :bad, "x", max_bytes: 0), :invalid_options)
    end

    test "#{operation} rejects invalid max_bytes before unsupported capability", %{handle: handle} do
      capabilities = if unquote(operation) == :sign, do: [:verify], else: [:sign]
      restricted = %{handle | capabilities: capabilities}
      assert_reason(call(unquote(operation), restricted, "x", []), :unsupported_operation)
      assert_reason(call(unquote(operation), restricted, "x", max_bytes: 0), :invalid_options)
    end

    test "#{operation} accepts timeout and max_bytes in either order", %{handle: handle} do
      for opts <- [[timeout: 5_000, max_bytes: 10], [max_bytes: 10, timeout: 5_000]] do
        assert_success(call(unquote(operation), handle, "x", opts))
      end
    end

    test "#{operation} rejects max_bytes combined with an unknown option", %{handle: handle} do
      assert_reason(
        call(unquote(operation), handle, "x", max_bytes: 10, unknown: 1),
        :invalid_options
      )
    end

    test "Crypto #{operation} validates options before resolving the algorithm" do
      key = {:hmac, :binary.copy(<<1>>, 32)}
      args = if unquote(operation) == :sign, do: ["x", key], else: ["x", <<>>, key]

      assert_reason(
        apply(Crypto, unquote(operation), [:unknown | args] ++ [[]]),
        :unsupported_algorithm
      )

      for opts <- [[max_bytes: 0], [unknown: 1], [max_bytes: 1, max_bytes: 2]] do
        assert_reason(
          apply(Crypto, unquote(operation), [:unknown | args] ++ [opts]),
          :invalid_options
        )
      end
    end

    test "Local #{operation} bounds direct calls before reading the reference", %{
      handle: handle,
      seed: seed
    } do
      owner = self()
      original = handle.ref

      observed = %{
        handle
        | ref: fn ->
            send(owner, :reference_read)
            original.()
          end
      }

      assert_success(direct(unquote(operation), observed, "x", seed))
      assert_receive :reference_read

      for bytes <- [:binary.copy(<<0>>, 16_777_217), :not_binary] do
        assert_reason(direct(unquote(operation), observed, bytes, seed), :invalid_data)
        refute_receive :reference_read, 20
      end
    end

    test "Local #{operation} accepts the full ceiling when called directly", %{
      handle: handle,
      seed: seed
    } do
      assert_success(direct(unquote(operation), handle, :binary.copy(<<0>>, 16_777_216), seed))
    end
  end

  test "Support.max_bytes independently rejects malformed keyword input" do
    assert Support.max_bytes([]) == 1_048_576
    assert Support.max_bytes(timeout: 5_000, max_bytes: 10) == 10

    for opts <- [
          :bad,
          %{},
          [1],
          [{:max_bytes, 1} | :bad],
          [max_bytes: 1, max_bytes: 2],
          [foo: 1],
          [timeout: 1, foo: 1]
        ] do
      assert {:custody_error, :invalid_options} = catch_throw(Support.max_bytes(opts))
    end
  end

  test "public-key fallback verifies 1,235,403 bytes and the full ceiling", %{
    handle: handle,
    seed: seed
  } do
    assert function_exported?(PublicKeyFallback, :public_key, 1)
    refute function_exported?(PublicKeyFallback, :verify, 5)
    fallback = %{handle | custodian: PublicKeyFallback}

    for {size, max} <- [{1_235_403, 2_097_152}, {16_777_216, 16_777_216}] do
      bytes = :binary.copy(<<0>>, size)
      signature = :crypto.sign(:eddsa, :none, bytes, [seed, :ed25519])
      assert :ok = Custody.verify(fallback, bytes, signature, max_bytes: max)
    end
  end

  test "Local signs and verifies the full ceiling and rejects the next byte", %{
    handle: handle,
    seed: seed
  } do
    bytes = :binary.copy(<<0>>, 16_777_216)
    expected = :crypto.sign(:eddsa, :none, bytes, [seed, :ed25519])
    assert {:ok, ^expected} = Custody.sign(handle, bytes, max_bytes: 16_777_216)
    assert :ok = Custody.verify(handle, bytes, expected, max_bytes: 16_777_216)
    assert_reason(Custody.sign(handle, bytes <> <<0>>, max_bytes: 16_777_216), :invalid_data)

    assert_reason(
      Custody.verify(handle, bytes <> <<0>>, expected, max_bytes: 16_777_216),
      :invalid_data
    )
  end

  defp call(:sign, handle, bytes, opts), do: Custody.sign(handle, bytes, opts)

  defp call(:verify, handle, bytes, opts) do
    # A valid signature comes from the actual Local holder, even when the
    # facade handle under test has only :verify capability.
    signature =
      if is_struct(handle),
        do: elem(Local.sign(handle.ref, "ed25519", bytes, context()), 1),
        else: <<>>

    Custody.verify(handle, bytes, signature, opts)
  end

  defp direct(:sign, handle, bytes, _seed),
    do: Local.sign(handle.ref, "ed25519", bytes, context())

  defp direct(:verify, handle, bytes, seed) do
    signature =
      if is_binary(bytes), do: :crypto.sign(:eddsa, :none, bytes, [seed, :ed25519]), else: <<>>

    Local.verify(handle.ref, "ed25519", bytes, signature, context())
  end

  defp context,
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}

  defp assert_success({:ok, signature}), do: assert(is_binary(signature))
  defp assert_success(:ok), do: :ok
  defp assert_success(other), do: flunk("expected success, got: #{inspect(other)}")
  defp assert_reason({:error, %{reason: reason}}, expected), do: assert(reason == expected)
  defp assert_reason({:error, reason}, expected), do: assert(reason == expected)
end
