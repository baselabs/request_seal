defmodule RequestSeal.CustodyGenerationTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Crypto, Custody, KeyHandle, PublicKey}
  alias RequestSeal.Custody.{Context, DeriveRequest, Local}
  alias RequestSeal.JOSE.KeyManagement

  defmodule MissingRelease do
    def derive(_, _, _), do: {:error, :unsupported_operation}
    def commit(_, _, _), do: {:error, :unavailable}
  end

  test "generate supports every signing algorithm and narrows capabilities inside custody" do
    algorithms =
      Crypto.algorithms() ++
        Enum.map(~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA), &{:jws, &1})

    for algorithm <- algorithms do
      rsa? =
        algorithm in ["rsa-pss-sha512", "rsa-v1_5-sha256"] or
          algorithm in Enum.map(~w(RS256 PS256 PS384 PS512), &{:jws, &1})
      opts = if rsa?, do: [bits: 2048], else: []
      assert {:ok, handle} = Local.generate(algorithm, opts ++ [capabilities: [:sign]])
      assert handle.algorithm == algorithm
      assert handle.capabilities == [:sign]
      assert {:ok, signature} = Custody.sign(handle, "generated inside custody")
      forged = %{handle | capabilities: [:sign, :verify]}
      assert_error(
        Custody.verify(forged, "generated inside custody", signature),
        :unsupported_operation
      )

      if algorithm in ["hmac-sha256", {:jws, "HS256"}] do
        assert_error(Custody.public_key(handle), :no_public_key)
        assert {:ok, %{kind: :unknown, value: nil}} = Custody.identity(handle)
      else
        assert {:ok, public} = Custody.public_key(handle)
        assert :ok = Crypto.verify(algorithm, "generated inside custody", signature, public)
        assert_error(Crypto.verify(algorithm, "changed", signature, public), :invalid_signature)
      end

      assert :ok = Custody.release(handle)
    end
  end

  @tag timeout: 120_000
  test "generate covers every RSA size and both OAEP algorithms with exponent 65537" do
    for bits <- [2048, 3072, 4096],
        algorithm <- ["rsa-v1_5-sha256", {:jwe, "RSA-OAEP"}, {:jwe, "RSA-OAEP-256"}] do
      assert {:ok, handle} = Local.generate(algorithm, bits: bits)
      assert {:ok, %PublicKey{material: {_, modulus, 65_537}} = public} = Custody.public_key(handle)
      assert bit_size(:binary.encode_unsigned(modulus)) == bits

      case algorithm do
        {:jwe, name} ->
          {:rsa, n, e} = public.material
          cek = <<0::256>>
          assert {:ok, wrapped} = KeyManagement.wrap(name, cek, %{}, {:rsa, {:RSAPublicKey, n, e}})
          assert {:ok, [{:ok, ^cek}]} = Custody.unwrap(handle, [{wrapped.encrypted_key, %{}, 256}])

        _ ->
          assert {:ok, sig} = Custody.sign(handle, "RSA generation")
          assert :ok = Crypto.verify(algorithm, "RSA generation", sig, public)
      end

      assert :ok = Custody.release(handle)
    end
  end

  test "generate covers each agreement curve and algorithm and both AES widths with real recovery" do
    for curve <- ["P-256", "P-384", "X25519"], alg <- ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW) do
      assert {:ok, handle} = Local.generate({:jwe, alg}, curve: curve)
      assert {:ok, public} = Custody.public_key(handle)
      assert {:ok, agreed} = KeyManagement.agree(alg, "A256GCM", public, %{})
      params =
        KeyManagement.Agreement.header_params!(alg, Map.put(agreed.header, "enc", "A256GCM"))
      assert {:ok, [{:ok, cek}]} = Custody.unwrap(handle, [{agreed.encrypted_key, params, 256}])
      assert cek == agreed.cek
      assert :ok = Custody.release(handle)
    end

    for alg <- ~w(A128KW A256KW) do
      assert {:ok, handle} = Local.generate({:jwe, alg}, capabilities: [:wrap, :unwrap])
      assert {:ok, wrapped} = Custody.wrap(handle, <<1::128>>)
      assert {:ok, [{:ok, <<1::128>>}]} =
               Custody.unwrap(handle, [{wrapped.encrypted_key, %{}, 128}])
      assert_error(Custody.public_key(handle), :no_public_key)
      assert :ok = Custody.release(handle)
    end
  end

  test "generation and derivation refuse unknown misplaced missing duplicate and invalid options" do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<0::256>>})

    for opts <- [
          [],
          [curve: nil],
          [curve: "P-521"],
          [bits: 2048],
          [curve: "P-256", curve: "X25519"]
        ] do
      assert_error(Local.generate({:jwe, "ECDH-ES"}, opts), :invalid_options)
      assert_error(
        Custody.derive(parent, {:jwe, "ECDH-ES"}, "domain", [timeout: 5000] ++ opts),
        :invalid_options
      )
    end

    for opts <- [
          [curve: "P-256"],
          [bits: 2048],
          [timeout: 1],
          [unknown: true],
          [capabilities: []],
          [capabilities: [:sign, :sign]],
          [capabilities: [:derive]],
          [capabilities: nil],
          nil,
          %{}
        ] do
      assert_error(Local.generate("ed25519", opts), :invalid_options)
    end

    for opts <- [
          [],
          [timeout: 0],
          [timeout: :infinity],
          [timeout: 300_001],
          [timeout: 1, timeout: 2],
          [timeout: 5000, curve: nil],
          [timeout: 5000, curve: "P-256"],
          [timeout: 5000, capabilities: []],
          [timeout: 5000, bits: 2048],
          [timeout: 5000, capabilities: [:sign, :sign]],
          [timeout: 5000, unknown: true],
          nil
        ] do
      assert_error(Custody.derive(parent, "ed25519", "domain", opts), :invalid_options)
    end

    for opts <- [[], [bits: 1024], [bits: 8192], [bits: 2048.0], [bits: 2048, curve: "P-256"]] do
      assert_error(Local.generate("rsa-pss-sha512", opts), :invalid_options)
    end

    for algorithm <- [
          {:jwe, "A128GCMKW"},
          {:jwe, "A256GCMKW"},
          {:jwe, "dir"},
          {:derive, "hkdf-sha256"},
          "none"
        ] do
      assert_error(Local.generate(algorithm, []), :unsupported_algorithm)
      assert_error(
        Custody.derive(parent, algorithm, "domain", timeout: 5000),
        :unsupported_algorithm
      )
    end

    for algorithm <- ["rsa-pss-sha512", "ecdsa-p256-sha256", {:jws, "EdDSA"}, {:jws, "HS256"}] do
      assert_error(
        Custody.derive(parent, algorithm, "domain", timeout: 5000),
        :unsupported_algorithm
      )
    end

    for domain <- [nil, [], "", :binary.copy(<<0>>, 256)] do
      assert_error(Custody.derive(parent, "ed25519", domain, timeout: 5000), :invalid_data)
    end

    for width <- [31, 65] do
      assert_error(
        Local.new({:derive, "hkdf-sha256"}, {:ikm, :binary.copy(<<0>>, width)}),
        :invalid_key
      )
    end

    for width <- [32, 64] do
      assert {:ok, root} = Local.new({:derive, "hkdf-sha256"}, {:ikm, :binary.copy(<<0>>, width)})
      assert :ok = Custody.release(root)
    end

    assert :ok = Custody.release(parent)
  end

  test "derive construction requires all three callbacks" do
    assert_error(
      KeyHandle.new(MissingRelease, {:derive, "hkdf-sha256"}, [:derive], fn -> :ref end),
      :invalid_options
    )
  end

  test "derivation commits deterministic separated children without extending their authority" do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<1::256>>})
    assert_error(Custody.sign(parent, "no signing"), :unsupported_operation)
    assert_error(Custody.public_key(parent), :no_public_key)
    assert {:ok, first} =
             Custody.derive(parent, "ed25519", "domain", timeout: 5000, capabilities: [:sign])
    assert {:ok, second} = Custody.derive(parent, "ed25519", "domain", timeout: 5000)
    assert {:ok, different} = Custody.derive(parent, "ed25519", "other", timeout: 5000)
    assert {:ok, a} = Custody.public_key(first)
    assert {:ok, ^a} = Custody.public_key(second)
    assert {:ok, b} = Custody.public_key(different)
    refute a.material == b.material
    assert {:ok, sig} = Custody.sign(first, "child remains")
    assert_error(
      Custody.verify(%{first | capabilities: [:sign, :verify]}, "child remains", sig),
      :unsupported_operation
    )
    assert :ok = Custody.release(parent)
    assert {:ok, ^sig} = Custody.sign(first, "child remains")

    for child <- [first, second, different], do: assert(:ok == Custody.release(child))
  end

  test "all three curves separate children for the same parent and domain" do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<2::256>>})
    keys =
      for curve <- ["P-256", "P-384", "X25519"] do
        assert {:ok, child} =
                 Custody.derive(parent, {:jwe, "ECDH-ES"}, "domain", timeout: 5000, curve: curve)

        assert {:ok, public} = Custody.public_key(child)
        assert :ok = Custody.release(child)
        public.material
      end

    assert length(Enum.uniq(keys)) == 3
    assert :ok = Custody.release(parent)
  end

  test "uncommitted child refuses every operation and wrong token then commits atomically" do
    {parent, child, request, context} = candidate(5000)
    assert_error(Custody.sign(child, "probe"), :unavailable)
    assert_error(Custody.verify(child, "probe", <<0>>), :unavailable)
    assert_error(Custody.public_key(child), :unavailable)
    assert_error(Custody.identity(child), :unavailable)
    assert {:error, :unavailable} = Local.commit(child.ref, <<0::256>>, context)
    assert {:ok, :ok} =
             Custody.run(context, fn -> Local.commit(child.ref, request.token, context) end)
    {pid, access} = child.ref.()
    send(pid, {:commit_expired, access})
    assert {:ok, sig} = Custody.sign(child, "committed")
    assert :ok = Custody.verify(child, "committed", sig)
    assert {:error, :unavailable} = Local.commit(child.ref, request.token, context)
    assert :ok = Custody.release(child)
    assert :ok = Custody.release(parent)
  end

  test "a successful atomic commit survives its actual expiry deadline" do
    {parent, child, request, context} = candidate(250)
    assert {:ok, :ok} =
             Custody.run(context, fn -> Local.commit(child.ref, request.token, context) end)

    deadline(context)
    assert {:ok, _signature} = Custody.sign(child, "after expiry")
    assert :ok = Custody.release(child)
    assert :ok = Custody.release(parent)
  end

  test "binary domain bounds are inclusive and generated keys are fresh" do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<6::256>>})

    for domain <- [<<255>>, :binary.copy(<<255>>, 255)] do
      assert {:ok, child} = Custody.derive(parent, "ed25519", domain, timeout: 5000)
      assert {:ok, _signature} = Custody.sign(child, "binary domain")
      assert :ok = Custody.release(child)
    end

    assert {:ok, first} = Local.generate("ed25519", [])
    assert {:ok, second} = Local.generate("ed25519", [])
    assert {:ok, a} = Custody.public_key(first)
    assert {:ok, b} = Custody.public_key(second)
    refute a.material == b.material
    for handle <- [parent, first, second], do: assert(:ok == Custody.release(handle))
  end

  test "uncommitted candidates expire and queued late commits cannot resurrect them" do
    {parent, child, request, context} = candidate(250)
    {pid, access} = child.ref.()
    down = Process.monitor(pid)
    :erlang.suspend_process(pid)
    reply = :erlang.alias()

    try do
      send(pid, {:request, access, self(), reply, context, {:commit, request.token}})
      deadline(context)
    after
      :erlang.resume_process(pid)
    end

    assert_receive {^reply, {:error, :deadline_exceeded}}, 1000
    :erlang.unalias(reply)
    assert_receive {:DOWN, ^down, :process, ^pid, :normal}, 1000
    assert_error(Custody.sign(child, "expired"), :key_not_found)
    assert :ok = Custody.release(parent)

    {parent, child, _, _} = candidate(100)
    {pid, _} = child.ref.()
    down = Process.monitor(pid)
    assert_receive {:DOWN, ^down, :process, ^pid, :normal}, 1000
    assert :ok = Custody.release(parent)
  end

  test "owner death destroys uncommitted and committed children independently of parent" do
    for commit? <- [false, true] do
      {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<3::256>>})
      controller = self()
      {owner, owner_down} =
        spawn_monitor(fn ->
          context = context(5000)
          request = request(context.owner)
          {:ok, ref} = Custody.run(context, fn -> Local.derive(parent.ref, request, context) end)

          if commit? do
            {:ok, :ok} = Custody.run(context, fn -> Local.commit(ref, request.token, context) end)
          end

          send(controller, {:child, ref})

          receive do
            :stop -> :ok
          end
        end)

      on_exit(fn -> stop_owner(owner) end)
      assert_receive {:child, ref}, 5000
      {pid, _} = ref.()
      down = Process.monitor(pid)
      send(owner, :stop)
      assert_receive {:DOWN, ^owner_down, :process, ^owner, :normal}, 1000
      assert_receive {:DOWN, ^down, :process, ^pid, :normal}, 1000
      assert {:ok, %{kind: :unknown}} = Custody.identity(parent)
      assert :ok = Custody.release(parent)
    end
  end

  test "generated and derived handles expose no raw key operation or secret-bearing state" do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<4::256>>})
    {:ok, generated} = Local.generate("hmac-sha256", [])
    {:ok, derived} = Custody.derive(parent, "ed25519", "domain", timeout: 5000)

    for handle <- [parent, generated, derived] do
      {pid, token} = handle.ref.()
      {:env, captured} = :erlang.fun_info(handle.ref, :env)
      assert Enum.sort(captured) == Enum.sort([pid, token])
      assert Process.info(pid, :dictionary) == {:dictionary, []}
      error = assert_raise ErlangError, fn -> :sys.get_state(pid) end
      assert error.original == :unsupported_operation

      for operation <- [:export, :material, :private_key] do
        reply = :erlang.alias()
        send(pid, {:request, token, self(), reply, context(1000), operation})
        assert_receive {^reply, result}, 1000

        assert match?({:error, %Custody.Error{reason: :custodian_failure}}, result),
               "raw key export must be refused"

        :erlang.unalias(reply)
      end

      assert :ok = Custody.release(handle)
    end
  end

  defp candidate(timeout) do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<5::256>>})
    context = context(timeout)
    request = request(self())
    {:ok, ref} = Custody.run(context, fn -> Local.derive(parent.ref, request, context) end)
    child = %KeyHandle{
      custodian: Local,
      algorithm: "ed25519",
      capabilities: [:sign, :verify],
      ref: ref
    }

    {parent, child, request, context}
  end

  defp context(timeout),
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}

  defp request(owner),
    do: %DeriveRequest{
      target: %{algorithm: "ed25519", curve: nil},
      domain: "domain",
      capabilities: [:sign, :verify],
      owner: owner,
      token: :crypto.strong_rand_bytes(32)
    }

  defp stop_owner(owner) do
    monitor = Process.monitor(owner)
    Process.exit(owner, :kill)

    receive do
      {:DOWN, ^monitor, :process, ^owner, _} -> :ok
    end
  end

  defp deadline(context) do
    tag = make_ref()
    Process.send_after(self(), tag, Context.remaining(context) + 1)

    receive do
      ^tag -> :ok
    end
  end

  defp assert_error({:error, %{reason: reason}}, reason), do: :ok
end
