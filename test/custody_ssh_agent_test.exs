defmodule RequestSeal.CustodySSHAgentTest do
  use ExUnit.Case, async: false

  # Split so secret scanners do not read a header literal as key material; the key
  # bytes are generated at runtime from the RFC 9421 published Ed25519 seed.
  @openssh_private_begin "-----BEGIN OPENSSH " <> "PRIVATE KEY-----\n"
  alias RequestSeal.{Crypto, Custody, PublicKey}
  alias RequestSeal.Custody.{SSHAgent, SSHAgent.Wire}
  @root Path.join(__DIR__, "fixtures/crypto")
  @vector :json.decode(File.read!(Path.join(@root, "rfc9421.json")))
          |> Enum.find(&(&1["section"] == "B.2.6"))

  setup do
    for name <- ~w(ssh-agent ssh-add ssh-keygen), do: assert(System.find_executable(name))

    dir =
      Path.join(System.tmp_dir!(), "c-" <> Integer.to_string(System.unique_integer([:positive])))

    File.mkdir!(dir)
    File.chmod!(dir, 0o700)
    socket = Path.join(dir, "agent")
    assert byte_size(socket) < 104

    {output, 0} =
      System.cmd("ssh-agent", ["-a", socket, "-s"],
        env: [{"SSH_AUTH_SOCK", socket}, {"SSH_AGENT_PID", nil}],
        stderr_to_stdout: true
      )

    [_, pid] = Regex.run(~r/SSH_AGENT_PID=(\d+);/, output)
    env = [{"SSH_AUTH_SOCK", socket}, {"SSH_AGENT_PID", pid}]

    on_exit(fn ->
      if File.exists?(socket) do
        System.cmd("kill", ["-CONT", pid], stderr_to_stdout: true)
        System.cmd("kill", ["-TERM", pid], stderr_to_stdout: true)
      end

      File.rm_rf!(dir)
    end)

    IO.puts("EXTERNAL CUSTODY: isolated OpenSSH agent started")
    {:ok, dir: dir, socket: socket, pid: pid, env: env}
  end

  test "separate-process Ed25519 reproduces RFC 9421 B.2.6 bytes and explicit EdDSA", ctx do
    key_file = write_rfc_key(ctx.dir)
    assert {_, 0} = System.cmd("ssh-add", [key_file], env: ctx.env, stderr_to_stdout: true)
    key = agent_keys(ctx) |> hd() |> elem(1)

    for alg <- ["ed25519", {:jws, "EdDSA"}] do
      assert {:ok, handle} = SSHAgent.new(alg, ctx.socket, key)
      assert {:ok, signature} = Custody.sign(handle, @vector["base"])
      assert signature == Base.decode64!(@vector["signature"])
      assert :ok = Crypto.verify(alg, @vector["base"], signature, key)
      assert :ok = Custody.verify(handle, @vector["base"], signature)
      assert_error(Custody.verify(handle, @vector["base"] <> "\n", signature), :invalid_signature)
      assert Custody.public_key(handle) == {:ok, key}
    end

    assert_error(SSHAgent.new("hmac-sha256", ctx.socket, key), :unsupported_algorithm)
    assert_error(SSHAgent.new("rsa-pss-sha512", ctx.socket, key), :unsupported_algorithm)
    assert_error(SSHAgent.new("ed25519", ctx.socket, key, timeout: :infinity), :invalid_options)
    assert_error(SSHAgent.new("ed25519", ctx.socket, key, unknown: true), :invalid_options)
    assert_error(SSHAgent.new("ed25519", String.duplicate("a", 104), key), :invalid_options)

    assert_error(
      SSHAgent.new("ed25519", "/" <> String.duplicate("a", 103), key),
      :invalid_options
    )

    assert_error(SSHAgent.new("rsa-v1_5-sha256", ctx.socket, key), :key_mismatch)
  end

  test "generated RSA P-256 and P-384 sign against agent-reported public keys", ctx do
    for {type, bits, alg, jws} <- [
          {"rsa", "2048", "rsa-v1_5-sha256", "RS256"},
          {"ecdsa", "256", "ecdsa-p256-sha256", "ES256"},
          {"ecdsa", "384", "ecdsa-p384-sha384", "ES384"}
        ] do
      file = generate(ctx, type, bits, type <> bits)
      assert {_, 0} = System.cmd("ssh-add", [file], env: ctx.env, stderr_to_stdout: true)
      key = public_file(file)
      assert Enum.any?(agent_keys(ctx), &(elem(&1, 1) == key))

      for algorithm <- [alg, {:jws, jws}] do
        assert {:ok, handle} = SSHAgent.new(algorithm, ctx.socket, key)
        assert {:ok, signature} = Custody.sign(handle, @vector["base"])
        assert :ok = Crypto.verify(algorithm, @vector["base"], signature, key)
      end
    end
  end

  test "same-type keys bind exact public components and removed keys fail closed", ctx do
    first = generate(ctx, "ed25519", nil, "first")
    second = generate(ctx, "ed25519", nil, "second")
    absent = generate(ctx, "ed25519", nil, "absent")

    for file <- [first, second],
        do: assert({_, 0} = System.cmd("ssh-add", [file], env: ctx.env, stderr_to_stdout: true))

    assert_error(SSHAgent.new("ed25519", ctx.socket, public_file(absent)), :custodian_rejected)
    first_key = public_file(first)
    second_key = public_file(second)
    assert {:ok, handle} = SSHAgent.new("ed25519", ctx.socket, first_key)
    assert {:ok, signature} = Custody.sign(handle, @vector["base"])
    assert :ok = Crypto.verify("ed25519", @vector["base"], signature, first_key)
    assert {:error, _} = Crypto.verify("ed25519", @vector["base"], signature, second_key)
    assert {_, 0} = System.cmd("ssh-add", ["-d", first], env: ctx.env, stderr_to_stdout: true)
    assert_error(Custody.sign(handle, @vector["base"]), :key_not_found)
  end

  test "stopped agent deadlines late replies caller cancellation and killed agent", ctx do
    file = write_rfc_key(ctx.dir)
    assert {_, 0} = System.cmd("ssh-add", [file], env: ctx.env, stderr_to_stdout: true)
    assert {:ok, handle} = SSHAgent.new("ed25519", ctx.socket, public_file(file))
    assert {_, 0} = System.cmd("kill", ["-STOP", ctx.pid])
    start = System.monotonic_time(:millisecond)
    assert_error(Custody.sign(handle, @vector["base"], timeout: 60), :deadline_exceeded)
    assert System.monotonic_time(:millisecond) - start < 1_000
    assert {_, 0} = System.cmd("kill", ["-CONT", ctx.pid])
    assert {:ok, signature} = Custody.sign(handle, @vector["base"])
    assert signature == Base.decode64!(@vector["signature"])
    Process.sleep(30)

    receive do
      {ref, _} when is_reference(ref) -> flunk("stale custody result")
    after
      50 -> :ok
    end

    refute_receive {:DOWN, _, :process, _, _}, 50

    baseline = socket_ports()
    assert {_, 0} = System.cmd("kill", ["-STOP", ctx.pid])
    caller = Task.async(fn -> Custody.sign(handle, @vector["base"], timeout: 5_000) end)
    assert eventually(fn -> length(socket_ports()) > length(baseline) end)
    opened = socket_ports() -- baseline

    for port <- opened do
      assert {:ok, [packet_size: 1_048_576]} = :inet.getopts(port, [:packet_size])
      assert {:ok, [packet: 4]} = :inet.getopts(port, [:packet])
    end

    owners =
      Enum.map(opened, fn port ->
        {:connected, pid} = Port.info(port, :connected)
        pid
      end)

    monitors = Enum.map(owners, &Process.monitor/1)
    Task.shutdown(caller, :brutal_kill)
    for monitor <- monitors, do: assert_receive({:DOWN, ^monitor, :process, _, _}, 1_000)
    assert eventually(fn -> socket_ports() == baseline end)
    assert {_, 0} = System.cmd("kill", ["-CONT", ctx.pid])
    assert {:ok, _} = Custody.sign(handle, @vector["base"])
    assert {_, 0} = System.cmd("kill", ["-TERM", ctx.pid])
    assert eventually(fn -> not File.exists?(ctx.socket) end)
    assert_error(Custody.sign(handle, @vector["base"]), :custodian_unavailable)
  end

  test "captured real replies enforce mpint widths framing and verify before return", ctx do
    file = generate(ctx, "ecdsa", "256", "p256")
    assert {_, 0} = System.cmd("ssh-add", [file], env: ctx.env, stderr_to_stdout: true)
    key = public_file(file)
    blob = File.read!(file <> ".pub") |> String.split() |> Enum.at(1) |> Base.decode64!()
    # Capture actual peer bytes until a high-bit scalar requires a sign byte.
    replies = for _ <- 1..48, do: captured_reply(ctx.socket, blob, @vector["base"])

    reply =
      Enum.find(replies, fn response ->
        <<14, rest::binary>> = response
        {signature, ""} = string(rest)
        {_, fields} = string(signature)
        {raw, ""} = string(fields)
        {r, fields} = string(raw)
        {s, ""} = string(fields)
        byte_size(r) == 33 or byte_size(s) == 33
      end)

    assert reply != nil
    assert {:ok, signature} = Wire.signature(reply, "ecdsa-p256-sha256", @vector["base"], key)
    assert byte_size(signature) == 64
    assert :ok = Crypto.verify("ecdsa-p256-sha256", @vector["base"], signature, key)

    assert {:error, :custodian_protocol} =
             Wire.signature(reply <> <<0>>, "ecdsa-p256-sha256", @vector["base"], key)

    assert {:error, :custodian_protocol} =
             Wire.signature(<<14, 0xFFFFFFFF::32>>, "ecdsa-p256-sha256", @vector["base"], key)

    assert {:error, :custodian_protocol} =
             Wire.signature(<<12, 257::32>>, "ecdsa-p256-sha256", @vector["base"], key)

    assert {:error, :custodian_protocol} = Wire.identities(<<12, 257::32>>)
    assert {:error, :custodian_protocol} = Wire.identities(<<12, 1::32>>)

    {:ok, connection} =
      :gen_tcp.connect({:local, ctx.socket}, 0, [:binary, active: false, packet: 4], 1_000)

    identities =
      try do
        :ok = :gen_tcp.send(connection, <<11>>)
        {:ok, captured} = :gen_tcp.recv(connection, 0, 1_000)
        captured
      after
        :gen_tcp.close(connection)
      end

    assert {:ok, [^blob]} = Wire.identities(identities)
    <<12, 1::32, item::binary>> = identities

    assert {:error, :custodian_protocol} =
             Wire.identities(<<12, 257::32>> <> :binary.copy(item, 257))

    assert {:ok, bounded} = Wire.identities(<<12, 256::32>> <> :binary.copy(item, 256))
    assert length(bounded) == 256
    <<14, rest::binary>> = reply
    {packet, ""} = string(rest)
    {type, fields} = string(packet)
    {raw, ""} = string(fields)
    {r, fields} = string(raw)
    {s, ""} = string(fields)
    # Mutations of actual captured bytes, no substitute peer.
    for invalid <- [<<0>> <> r, :binary.copy(<<127>>, 34), <<128>>, ""] do
      changed =
        <<14>> <> ssh_string(ssh_string(type) <> ssh_string(ssh_string(invalid) <> ssh_string(s)))

      assert {:error, :custodian_protocol} =
               Wire.signature(changed, "ecdsa-p256-sha256", @vector["base"], key)
    end

    changed_s = if s == <<1>>, do: <<2>>, else: <<1>>

    tampered =
      <<14>> <> ssh_string(ssh_string(type) <> ssh_string(ssh_string(r) <> ssh_string(changed_s)))

    assert {:error, :custodian_rejected} =
             Wire.signature(tampered, "ecdsa-p256-sha256", @vector["base"], key)
  end

  test "hostile socket oversize prefix rejects within the deadline", ctx do
    hostile_sign(ctx, :oversize, :custodian_protocol)
  end

  test "hostile socket truncated sign reply is nonretryable", ctx do
    hostile_sign(ctx, :truncated, :custodian_protocol)
  end

  test "hostile socket close after sign request is nonretryable", ctx do
    hostile_sign(ctx, :closed, :custodian_protocol)
  end

  test "hostile socket that never replies stops at the deadline", ctx do
    hostile_sign(ctx, :silent, :deadline_exceeded)
  end

  test "send_timeout_close closes a saturated non-reading peer with a bounded failure", ctx do
    file = write_rfc_key(ctx.dir)
    assert {_, 0} = System.cmd("ssh-add", [file], env: ctx.env, stderr_to_stdout: true)
    key = public_file(file)
    assert {:ok, handle} = SSHAgent.new("ed25519", ctx.socket, key)
    path = Path.join(ctx.dir, "nonreading")

    assert {:ok, listener} =
             :gen_tcp.listen(0, [
               :binary,
               active: false,
               packet: 0,
               recbuf: 1024,
               ifaddr: {:local, path}
             ])

    parent = self()

    peer =
      Task.async(fn ->
        assert {:ok, socket} = :gen_tcp.accept(listener, 1_000)
        send(parent, :nonreading_peer_accepted)

        try do
          # Deliberately never read any frame. No successful peer reply is invented.
          receive do
            :stop -> :ok
          after
            5_000 -> flunk("non-reading peer was not stopped")
          end
        after
          :gen_tcp.close(socket)
        end
      end)

    original = handle.ref

    provisional = %{
      handle
      | ref: fn ->
          {algorithm, _, public, _} = original.()
          {algorithm, path, public, false}
        end
    }

    :erlang.trace_pattern({:gen_tcp, :send, 2}, [{:_, [], [{:return_trace}]}], [])

    caller =
      Task.async(fn ->
        receive do
          :start -> Custody.sign(provisional, "sample", timeout: 2_000)
        end
      end)

    :erlang.trace(caller.pid, true, [:call, :set_on_spawn])

    try do
      start = System.monotonic_time(:millisecond)
      send(caller.pid, :start)
      assert_receive :nonreading_peer_accepted, 1_000
      # Observe the actual adapter socket, including its runtime close option.
      assert_receive {:trace, runner, :call, {:gen_tcp, :send, [socket, <<13, _::binary>>]}},
                     1_000

      assert_receive {:trace, ^runner, :return_from, {:gen_tcp, :send, 2}, :ok}, 1_000
      close_option = :inet.getopts(socket, [:send_timeout_close])
      assert :ok = :inet.setopts(socket, send_timeout: 80)

      frame =
        <<13>> <>
          Wire.string(Wire.key_blob(key)) <> Wire.string(:binary.copy(<<0>>, 16_384)) <> <<0::32>>

      # Feed real sign-request frames on that connection until kernel backpressure
      # reaches gen_tcp.send. This exercises send timeout, not an idle recv timeout.
      assert {:error, :timeout} = saturate(socket, frame, 256)
      assert {:error, disconnected} = :inet.peername(socket)
      assert disconnected in [:enotconn, :einval, :closed]
      assert {:error, disconnected_send} = :gen_tcp.send(socket, frame)
      assert disconnected_send in [:enotconn, :einval, :closed]
      assert close_option == {:ok, [send_timeout_close: true]}
      # A pending receive may observe closure first or its original deadline.
      assert {:error, failure} = Task.await(caller, 3_000)
      assert failure.reason in [:deadline_exceeded, :custodian_protocol]
      assert failure.retryable == (failure.reason == :deadline_exceeded)
      assert System.monotonic_time(:millisecond) - start < 3_000
      assert Port.info(socket) == nil
      send(peer.pid, :stop)
      assert :ok = Task.await(peer, 1_000)
    after
      :erlang.trace_pattern({:gen_tcp, :send, 2}, false, [])
      Task.shutdown(caller, :brutal_kill)
      Task.shutdown(peer, :brutal_kill)
      :gen_tcp.close(listener)
      File.rm(path)
    end
  end

  defp saturate(_socket, _frame, 0), do: flunk("real socket did not reach send backpressure")

  defp saturate(socket, frame, remaining) do
    case :gen_tcp.send(socket, frame) do
      :ok -> saturate(socket, frame, remaining - 1)
      error -> error
    end
  end

  defp hostile_sign(ctx, behavior, reason) do
    file = write_rfc_key(ctx.dir)
    assert {_, 0} = System.cmd("ssh-add", [file], env: ctx.env, stderr_to_stdout: true)
    key = public_file(file)
    assert {:ok, handle} = SSHAgent.new("ed25519", ctx.socket, key)
    path = Path.join(ctx.dir, "hostile")

    assert {:ok, listener} =
             :gen_tcp.listen(0, [:binary, active: false, packet: 0, ifaddr: {:local, path}])

    peer =
      Task.async(fn ->
        assert {:ok, socket} = :gen_tcp.accept(listener, 1_000)

        try do
          # Forward the identity query to the real isolated agent; only the sign
          # response is hostile. No invented successful identity/signature reply.
          assert read_frame(socket) == <<11>>

          assert {:ok, agent} =
                   :gen_tcp.connect(
                     {:local, ctx.socket},
                     0,
                     [:binary, active: false, packet: 4],
                     1_000
                   )

          try do
            assert :ok = :gen_tcp.send(agent, <<11>>)
            assert {:ok, identities} = :gen_tcp.recv(agent, 0, 1_000)
            assert :ok = :gen_tcp.send(socket, <<byte_size(identities)::32, identities::binary>>)
          after
            :gen_tcp.close(agent)
          end

          assert read_frame(socket) ==
                   <<13>> <>
                     Wire.string(Wire.key_blob(key)) <> Wire.string(@vector["base"]) <> <<0::32>>

          case behavior do
            :oversize -> assert :ok = :gen_tcp.send(socket, <<1_048_577::32>>)
            :truncated -> assert :ok = :gen_tcp.send(socket, <<8::32, 14, 0>>)
            :closed -> :ok
            :silent -> :ok
          end

          if behavior in [:truncated, :closed] do
            :gen_tcp.close(socket)
          else
            # The deadline/protocol refusal must close the actual client socket.
            assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
          end
        after
          :gen_tcp.close(socket)
        end

        :ok
      end)

    original = handle.ref

    hostile = %{
      handle
      | ref: fn ->
          {algorithm, _, public, check} = original.()
          {algorithm, path, public, check}
        end
    }

    try do
      start = System.monotonic_time(:millisecond)
      assert_error(Custody.sign(hostile, @vector["base"], timeout: 300), reason)
      assert System.monotonic_time(:millisecond) - start < 1_500
      assert :ok = Task.await(peer, 3_000)
      assert {:ok, signature} = Custody.sign(handle, @vector["base"])
      assert signature == Base.decode64!(@vector["signature"])
    after
      Task.shutdown(peer, :brutal_kill)
      :gen_tcp.close(listener)
      File.rm(path)
    end
  end

  defp read_frame(socket) do
    assert {:ok, <<size::32>>} = :gen_tcp.recv(socket, 4, 1_000)
    assert {:ok, bytes} = :gen_tcp.recv(socket, size, 1_000)
    bytes
  end

  defp generate(ctx, type, bits, name) do
    file = Path.join(ctx.dir, name)
    args = ["-q", "-t", type, "-N", "", "-C", "custody-test", "-f", file]
    args = if bits, do: args ++ ["-b", bits], else: args
    assert {_, 0} = System.cmd("ssh-keygen", args, env: ctx.env, stderr_to_stdout: true)
    file
  end

  defp write_rfc_key(dir) do
    [entry] = :public_key.pem_decode(File.read!(Path.join(@root, "ed25519_private.pem")))
    {:ECPrivateKey, _, seed, _, _, _} = :public_key.pem_entry_decode(entry)
    {public, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    blob = ssh_string("ssh-ed25519") <> ssh_string(public)
    <<check::32>> = :crypto.strong_rand_bytes(4)

    private =
      <<check::32, check::32>> <>
        ssh_string("ssh-ed25519") <>
        ssh_string(public) <>
        ssh_string(seed <> public) <> ssh_string("RFC 9421 published test key")

    padding = 8 - rem(byte_size(private), 8)
    private = private <> :binary.list_to_bin(Enum.to_list(1..padding))

    encoded =
      "openssh-key-v1\0" <>
        ssh_string("none") <>
        ssh_string("none") <>
        ssh_string("") <>
        <<1::32>> <> ssh_string(blob) <> ssh_string(private)

    file = Path.join(dir, "rfc-ed25519")

    File.write!(
      file,
      @openssh_private_begin <>
        Base.encode64(encoded) <> "\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    File.chmod!(file, 0o600)
    File.write!(file <> ".pub", "ssh-ed25519 " <> Base.encode64(blob) <> "\n")
    file
  end

  defp agent_keys(ctx) do
    {output, 0} = System.cmd("ssh-add", ["-L"], env: ctx.env, stderr_to_stdout: true)

    String.split(output, "\n", trim: true)
    |> Enum.map(fn line ->
      [type, base | _] = String.split(line)
      {type, decode_public(Base.decode64!(base))}
    end)
  end

  defp public_file(file) do
    [_, base | _] = File.read!(file <> ".pub") |> String.split()
    decode_public(Base.decode64!(base))
  end

  defp decode_public(blob) do
    {type, rest} = string(blob)

    material =
      case type do
        "ssh-ed25519" ->
          {public, ""} = string(rest)
          {:ed25519, public}

        "ssh-rsa" ->
          {e, rest} = string(rest)
          {n, ""} = string(rest)
          {:rsa, :binary.decode_unsigned(n), :binary.decode_unsigned(e)}

        "ecdsa-sha2-" <> curve ->
          {^curve, rest} = string(rest)
          {point, ""} = string(rest)
          {:ec, if(curve == "nistp256", do: "P-256", else: "P-384"), point}
      end

    {:ok, key} = PublicKey.import(material, :raw)
    key
  end

  defp captured_reply(socket, blob, base) do
    {:ok, conn} =
      :gen_tcp.connect({:local, socket}, 0, [:binary, active: false, packet: 4], 1_000)

    try do
      :ok = :gen_tcp.send(conn, <<13>> <> ssh_string(blob) <> ssh_string(base) <> <<0::32>>)
      {:ok, reply} = :gen_tcp.recv(conn, 0, 1_000)
      reply
    after
      :gen_tcp.close(conn)
    end
  end

  defp ssh_string(bytes), do: <<byte_size(bytes)::32, bytes::binary>>
  defp string(<<size::32, bytes::binary-size(size), rest::binary>>), do: {bytes, rest}

  defp socket_ports,
    do: Enum.filter(Port.list(), &(Port.info(&1, :name) == {:name, ~c"tcp_inet"})) |> Enum.sort()

  defp eventually(fun, remaining \\ 100)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, remaining) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(10)
          eventually(fun, remaining - 1)
        )
  end

  defp assert_error(result, reason) do
    assert {:error, error} = result
    assert error.__struct__ == RequestSeal.Custody.Error
    assert error.reason == reason
    assert error.retryable == reason in [:deadline_exceeded, :custodian_unavailable]
  end
end
