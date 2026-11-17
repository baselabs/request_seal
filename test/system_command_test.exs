defmodule RequestSeal.SystemCommandTest do
  use ExUnit.Case, async: false
  alias RequestSeal.SystemCommand

  test "owner preserves nonzero and signal statuses and identifies deadlines" do
    python = System.find_executable("python3")
    assert {"", 7} = SystemCommand.run(python, ["-B", "-c", "raise SystemExit(7)"])

    assert {"", 143} =
             SystemCommand.run(python, [
               "-B",
               "-c",
               "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"
             ])

    assert {diagnostic, 124} =
             SystemCommand.run(python, ["-B", "-c", "import time; time.sleep(60)"],
               timeout: 0.1,
               stderr_to_stdout: true
             )

    assert diagnostic == "requestseal-owner: command deadline exceeded after 0.1s\n"
  end

  test "a bound Unix socket without a listener is not ready" do
    dir =
      Path.join(
        System.tmp_dir!(),
        "agent-bound-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir!(dir)
    path = Path.join(dir, "socket")
    {:ok, socket} = :socket.open(:local, :stream)

    try do
      # Exercise the kernel's bind-before-listen state without inventing a peer reply.
      :ok = :socket.bind(socket, %{family: :local, path: path})
      File.write!(path <> ".pid", System.pid())
      assert :retry = SystemCommand.agent_ready(path, path <> ".pid")
    after
      :socket.close(socket)
      File.rm_rf!(dir)
    end
  end

  test "real agent is listening with a numeric identity and teardown reaps both owners" do
    dir =
      Path.join(
        System.tmp_dir!(),
        "agent-owner-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir!(dir)
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
    {:os_pid, owner_pid} = Port.info(port, :os_pid)

    try do
      assert {number, ""} = Integer.parse(pid)
      assert number > 0
      assert {:ok, ^pid} = SystemCommand.agent_ready(socket, socket <> ".pid")

      for contents <- ["", "invalid", "0", "-1", pid <> "extra"] do
        File.write!(socket <> ".pid", contents)
        assert :retry = SystemCommand.agent_ready(socket, socket <> ".pid")
      end

      File.write!(socket <> ".pid", pid)

      assert {:ok, connection} =
               :gen_tcp.connect({:local, socket}, 0, [:binary, active: false], 100)

      assert :ok = :gen_tcp.close(connection)
      assert :ok = SystemCommand.signal_agent(owner, :stop)
      assert :ok = SystemCommand.signal_agent(owner, :continue)
      assert :ok = SystemCommand.stop_agent(owner)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
      assert Port.info(port) == nil
      assert {_, 1} = System.cmd("ps", ["-p", pid, "-o", "pid="])
      assert {_, 1} = System.cmd("ps", ["-p", to_string(owner_pid), "-o", "pid="])
      # A second teardown has no port and cannot send a signal to the old PID.
      assert :ok = SystemCommand.stop_agent(owner)
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "termination completes with the real agent status before owner teardown" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)

    try do
      assert 2 = SystemCommand.signal_agent(owner, :terminate)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
      refute File.exists?(socket)
      assert {_, 1} = System.cmd("ps", ["-p", pid, "-o", "pid="])
      assert :ok = SystemCommand.stop_agent(owner)
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "caller death queued during termination cannot start a second shutdown" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    parent = self()
    ref = make_ref()

    {caller, caller_monitor} =
      spawn_monitor(fn ->
        {owner, _pid} = SystemCommand.agent(socket)
        send(parent, {:agent_owner, owner})

        receive do
          :terminate -> send(owner, {{:signal, :terminate}, parent, ref})
        end
      end)

    assert_receive {:agent_owner, owner}
    monitor = Process.monitor(owner)

    try do
      # Queue both the real termination request and the caller's DOWN before
      # the owner can read any port status. No synthetic exit messages are used.
      :erlang.suspend_process(owner)

      try do
        send(caller, :terminate)
        assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :normal}
        {:messages, messages} = Process.info(owner, :messages)
        assert Enum.any?(messages, &match?({{:signal, :terminate}, ^parent, ^ref}, &1))
        assert Enum.any?(messages, &match?({:DOWN, _, :process, ^caller, :normal}, &1))
      after
        :erlang.resume_process(owner)
      end

      assert_receive {^ref, 2}, 8_000
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
      refute File.exists?(socket)
      assert :ok = SystemCommand.stop_agent(owner)
    after
      if Process.alive?(caller), do: Process.exit(caller, :kill)
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "readiness rejection reports the readiness reason directly" do
    dir = agent_directory()
    path = Path.join(dir, "occupied")
    {:ok, socket} = :socket.open(:local, :stream)

    try do
      # The real ssh-agent must reject a Unix address already bound in the kernel.
      :ok = :socket.bind(socket, %{family: :local, path: path})

      assert_raise RuntimeError, ~r/^ssh-agent exited before readiness: [0-9]+$/, fn ->
        SystemCommand.agent(path)
      end
    after
      :socket.close(socket)
      File.rm_rf!(dir)
    end
  end

  defp agent_directory do
    dir =
      Path.join(
        System.tmp_dir!(),
        "agent-state-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir!(dir)
    dir
  end
end
