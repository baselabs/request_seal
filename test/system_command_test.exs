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
end
