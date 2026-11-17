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

  test "termination consumes a queued real agent exit without writing to a closed port" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
    ref = make_ref()

    try do
      :erlang.suspend_process(owner)

      try do
        send(owner, {{:signal, :terminate}, self(), ref})
        assert {_, 0} = System.cmd("kill", ["-TERM", pid])

        assert eventually(fn ->
                 {:messages, messages} = Process.info(owner, :messages)
                 Enum.any?(messages, &match?({^port, {:exit_status, 2}}, &1))
               end)

        assert Port.info(port) == nil
      after
        :erlang.resume_process(owner)
      end

      assert_receive {^ref, 2}, 1_000
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
      refute File.exists?(socket)
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "termination continues a stopped real agent before waiting for its status" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)

    try do
      assert :ok = SystemCommand.signal_agent(owner, :stop)
      assert eventually(fn -> stopped?(pid) end)
      started = System.monotonic_time(:millisecond)
      assert 2 = SystemCommand.signal_agent(owner, :terminate)
      assert System.monotonic_time(:millisecond) - started < 3_000
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
      refute File.exists?(socket)
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "stop reports a queued real agent crash as an error" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
    ref = make_ref()

    try do
      :erlang.suspend_process(owner)

      try do
        send(owner, {:stop, self(), ref})
        assert {_, 0} = System.cmd("kill", ["-KILL", pid])

        assert eventually(fn ->
                 {:messages, messages} = Process.info(owner, :messages)
                 Enum.any?(messages, &match?({^port, {:exit_status, 137}}, &1))
               end)
      after
        :erlang.resume_process(owner)
      end

      assert_receive {^ref, {:error, "agent owner shutdown failed: 137"}}, 1_000
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
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
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
    {:os_pid, owner_pid} = Port.info(port, :os_pid)

    try do
      # Stop the real Python owner so it cannot read its command or exit yet.
      # A premature reply now fails regardless of the value it carries.
      assert {_, 0} = System.cmd("kill", ["-STOP", to_string(owner_pid)])

      try do
        assert eventually(fn -> stopped?(to_string(owner_pid)) end)
        :erlang.suspend_process(owner)

        try do
          send(caller, :terminate)
          assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :normal}

          assert eventually(fn ->
                   {:messages, messages} = Process.info(owner, :messages)

                   Enum.any?(messages, &match?({{:signal, :terminate}, ^parent, ^ref}, &1)) and
                     Enum.any?(messages, &match?({:DOWN, _, :process, ^caller, :normal}, &1))
                 end)
        after
          :erlang.resume_process(owner)
        end

        assert eventually(fn ->
                 case Process.info(owner, :current_function) do
                   {:current_function, {SystemCommand, :await_exit, 2}} -> true
                   nil -> true
                   _ -> false
                 end
               end)

        refute_receive {^ref, _}, 150
        assert Process.alive?(owner)
      after
        # Resume before any terminal status can release this process identity,
        # including when an assertion fails while the Python owner is stopped.
        if Port.info(port) do
          assert {_, 0} = System.cmd("kill", ["-CONT", to_string(owner_pid)])
        end
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

  defp stopped?(pid) do
    case System.cmd("ps", ["-p", pid, "-o", "stat="]) do
      {state, 0} -> String.starts_with?(String.trim(state), "T")
      _ -> false
    end
  end

  defp eventually(condition) do
    poll(condition, System.monotonic_time(:millisecond) + 5_000)
  end

  defp poll(condition, deadline) do
    cond do
      condition.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(10)
        poll(condition, deadline)
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
