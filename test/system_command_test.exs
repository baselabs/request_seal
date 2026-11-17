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

        assert eventually(fn -> Port.info(port) == nil end)
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

  test "an idle agent crash is retained for stop and terminate requests" do
    for request <- [:stop, :terminate] do
      dir = agent_directory()
      socket = Path.join(dir, "agent")
      {owner, pid} = SystemCommand.agent(socket)
      monitor = Process.monitor(owner)

      try do
        assert {_, 0} = System.cmd("kill", ["-KILL", pid])
        assert eventually(fn -> terminal_agent?(owner) end)
        assert Process.alive?(owner)

        case request do
          :stop ->
            assert {:error, "agent owner shutdown failed: 137"} = SystemCommand.stop_agent(owner)

          :terminate ->
            assert 137 = SystemCommand.signal_agent(owner, :terminate)
        end

        assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
        # The first caller received the crash; teardown does not report it twice.
        assert :ok = SystemCommand.stop_agent(owner)
      after
        SystemCommand.stop_agent(owner)
        File.rm_rf!(dir)
      end
    end
  end

  test "other signals report an idle agent crash without consuming its terminal status" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)

    try do
      assert {_, 0} = System.cmd("kill", ["-KILL", pid])
      assert eventually(fn -> terminal_agent?(owner) end)

      for signal <- [:stop, :continue] do
        assert {:error, "agent owner exited: 137"} = SystemCommand.signal_agent(owner, signal)
        assert Process.alive?(owner)
      end

      assert 137 = SystemCommand.signal_agent(owner, :terminate)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "signal requests consume a queued real agent crash and retain it for stop" do
    for signal <- [:stop, :continue] do
      dir = agent_directory()
      socket = Path.join(dir, "agent")
      {owner, pid} = SystemCommand.agent(socket)
      monitor = Process.monitor(owner)
      [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
      ref = make_ref()

      try do
        :erlang.suspend_process(owner)

        try do
          # Put the request first, then wait for the real status to be queued.
          # The signal clause must consume it before touching the closed port.
          send(owner, {{:signal, signal}, self(), ref})
          assert {_, 0} = System.cmd("kill", ["-KILL", pid])

          assert eventually(fn ->
                   {:messages, messages} = Process.info(owner, :messages)
                   Enum.any?(messages, &match?({^port, {:exit_status, 137}}, &1))
                 end)

          assert eventually(fn -> Port.info(port) == nil end)
        after
          :erlang.resume_process(owner)
        end

        assert_receive {^ref, {:error, "agent owner exited: 137"}}
        assert eventually(fn -> terminal_agent?(owner) end)
        assert {:error, "agent owner shutdown failed: 137"} = SystemCommand.stop_agent(owner)
        assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
        assert :ok = SystemCommand.stop_agent(owner)
      after
        SystemCommand.stop_agent(owner)
        File.rm_rf!(dir)
      end
    end
  end

  test "an exit during signal acknowledgement is reported and retained for stop" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
    {:os_pid, owner_pid} = Port.info(port, :os_pid)
    ref = make_ref()

    try do
      assert {_, 0} = System.cmd("kill", ["-STOP", to_string(owner_pid)])

      try do
        assert eventually(fn -> stopped?(to_string(owner_pid)) end)
        send(owner, {{:signal, :stop}, self(), ref})

        assert eventually(fn ->
                 Process.info(owner, :current_function) ==
                   {:current_function, {SystemCommand, :await_signal, 4}}
               end)

        # TERM is pending before the Python owner resumes. It cleans up the
        # real agent and exits without acknowledging the buffered signal.
        assert {_, 0} = System.cmd("kill", ["-TERM", to_string(owner_pid)])
      after
        if Port.info(port) do
          assert {_, 0} = System.cmd("kill", ["-CONT", to_string(owner_pid)])
        end
      end

      assert_receive {^ref, {:error, "agent owner exited: 143"}}
      assert eventually(fn -> terminal_agent?(owner) end)
      assert {:error, "agent owner shutdown failed: 143"} = SystemCommand.stop_agent(owner)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
      assert {_, 1} = System.cmd("ps", ["-p", pid, "-o", "pid="])
      refute File.exists?(socket)
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "writes to closed owner stdin report and retain the real port exit" do
    for request <- [:stop, :terminate, :stop_signal, :continue_signal, :idle] do
      dir = agent_directory()
      {owner, pid, port, owner_pid} = closed_stdin_agent(dir)
      monitor = Process.monitor(owner)
      expected = {:error, "agent owner port exited: :epipe"}

      try do
        close_owner_stdin(dir, owner, port, owner_pid)
        :erlang.trace(owner, true, [:receive])

        case request do
          :stop ->
            assert ^expected = SystemCommand.stop_agent(owner)

          :terminate ->
            assert ^expected = SystemCommand.signal_agent(owner, :terminate)

          :stop_signal ->
            assert ^expected = SystemCommand.signal_agent(owner, :stop)

          :continue_signal ->
            assert ^expected = SystemCommand.signal_agent(owner, :continue)

          :idle ->
            # No request is pending: the loop itself must retain the VM's EXIT.
            assert Port.command(port, "stop\n")
        end

        # This is emitted by the VM after its real write fails, never injected
        # as an Elixir message. The linked owner must survive that same EXIT.
        assert_receive {:trace, ^owner, :receive, {:EXIT, ^port, :epipe}}, 1_000

        if request in [:stop_signal, :continue_signal, :idle] do
          assert eventually(fn -> terminal_agent?(owner) end)
          assert Process.alive?(owner)
          assert ^expected = SystemCommand.signal_agent(owner, :stop)
          assert ^expected = SystemCommand.signal_agent(owner, :continue)

          if request == :continue_signal do
            assert ^expected = SystemCommand.signal_agent(owner, :terminate)
          else
            assert ^expected = SystemCommand.stop_agent(owner)
          end
        end

        assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
        assert eventually(fn -> Port.info(port) == nil end)
        assert :ok = SystemCommand.stop_agent(owner)
      after
        release_closed_stdin_agent(dir, owner, pid, owner_pid)
      end
    end
  end

  test "an owner retaining a port exit still exits when its caller dies" do
    dir = agent_directory()
    parent = self()

    {caller, caller_monitor} =
      spawn_monitor(fn ->
        send(parent, {:closed_stdin_agent, closed_stdin_agent(dir)})

        receive do
          :finish -> :ok
        end
      end)

    assert_receive {:closed_stdin_agent, {owner, pid, port, owner_pid}}, 15_000
    monitor = Process.monitor(owner)

    try do
      close_owner_stdin(dir, owner, port, owner_pid)
      assert Port.command(port, "stop\n")
      assert eventually(fn -> terminal_agent?(owner) end)

      assert {:error, "agent owner port exited: :epipe"} =
               SystemCommand.signal_agent(owner, :continue)

      send(caller, :finish)
      assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :normal}
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
      assert eventually(fn -> Port.info(port) == nil end)
    after
      if Process.alive?(caller), do: Process.exit(caller, :kill)
      release_closed_stdin_agent(dir, owner, pid, owner_pid)
    end
  end

  test "an idle successful exit can be stopped twice" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    {owner, _pid} = SystemCommand.agent(socket)
    monitor = Process.monitor(owner)
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))

    try do
      # End the real command channel before sending the owner an agent request.
      assert Port.command(port, "stop\n")
      assert eventually(fn -> terminal_agent?(owner) end)
      assert :ok = SystemCommand.stop_agent(owner)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
      assert :ok = SystemCommand.stop_agent(owner)
      refute File.exists?(socket)
    after
      SystemCommand.stop_agent(owner)
      File.rm_rf!(dir)
    end
  end

  test "an owner retaining an idle agent crash exits when its caller dies" do
    dir = agent_directory()
    socket = Path.join(dir, "agent")
    parent = self()

    {caller, caller_monitor} =
      spawn_monitor(fn ->
        {owner, pid} = SystemCommand.agent(socket)
        send(parent, {:idle_agent, owner, pid})

        receive do
          :finish -> :ok
        end
      end)

    assert_receive {:idle_agent, owner, pid}
    monitor = Process.monitor(owner)

    try do
      assert {_, 0} = System.cmd("kill", ["-KILL", pid])
      assert eventually(fn -> terminal_agent?(owner) end)
      send(caller, :finish)
      assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :normal}
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    after
      if Process.alive?(caller), do: Process.exit(caller, :kill)
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

  defp closed_stdin_agent(dir) do
    runner = Path.join(dir, "owner.py")

    # Exercise the real owner and ssh-agent, adding only a signal-controlled
    # pause with stdin closed. Suspending the BEAM receiver cannot suspend the
    # spawn driver's independent reaping and EOF handling after an OS exit;
    # this hook makes the no-reader/no-exit-status window deterministic instead.
    File.write!(runner, """
    import os, signal, sys, time
    from pathlib import Path
    sys.dont_write_bytecode = True
    sys.path.insert(0, #{inspect(Path.expand("../scripts", __DIR__))})
    import processes
    closed = Path(#{inspect(Path.join(dir, "stdin-closed"))})
    release = Path(#{inspect(Path.join(dir, "release"))})
    def close_stdin(signum, frame):
        os.close(0)
        closed.touch()
        deadline = time.monotonic() + 5
        while not release.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        # End through the real owner's cleanup even if the test was killed.
        raise EOFError("command owner closed stdin")
    signal.signal(signal.SIGUSR1, close_stdin)
    raise SystemExit(processes.main(restore_signal_mask=False))
    """)

    {owner, pid} = SystemCommand.agent(Path.join(dir, "agent"), runner: runner)
    [port] = Enum.filter(Port.list(), &(Port.info(&1, :connected) == {:connected, owner}))
    {:os_pid, owner_pid} = Port.info(port, :os_pid)
    {owner, pid, port, owner_pid}
  end

  defp close_owner_stdin(dir, owner, port, owner_pid) do
    :erlang.suspend_process(owner)

    try do
      assert {_, 0} = System.cmd("kill", ["-USR1", to_string(owner_pid)])
      assert eventually(fn -> File.exists?(Path.join(dir, "stdin-closed")) end)
      assert Port.info(port) != nil
      {:messages, messages} = Process.info(owner, :messages)
      refute Enum.any?(messages, &match?({^port, {:exit_status, _}}, &1))
    after
      :erlang.resume_process(owner)
    end
  end

  defp release_closed_stdin_agent(dir, owner, pid, owner_pid) do
    File.write!(Path.join(dir, "release"), "+")

    try do
      SystemCommand.stop_agent(owner)
    after
      try do
        assert eventually(fn ->
                 match?({_, 1}, System.cmd("ps", ["-p", to_string(owner_pid), "-o", "pid="]))
               end)

        assert {_, 1} = System.cmd("ps", ["-p", pid, "-o", "pid="])
      after
        File.rm_rf!(dir)
      end
    end
  end

  defp terminal_agent?(owner) do
    Process.info(owner, :current_function) ==
      {:current_function, {SystemCommand, :agent_exited, 2}}
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
