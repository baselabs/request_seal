defmodule RequestSeal.SystemCommand do
  @moduledoc """
  Owns test commands and real SSH agents through a command-channel port.

  An agent's terminal status or port exit reason is retained until a stop or
  terminate request reports it. Other signals report it without consuming it.
  After reporting the status to stop or terminate, the owner exits; a later
  stop returns `:ok` because the earlier caller already received the outcome.

  Stop returns `:ok` or `{:error, message}`. Stop and continue signals return
  `:ok` or `{:error, message}`; terminate returns the integer terminal status
  or `{:error, message}`. Errors include a port exit reason and, for stop or
  terminate, `"ssh-agent owner shutdown deadline exceeded"`. A nonzero status
  is an error for `stop_agent/1`. Stop and continue signals report any retained
  terminal status as an error. Request deadlines and unexpected owner exits
  raise in the caller.
  """
  @runner Path.expand("../../scripts/processes.py", __DIR__)
  @readiness_timeout 10_000
  @shutdown_timeout 7_000
  @signal_timeout 5_000
  @response_margin 1_000
  @caller_readiness_timeout @readiness_timeout + @shutdown_timeout + @response_margin
  @caller_response_timeout max(@signal_timeout, @shutdown_timeout) + @response_margin

  # A BEAM port holds the runner's stdin open. VM or port-owner death closes it,
  # so the Python owner terminates the entire session even after a test timeout.
  def run(executable, args, options \\ []) do
    {timeout, options} = Keyword.pop(options, :timeout, 300)
    python = System.find_executable("python3") || raise "python3 is required"

    System.cmd(
      python,
      [@runner, "--timeout", to_string(timeout), "--", executable | args],
      options
    )
  end

  def agent(socket, options \\ []) do
    caller = self()
    ref = make_ref()
    # Tests can instrument the real Python owner without replacing its logic.
    runner = Keyword.get(options, :runner, @runner)
    {owner, monitor} = spawn_monitor(fn -> own_agent(caller, ref, socket, runner) end)

    receive do
      {^ref, {:ready, pid}} ->
        Process.demonitor(monitor, [:flush])
        {owner, pid}

      {^ref, {:error, message}} ->
        Process.demonitor(monitor, [:flush])
        raise message

      {:DOWN, ^monitor, :process, ^owner, reason} ->
        raise "ssh-agent owner failed: #{inspect(reason)}"
    after
      @caller_readiness_timeout -> raise "ssh-agent owner readiness deadline exceeded"
    end
  end

  @doc """
  Stops an agent, returning `:ok` for status zero or an already stopped owner.

  Returns `{:error, message}` for a nonzero status, a port exit reason, or
  `"ssh-agent owner shutdown deadline exceeded"`. An unexpected owner exit or
  a response deadline raises in the caller.

  Reporting that status completes the owner's lifetime. A later stop returns
  `:ok`, including after a crash was reported to stop or terminate.
  """
  def stop_agent(owner), do: agent_request(owner, :stop)

  @doc """
  Sends stop, continue, or terminate to the agent through its owner.

  Stop and continue return `:ok` after acknowledgement, or `{:error, message}`
  naming a retained terminal status or port exit reason. Terminate waits for
  shutdown and returns its integer status, or `{:error, message}` for a port
  exit reason or `"ssh-agent owner shutdown deadline exceeded"`.

  Terminate completes the owner's lifetime; stop and continue retain terminal
  outcomes for a later stop or terminate. Signal acknowledgement deadlines,
  response deadlines, and unexpected owner exits raise in the caller.
  """
  def signal_agent(owner, signal) when signal in [:stop, :continue, :terminate] do
    agent_request(owner, {:signal, signal})
  end

  defp agent_request(owner, request) do
    monitor = Process.monitor(owner)
    ref = make_ref()
    send(owner, {request, self(), ref})

    receive do
      {^ref, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^owner, reason}
      when request == :stop and reason in [:normal, :noproc] ->
        :ok

      {:DOWN, ^monitor, :process, ^owner, reason} ->
        raise "agent owner exited: #{inspect(reason)}"
    after
      @caller_response_timeout -> raise "ssh-agent owner response deadline exceeded"
    end
  end

  defp own_agent(caller, ref, socket, runner) do
    # This holds for every OTP release in .tool-versions:
    # erts/emulator/sys/unix/sys_drivers.c output() fails writev(EPIPE) through
    # driver_failure_posix. In erts/emulator/beam/io.c, driver_failure_term()
    # calls erts_deliver_port_exit(), invalidating the port. driver_report_exit()
    # then returns early: no exit_status follows EXIT. Port-to-process signal
    # ordering puts any earlier status ahead of EXIT, so EXIT is final itself.
    # https://github.com/erlang/otp/blob/ad05823719d77c8faee87348ea39513d4e2f99c5/erts/emulator/sys/unix/sys_drivers.c
    # https://github.com/erlang/otp/blob/ad05823719d77c8faee87348ea39513d4e2f99c5/erts/emulator/beam/io.c
    # https://github.com/erlang/otp/blob/09fb046150ab94104e03ee816b95c8b7e6b04683/erts/emulator/sys/unix/sys_drivers.c
    # https://github.com/erlang/otp/blob/09fb046150ab94104e03ee816b95c8b7e6b04683/erts/emulator/beam/io.c
    # https://github.com/erlang/otp/blob/c388a2d1b3f9918652276d4798692dd4d8ef97fc/erts/emulator/sys/unix/sys_drivers.c
    # https://github.com/erlang/otp/blob/c388a2d1b3f9918652276d4798692dd4d8ef97fc/erts/emulator/beam/io.c
    Process.flag(:trap_exit, true)
    monitor = Process.monitor(caller)
    python = System.find_executable("python3") || raise "python3 is required"
    pid_file = socket <> ".pid"

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: [
          runner,
          "--pid-file",
          pid_file,
          "--timeout",
          "600",
          "--",
          "ssh-agent",
          "-D",
          "-a",
          socket
        ]
      ])

    try do
      deadline = System.monotonic_time(:millisecond) + @readiness_timeout

      case await_agent(port, socket, pid_file, deadline) do
        {:ok, pid} ->
          send(caller, {ref, {:ready, pid}})
          agent_loop(port, monitor)

        {:error, reason, state} ->
          teardown = if state == :running, do: stop_port(port), else: :ok

          message =
            case teardown do
              :ok -> reason
              {:error, failure} -> reason <> "; teardown failed: " <> failure
            end

          send(caller, {ref, {:error, message}})
      end
    after
      # Explicit Port.close discards the exit-status channel. First request
      # shutdown over stdin and receive the owner's status, then close the port.
      try do
        Port.close(port)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  defp agent_loop(port, monitor) do
    receive do
      {:stop, from, ref} ->
        send(from, {ref, stop_port(port)})

      {{:signal, :terminate}, from, ref} ->
        send(from, {ref, terminate_result(command_exit(port, "signal SIGTERM\n"))})

      {{:signal, signal}, from, ref} ->
        # Signal numbers differ on BSD/macOS; resolve them in the Python owner.
        name = %{stop: "SIGSTOP", continue: "SIGCONT"}

        result =
          case queued_exit(port) do
            :running ->
              try do
                true = Port.command(port, "signal " <> name[signal] <> "\n")
              rescue
                # A closed port owes either exit_status or a trapped EXIT.
                ArgumentError -> :ok
              end

              deadline = System.monotonic_time(:millisecond) + @signal_timeout
              await_signal(port, name[signal], "", deadline)

            outcome ->
              {:exited, outcome}
          end

        case result do
          :ok ->
            send(from, {ref, :ok})
            agent_loop(port, monitor)

          {:exited, outcome} ->
            send(from, {ref, signal_result(outcome)})
            agent_exited(monitor, outcome)
        end

      {:DOWN, ^monitor, :process, _, _} ->
        # Nobody remains to receive a failure. Finish cleanup and exit normally.
        stop_port(port)
        :ok

      {^port, {:exit_status, status}} ->
        agent_exited(monitor, {:ok, status})

      {:EXIT, ^port, reason} ->
        agent_exited(monitor, port_exit(reason))

      {^port, {:data, _}} ->
        agent_loop(port, monitor)
    end
  end

  defp agent_exited(monitor, outcome) do
    receive do
      {:stop, from, ref} ->
        send(from, {ref, stop_result(outcome)})

      {{:signal, :terminate}, from, ref} ->
        send(from, {ref, terminate_result(outcome)})

      {{:signal, _}, from, ref} ->
        send(from, {ref, signal_result(outcome)})
        agent_exited(monitor, outcome)

      {:DOWN, ^monitor, :process, _, _} ->
        :ok
    end
  end

  defp await_signal(port, name, output, deadline) do
    receive do
      {^port, {:data, bytes}} ->
        output = output <> bytes

        if String.contains?(output, "requestseal-owner: signal " <> name <> "\n") do
          :ok
        else
          await_signal(port, name, output, deadline)
        end

      {^port, {:exit_status, status}} ->
        {:exited, {:ok, status}}

      {:EXIT, ^port, reason} ->
        {:exited, port_exit(reason)}
    after
      max(0, deadline - System.monotonic_time(:millisecond)) ->
        raise "ssh-agent signal deadline exceeded"
    end
  end

  defp stop_port(port), do: stop_result(command_exit(port, "stop\n"))

  defp stop_result({:ok, 0}), do: :ok
  defp stop_result({:ok, status}), do: {:error, "agent owner shutdown failed: #{status}"}
  defp stop_result({:error, _} = outcome), do: outcome

  defp terminate_result({:ok, status}), do: status
  defp terminate_result({:error, _} = outcome), do: outcome

  defp signal_result({:ok, status}), do: {:error, "agent owner exited: #{status}"}
  defp signal_result({:error, _} = outcome), do: outcome

  defp queued_exit(port) do
    receive do
      {^port, {:exit_status, status}} -> {:ok, status}
      {:EXIT, ^port, reason} -> port_exit(reason)
    after
      0 -> :running
    end
  end

  defp port_exit(reason), do: {:error, "agent owner port exited: #{inspect(reason)}"}

  defp command_exit(port, command) do
    # A caller's DOWN may precede an already queued port status. Consume that
    # terminal state before attempting to write to the command channel.
    case queued_exit(port) do
      :running ->
        if Port.info(port) do
          try do
            true = Port.command(port, command)
          rescue
            # Port death can race the write. Await its status or trapped EXIT;
            # a closed command channel is not a successful stop.
            ArgumentError -> :ok
          end
        end

        await_exit(port, @shutdown_timeout)

      outcome ->
        outcome
    end
  end

  defp await_exit(port, timeout) do
    receive do
      {^port, {:exit_status, status}} -> {:ok, status}
      {:EXIT, ^port, reason} -> port_exit(reason)
    after
      timeout -> {:error, "ssh-agent owner shutdown deadline exceeded"}
    end
  end

  def agent_ready(socket, pid_file) do
    with {:ok, contents} <- File.read(pid_file),
         {pid, ""} when pid > 0 <- Integer.parse(String.trim(contents)),
         {:ok, connection} <- :gen_tcp.connect({:local, socket}, 0, [:binary, active: false], 50) do
      :ok = :gen_tcp.close(connection)
      {:ok, Integer.to_string(pid)}
    else
      _ -> :retry
    end
  end

  defp await_agent(port, socket, pid_file, deadline) do
    case agent_ready(socket, pid_file) do
      {:ok, pid} ->
        {:ok, pid}

      :retry ->
        receive do
          {^port, {:exit_status, status}} ->
            {:error, "ssh-agent exited before readiness: #{status}", :exited}

          {:EXIT, ^port, reason} ->
            {:error, message} = port_exit(reason)
            {:error, "ssh-agent exited before readiness; " <> message, :exited}
        after
          10 ->
            if System.monotonic_time(:millisecond) >= deadline do
              {:error, "ssh-agent readiness deadline exceeded", :running}
            else
              await_agent(port, socket, pid_file, deadline)
            end
        end
    end
  end
end
