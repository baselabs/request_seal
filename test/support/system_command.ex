defmodule RequestSeal.SystemCommand do
  @moduledoc """
  Owns test commands and real SSH agents through a command-channel port.

  An agent's terminal status or port exit reason is retained until a stop or
  terminate request reports it. Other signals report it without consuming it.
  After reporting the status to stop or terminate, the owner exits; a later
  stop returns `:ok` because the earlier caller already received the outcome.
  """
  @runner Path.expand("../../scripts/processes.py", __DIR__)
  @readiness_timeout 10_000
  @shutdown_timeout 7_000
  @signal_timeout 5_000
  @port_exit_timeout 100
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
  Stops an agent, returning an error for a nonzero status or a port exit reason.

  Reporting that status completes the owner's lifetime. A later stop returns
  `:ok`, including after a crash was reported to stop or terminate.
  """
  def stop_agent(owner), do: agent_request(owner, :stop)

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
    # OTP-29.1.1, OTP-28.5.0.7 and OTP-27.3.4:
    # erts/emulator/sys/unix/sys_drivers.c output() fails writev(EPIPE) through
    # driver_failure_posix, bypassing port_inp_failure's driver_report_exit.
    # erts/emulator/beam/io.c driver_failure_term() delivers the linked port
    # exit and tears the driver down; a child status is not guaranteed after it.
    # https://github.com/erlang/otp/blob/OTP-29.1.1/erts/emulator/sys/unix/sys_drivers.c
    # https://github.com/erlang/otp/blob/OTP-29.1.1/erts/emulator/beam/io.c
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
        finish_stop(port)

      {^port, {:exit_status, status}} ->
        agent_exited(monitor, {:ok, status})

      {:EXIT, ^port, reason} ->
        agent_exited(monitor, port_exit(port, reason))

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
        {:exited, port_exit(port, reason)}
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
      {:EXIT, ^port, reason} -> port_exit(port, reason)
    after
      0 -> :running
    end
  end

  defp port_exit(port, reason) do
    # Prefer a status already in transit, but do not wait a shutdown deadline
    # for a driver failure that destroyed the exit-status channel.
    receive do
      {^port, {:exit_status, status}} -> {:ok, status}
    after
      @port_exit_timeout -> {:error, "agent owner port exited: #{inspect(reason)}"}
    end
  end

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

  defp finish_stop(port) do
    case stop_port(port) do
      :ok -> :ok
      {:error, message} -> raise message
    end
  end

  defp await_exit(port, timeout) do
    receive do
      {^port, {:exit_status, status}} -> {:ok, status}
      {:EXIT, ^port, reason} -> port_exit(port, reason)
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
            message =
              case port_exit(port, reason) do
                {:ok, status} -> "ssh-agent exited before readiness: #{status}"
                {:error, message} -> "ssh-agent exited before readiness; " <> message
              end

            {:error, message, :exited}
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
