defmodule RequestSeal.SystemCommand do
  @moduledoc false
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

  def agent(socket) do
    caller = self()
    ref = make_ref()
    {owner, monitor} = spawn_monitor(fn -> own_agent(caller, ref, socket) end)

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

  defp own_agent(caller, ref, socket) do
    monitor = Process.monitor(caller)
    python = System.find_executable("python3") || raise "python3 is required"
    pid_file = socket <> ".pid"

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: [
          @runner,
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
      if Port.info(port), do: Port.close(port)
    end
  end

  defp agent_loop(port, monitor) do
    receive do
      {:stop, from, ref} ->
        send(from, {ref, stop_port(port)})

      {{:signal, :terminate}, from, ref} ->
        case command_exit(port, "signal SIGTERM\n") do
          {:ok, status} -> send(from, {ref, status})
          {:error, message} -> raise message
        end

      {{:signal, signal}, from, ref} ->
        # Signal numbers differ on BSD/macOS; resolve them in the Python owner.
        name = %{stop: "SIGSTOP", continue: "SIGCONT"}
        true = Port.command(port, "signal " <> name[signal] <> "\n")
        deadline = System.monotonic_time(:millisecond) + @signal_timeout
        await_signal(port, name[signal], "", deadline)
        send(from, {ref, :ok})
        agent_loop(port, monitor)

      {:DOWN, ^monitor, :process, _, _} ->
        finish_stop(port)

      {^port, {:exit_status, status}} ->
        agent_exited(monitor, status)

      {^port, {:data, _}} ->
        agent_loop(port, monitor)
    end
  end

  defp agent_exited(monitor, status) do
    receive do
      {:stop, from, ref} ->
        send(from, {ref, stop_result(status)})

      {{:signal, :terminate}, from, ref} ->
        send(from, {ref, status})

      {{:signal, _}, from, ref} ->
        send(from, {ref, {:error, "agent owner exited: #{status}"}})
        agent_exited(monitor, status)

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
        raise "agent owner exited during signal: #{status}"
    after
      max(0, deadline - System.monotonic_time(:millisecond)) ->
        raise "ssh-agent signal deadline exceeded"
    end
  end

  defp stop_port(port) do
    case command_exit(port, "stop\n") do
      {:ok, status} -> stop_result(status)
      {:error, message} -> {:error, message}
    end
  end

  defp stop_result(0), do: :ok
  defp stop_result(status), do: {:error, "agent owner shutdown failed: #{status}"}

  defp command_exit(port, command) do
    # A caller's DOWN may precede an already queued port status. Consume that
    # terminal state before attempting to write to the command channel.
    receive do
      {^port, {:exit_status, status}} -> {:ok, status}
    after
      0 ->
        if Port.info(port) do
          try do
            true = Port.command(port, command)
          rescue
            # Port death can race the write. Its real status still arrives on
            # the exit-status channel; a closed port is not a successful stop.
            ArgumentError -> :ok
          end
        end

        await_exit(port, @shutdown_timeout)
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
