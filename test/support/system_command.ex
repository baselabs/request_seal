defmodule RequestSeal.SystemCommand do
  @moduledoc false
  @runner Path.expand("../../scripts/processes.py", __DIR__)

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

      {:DOWN, ^monitor, :process, ^owner, reason} ->
        raise "ssh-agent owner failed: #{inspect(reason)}"
    after
      15_000 -> raise "ssh-agent owner readiness deadline exceeded"
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

      {:DOWN, ^monitor, :process, ^owner, reason} when request == :stop and reason in [:normal, :noproc] -> :ok
      {:DOWN, ^monitor, :process, ^owner, reason} -> raise "agent owner exited: #{inspect(reason)}"
    after
      10_000 -> raise "ssh-agent owner response deadline exceeded"
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
      pid = await_agent(port, socket, pid_file, System.monotonic_time(:millisecond) + 10_000)
      send(caller, {ref, {:ready, pid}})
      agent_loop(port, monitor)
    after
      # Explicit Port.close discards the exit-status channel. First request
      # shutdown over stdin and receive the owner's status, then close the port.
      if Port.info(port), do: Port.close(port)
    end
  end

  defp agent_loop(port, monitor) do
    receive do
      {:stop, _from, _ref} ->
        stop_port(port)

      {{:signal, signal}, from, ref} ->
        # Signal numbers differ on BSD/macOS; resolve them in the Python owner.
        name = %{stop: "SIGSTOP", continue: "SIGCONT", terminate: "SIGTERM"}
        true = Port.command(port, "signal " <> name[signal] <> "\n")
        await_signal(port, name[signal], "")
        send(from, {ref, :ok})
        agent_loop(port, monitor)

      {:DOWN, ^monitor, :process, _, _} -> stop_port(port)
      {^port, {:exit_status, _}} -> :ok
      {^port, {:data, _}} -> agent_loop(port, monitor)
    end
  end

  defp await_signal(port, name, output) do
    receive do
      {^port, {:data, bytes}} ->
        output = output <> bytes

        if String.contains?(output, "requestseal-owner: signal " <> name <> "\n") do
          :ok
        else
          await_signal(port, name, output)
        end

      {^port, {:exit_status, status}} -> raise "agent owner exited during signal: #{status}"
    after
      5_000 -> raise "ssh-agent signal deadline exceeded"
    end
  end

  defp stop_port(port) do
    if Port.info(port) do
      true = Port.command(port, "stop\n")

      receive do
        {^port, {:exit_status, 0}} -> :ok
        {^port, {:exit_status, status}} -> raise "agent owner shutdown failed: #{status}"
      after
        7_000 -> raise "ssh-agent owner shutdown deadline exceeded"
      end
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
      {:ok, pid} -> pid
      :retry ->
        receive do
          {^port, {:exit_status, status}} -> raise "ssh-agent exited before readiness: #{status}"
        after
          10 ->
            if System.monotonic_time(:millisecond) >= deadline do
              stop_port(port)
              raise "ssh-agent readiness deadline exceeded"
            end

            await_agent(port, socket, pid_file, deadline)
        end
    end
  end
end
