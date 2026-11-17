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

    await_agent(port, socket, pid_file, System.monotonic_time(:millisecond) + 10_000)
  end

  defp await_agent(port, socket, pid_file, deadline) do
    if File.exists?(socket) and File.exists?(pid_file) do
      {port, File.read!(pid_file) |> String.trim()}
    else
      receive do
        {^port, {:exit_status, status}} -> raise "ssh-agent exited before readiness: #{status}"
      after
        10 ->
          if System.monotonic_time(:millisecond) >= deadline do
            Port.close(port)
            raise "ssh-agent readiness deadline exceeded"
          end

          await_agent(port, socket, pid_file, deadline)
      end
    end
  end
end
