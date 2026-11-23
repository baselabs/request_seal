defmodule RequestSeal.Test.HostConditions do
  @moduledoc false

  def cpu_stat, do: File.read!("/proc/stat") |> String.split("\n", parts: 2) |> hd()

  def process_snapshot(:before) do
    root = File.read!("/proc/self/stat")
    process_tree(root, process_stats())
  end

  def process_snapshot(:after) do
    processes = process_stats()
    process_tree(File.read!("/proc/self/stat"), processes)
  end

  def process_tree(root, lines) do
    root_pid = process_times(root).pid

    children =
      lines
      |> Enum.map(&{process_times(&1), &1})
      |> Enum.reject(fn {process, _} -> process.pid == root_pid end)
      |> Enum.group_by(fn {process, _} -> process.parent end)

    [root | descendant_stats(root_pid, children)]
  end

  def percentages(before_cpu, after_cpu, before_processes, after_processes) do
    start = cpu_times(before_cpu)
    stop = cpu_times(after_cpu)
    elapsed = stop.total - start.total
    stolen = stop.steal - start.steal
    workload = workload_times(before_processes, after_processes)
    foreign = stop.busy - start.busy - workload
    steal = if elapsed > 0 and stolen >= 0 and stolen <= elapsed, do: 100 * stolen / elapsed
    {steal, if(elapsed > 0, do: 100 * foreign / elapsed)}
  end

  def admitted?(steal, foreign),
    do:
      is_number(steal) and steal >= 0 and steal <= 5 and
        is_number(foreign) and foreign >= 0 and foreign <= 10

  defp process_stats do
    for entry <- File.ls!("/proc"), {pid, ""} <- [Integer.parse(entry)], pid > 0 do
      path = "/proc/#{entry}/stat"

      case File.read(path) do
        {:ok, line} -> line
        {:error, reason} when reason in [:enoent, :esrch] -> nil
        {:error, reason} -> raise File.Error, reason: reason, action: "read file", path: path
      end
    end
    |> Enum.reject(&is_nil/1)
  end

  defp descendant_stats(pid, children) do
    Enum.flat_map(Map.get(children, pid, []), fn {child, line} ->
      [line | descendant_stats(child.pid, children)]
    end)
  end

  defp cpu_times(text) do
    ["cpu" | fields] = String.split(text)
    values = fields |> Enum.take(8) |> Enum.map(&String.to_integer/1)
    [user, nice, system, _, _, irq, softirq, steal] = values
    true = Enum.all?(values, &(&1 >= 0))
    %{total: Enum.sum(values), busy: user + nice + system + irq + softirq, steal: steal}
  end

  defp process_times(text) do
    [pid, comm] = String.split(text, " (", parts: 2)
    # The process name can contain spaces and closing parentheses.
    parts = String.split(comm, ")")
    true = length(parts) > 1
    [_, parent | _] = fields = parts |> List.last() |> String.split()

    [user, system, child_user, child_system] =
      fields |> Enum.slice(11, 4) |> Enum.map(&String.to_integer/1)

    true = Enum.all?([user, system, child_user, child_system], &(&1 >= 0))

    %{
      pid: String.to_integer(pid),
      parent: String.to_integer(parent),
      started: fields |> Enum.at(19) |> String.to_integer(),
      own: user + system,
      waited: child_user + child_system
    }
  end

  defp identity(process), do: {process.pid, process.started}

  # End-only live processes have no baseline. The BEAM's waited CPU covers
  # reaped processes after discounting the prior CPU of start-only descendants.
  defp workload_times([before_root | _] = before_lines, [after_root | _] = after_lines) do
    root_before = process_times(before_root)
    root_after = process_times(after_root)
    true = identity(root_before) == identity(root_after)
    waited = root_after.waited - root_before.waited
    true = waited >= 0

    after_times =
      after_lines
      |> Enum.map(&process_times/1)
      |> Map.new(&{identity(&1), &1})

    {retained, baseline} =
      Enum.reduce(before_lines, {0, 0}, fn line, {retained, baseline} ->
        start = process_times(line)

        case Map.fetch(after_times, identity(start)) do
          {:ok, stop} ->
            delta = stop.own - start.own
            true = delta >= 0
            {retained + delta, baseline}

          :error ->
            {retained, baseline + start.own + start.waited}
        end
      end)

    retained + max(0, waited - baseline)
  end
end
