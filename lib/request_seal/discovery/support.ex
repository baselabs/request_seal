defmodule RequestSeal.Discovery.Support do
  @moduledoc false
  alias RequestSeal.Discovery.Error
  def ensure(true, _), do: :ok
  def ensure(_, reason), do: throw({:discovery_error, reason})

  def safe(fun, fallback \\ :invalid_response) do
    fun.()
  rescue
    _ -> {:error, Error.new(fallback)}
  catch
    {:discovery_error, %Error{} = error} -> {:error, error}
    {:discovery_error, reason} -> {:error, Error.new(reason)}
    _, _ -> {:error, Error.new(fallback)}
  end

  def unwrap({:ok, value}), do: value
  def unwrap(:ok), do: :ok
  def unwrap(_), do: ensure(false, :invalid_response)

  def options(opts, allowed) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options
    )

    opts
  end

  def clock(clock) do
    ensure(is_function(clock, 0), :invalid_options)

    value =
      try do
        clock.()
      rescue
        _ -> ensure(false, :invalid_options)
      catch
        _, _ -> ensure(false, :invalid_options)
      end

    ensure(is_integer(value) and value in 0..999_999_999_999_999, :invalid_options)
    value
  end

  def remaining(deadline) do
    left = deadline - System.monotonic_time(:millisecond)
    ensure(left > 0, :deadline_exceeded)
    left
  end

  def run(timeout, fun) do
    owner = self()
    tag = make_ref()
    deadline = System.monotonic_time(:millisecond) + timeout

    {worker, ref} =
      spawn_monitor(fn -> watch(owner, tag, fn -> safe(fn -> fun.(deadline) end) end) end)

    receive do
      {^tag, result} ->
        Process.demonitor(ref, [:flush])

        if System.monotonic_time(:millisecond) < deadline,
          do: result,
          else: {:error, Error.new(:deadline_exceeded)}

      {:DOWN, ^ref, :process, ^worker, _} ->
        {:error, Error.new(:source_unavailable)}
    after
      timeout ->
        send(worker, {:cancel, tag})

        receive do
          {:DOWN, ^ref, :process, ^worker, _} -> :ok
        end

        receive do
          {^tag, _} -> :ok
        after
          0 -> :ok
        end

        {:error, Error.new(:deadline_exceeded)}
    end
  end

  defp watch(owner, tag, fun) do
    Process.flag(:trap_exit, true)
    ref = Process.monitor(owner)
    middle = self()
    runner = spawn_link(fn -> send(middle, {tag, fun.()}) end)

    receive do
      {^tag, result} ->
        stop(runner)
        send(owner, {tag, result})

      {:DOWN, ^ref, :process, ^owner, _} ->
        stop(runner)

      {:cancel, ^tag} ->
        stop(runner)

      {:EXIT, ^runner, _} ->
        :ok
    end
  end

  defp stop(runner) do
    Process.exit(runner, :kill)

    receive do
      {:EXIT, ^runner, _} -> :ok
    end
  end
end
