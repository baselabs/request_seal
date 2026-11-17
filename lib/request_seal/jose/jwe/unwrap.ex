defmodule RequestSeal.JOSE.JWE.Unwrap do
  @moduledoc false
  alias RequestSeal.Custody
  alias Custody.{Context, Sink}
  alias RequestSeal.JOSE.JWE.Bounds

  def run(tag, g, u, count, parent, slot, caller, notice) do
    :erlang.process_flag(:sensitive, true)
    receive do
      {:'ETS-TRANSFER', _, _, {^tag, :slot, ^slot}} -> :ok
    end
    {handle, contributions, valid} = collect(tag, g, count, %{}, nil, true)
    # Complete library setup before the final callback gate.
    context = %Context{owner: caller, deadline: Bounds.milliseconds(u)}
    {items, routes, contributors} = combine(:maps.to_list(contributions), [], %{}, [])
    sink = Sink.routed(routes, context)
    if :ets.info(notice, :owner) == caller and Bounds.now() < u do
      kind =
        if valid and handle != nil do
          case Custody.unwrap(handle, items, sink, context) do
            {:ok, :ok} -> :ok
            _ -> :error
          end
        else
          :error
        end
      notify(contributors, tag, g, kind)
      send(parent, {tag, :unwrap_summary, g, kind})
      receive do
        :stop -> :ok
      end
    end
    exit(:normal)
  end

  defp collect(_, _, count, entries, handle, valid) when map_size(entries) == count,
    do: {handle, entries, valid}
  defp collect(tag, g, count, entries, handle, valid) do
    receive do
      {^tag, :contribution, ^g, w, candidate, items, worker} ->
        if is_map_key(entries, w) do
          collect(tag, g, count, entries, handle, valid)
        else
          valid = valid and candidate != nil and (handle == nil or handle === candidate)
          collect(tag, g, count, :maps.put(w, {items, worker}, entries), candidate, valid)
        end
      {^tag, :contributor_down, w} ->
        if is_map_key(entries, w),
          do: collect(tag, g, count, entries, handle, valid),
          else: collect(tag, g, count, :maps.put(w, {[], nil}, entries), handle, valid)
    end
  end

  defp combine([], items, routes, workers), do: {:lists.reverse(items), routes, workers}
  defp combine([{_, {items, worker}} | rest], acc, routes, workers) do
    {acc, routes} = add(items, acc, routes)
    workers = if worker == nil, do: workers, else: [worker | workers]
    combine(rest, acc, routes, workers)
  end
  defp add([], acc, routes), do: {acc, routes}
  defp add([{i, item, route} | rest], acc, routes),
    do: add(rest, [item | acc], :maps.put(i, {elem(route, 0), elem(route, 1), elem(item, 3)}, routes))
  defp notify([], _, _, _), do: :ok
  defp notify([pid | rest], tag, g, kind) do
    send(pid, {tag, :group_summary, g, kind})
    notify(rest, tag, g, kind)
  end
end
