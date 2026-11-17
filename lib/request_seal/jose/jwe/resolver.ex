defmodule RequestSeal.JOSE.JWE.Resolver do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.Bounds
  alias RequestSeal.KeyHandle

  def run(tag, i, worker, r, _coordinator, slot, caller, notice) do
    :erlang.process_flag(:sensitive, true)

    try do
      receive do
        {:"ETS-TRANSFER", _, _, {^tag, :slot, ^slot}} -> :ok
      end

      receive do
        {^tag, :request, request, callback} ->
          if :ets.info(notice, :owner) == caller and Bounds.now() < r do
            answer = resolve(callback, request)
            send(worker, {tag, :answer, i, answer})

            receive do
              :stop -> :ok
            end
          end
      end
    catch
      _, _ -> exit(:internal_failure)
    end

    exit(:normal)
  end

  defp resolve(callback, request) do
    answer =
      try do
        callback.(request)
      catch
        _, _ -> :key_resolver_failed
      end

    normalize(answer, request.algorithm)
  end

  defp normalize(:error, _), do: :unknown_key

  defp normalize({:ok, %{algorithm: algorithm}}, expected) when algorithm != expected,
    do: :algorithm_mismatch

  defp normalize(
         {:ok,
          %{
            algorithm: algorithm,
            key: %KeyHandle{algorithm: a, capabilities: c} = handle
          } = entry},
         expected
       )
       when map_size(entry) == 2 do
    cond do
      not Bounds.within?(handle, Bounds.handle_words(), Bounds.binary_bytes()) ->
        :key_resolver_failed

      a != {:jwe, expected} ->
        :refused

      not is_list(c) ->
        :refused

      not unwrap_capability?(c) ->
        :refused

      true ->
        digest = :crypto.hash(:sha256, :erlang.term_to_binary(handle, [:deterministic]))
        {:ok, algorithm, handle, digest}
    end
  end

  defp normalize(_, _), do: :key_resolver_failed

  defp unwrap_capability?([]), do: false
  defp unwrap_capability?([:unwrap | rest]), do: proper_capabilities?(rest)
  defp unwrap_capability?([_ | rest]), do: unwrap_capability?(rest)
  defp unwrap_capability?(_), do: false

  defp proper_capabilities?([]), do: true
  defp proper_capabilities?([_ | rest]), do: proper_capabilities?(rest)
  defp proper_capabilities?(_), do: false
end
