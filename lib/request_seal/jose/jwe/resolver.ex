defmodule RequestSeal.JOSE.JWE.Resolver do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.Bounds
  alias RequestSeal.KeyHandle

  def run(tag, i, worker, r, _coordinator, slot, caller, notice) do
    :erlang.process_flag(:sensitive, true)
    receive do
      {:'ETS-TRANSFER', _, _, {^tag, :slot, ^slot}} -> :ok
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
    exit(:normal)
  end

  defp resolve(callback, request) do
    answer = try do
      callback.(request)
    catch
      _, _ -> :key_resolver_failed
    end
    normalize(answer, request.algorithm)
  end

  defp normalize(:error, _), do: :unknown_key
  defp normalize({:ok, %{algorithm: algorithm, key: %KeyHandle{} = handle} = entry}, expected)
       when map_size(entry) == 2 do
    cond do
      algorithm != expected -> :algorithm_mismatch
      not Bounds.within?(handle, Bounds.handle_words(), Bounds.binary_bytes()) -> :key_resolver_failed
      handle.algorithm != {:jwe, expected} -> :refused
      not is_list(handle.capabilities) -> :refused
      not :lists.member(:unwrap, handle.capabilities) -> :refused
      true ->
        digest = :crypto.hash(:sha256, :erlang.term_to_binary(handle, [:deterministic]))
        {:ok, algorithm, handle, digest}
    end
  end
  defp normalize(_, _), do: :key_resolver_failed
end
