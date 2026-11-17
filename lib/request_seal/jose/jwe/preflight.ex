defmodule RequestSeal.JOSE.JWE.Preflight do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.{Bounds, Codec}

  def run(tag, parent, flag, mode, d) do
    :erlang.process_flag(:sensitive, true)

    validated =
      try do
        p = take_policy(tag, flag, d, mode)
        n = take_count(tag, parent, flag, d, mode, p)
        {rows, _, _} = intake(tag, flag, d, mode, p, n, 0, [], 0, 0)
        Codec.unit(flag, d)
        {:ok, p, rows}
      catch
        :throw, :preflight_deadline ->
          deadline(tag, parent, flag)

        :throw, {:jose_error, reason, layer} ->
          :atomics.put(flag, 1, 1)
          send(parent, {tag, :preflight, {:outer, reason, layer}})
          :done

        _, _ ->
          exit(:internal_failure)
      end

    case validated do
      {:ok, p, rows} ->
        send(parent, {tag, :preflight, :ok})

        try do
          handoff(tag, parent, flag, d, p, :lists.reverse(rows), %{})
        catch
          :throw, :preflight_deadline -> deadline(tag, parent, flag)
          _, _ -> exit(:internal_failure)
        end

      :done ->
        :ok
    end

    exit(:normal)
  end

  defp deadline(tag, parent, flag) do
    :atomics.put(flag, 1, 1)
    send(parent, {tag, :preflight, :deadline})
    :done
  end

  defp take_policy(tag, flag, d, mode) do
    Codec.unit(flag, d)

    receive do
      {^tag, :policy, p} -> Codec.policy(p, mode == :batch, flag, d)
    after
      Bounds.remaining(d) ->
        Codec.unit(flag, d)
        take_policy(tag, flag, d, mode)
    end
  end

  defp take_count(tag, parent, flag, d, mode, p) do
    Codec.unit(flag, d)

    receive do
      {^tag, :count, :over_cap} ->
        Codec.fail(:limit)

      {^tag, :count, :improper} ->
        Codec.fail(:invalid_serialization)

      {^tag, :count, n} when is_integer(n) and n >= 0 ->
        Codec.ensure(mode == :single or n <= :erlang.map_get(:max_tokens, p), :limit)
        # No checkpoint or receive separates the timestamp from the report.
        tc = Bounds.now()
        if tc >= d, do: throw(:preflight_deadline)
        send(parent, {tag, :cardinality, n, tc})
        n
    after
      Bounds.remaining(d) ->
        Codec.unit(flag, d)
        take_count(tag, parent, flag, d, mode, p)
    end
  end

  defp intake(tag, flag, d, mode, p, n, n, rows, input, plaintext) do
    :atomics.put(flag, 1, 1)
    Codec.unit(flag, d)

    receive do
      {^tag, :input_end} -> {rows, input, plaintext}
    after
      Bounds.remaining(d) ->
        Codec.unit(flag, d)
        intake(tag, flag, d, mode, p, n, n, rows, input, plaintext)
    end
  end

  defp intake(tag, flag, d, mode, p, n, i, rows, input, plaintext) do
    Codec.unit(flag, d)

    receive do
      {^tag, :item, ^i, kind, token, expected} ->
        Codec.unit(flag, d)
        result = validate(kind, token, expected, p)

        if mode == :single and match?({:error, %{reason: :invalid_policy}}, result),
          do: Codec.fail(:invalid_policy)

        Codec.unit(flag, d)

        {encoded, refusal} =
          case result do
            {:ok, bytes} -> {bytes, nil}
            {:error, error} -> {nil, error}
          end

        input =
          input + if(is_binary(token), do: byte_size(token), else: 0) +
            if(is_binary(encoded), do: byte_size(encoded), else: 0)

        Codec.unit(flag, d)
        split = Codec.split(token)
        plaintext = plaintext + estimate(split)

        if mode == :batch do
          Codec.ensure(input <= :erlang.map_get(:max_total_input, p), :limit)
          Codec.ensure(plaintext <= :erlang.map_get(:max_total_plaintext, p), :limit)
        end

        row = if refusal == nil, do: {expected, split}, else: {:failed, refusal}
        intake(tag, flag, d, mode, p, n, i + 1, [{i, row} | rows], input, plaintext)
    after
      Bounds.remaining(d) ->
        Codec.unit(flag, d)
        intake(tag, flag, d, mode, p, n, i, rows, input, plaintext)
    end
  end

  defp validate(kind, _, _, _) when kind != :exact, do: Codec.error(:invalid_serialization)
  defp validate(:exact, _, :oversized, _), do: Codec.error(:invalid_policy)

  defp validate(:exact, _, expected, p),
    do: Codec.expected(expected, :erlang.map_get(:permitted, :erlang.map_get(:protected, p)))

  defp estimate({:ok, [_, _, _, ct, _]}), do: div(byte_size(ct) * 3, 4)
  defp estimate(_), do: 0

  defp handoff(tag, parent, flag, d, p, rows, workers) do
    Codec.unit(flag, d)

    receive do
      {^tag, :worker, w, lo, hi, pid} ->
        handoff(tag, parent, flag, d, p, rows, :maps.put(w, {lo, hi, pid}, workers))

      {^tag, :workers_done} ->
        send_policy(:maps.to_list(workers), tag, flag, d, p)
        send_rows(rows, tag, flag, d, workers)
        send_done(:maps.to_list(workers), tag, flag, d)
        Codec.unit(flag, d)
        send(parent, {tag, :handed_off})
    after
      Bounds.remaining(d) ->
        Codec.unit(flag, d)
        handoff(tag, parent, flag, d, p, rows, workers)
    end
  end

  defp send_policy([], _, _, _, _), do: :ok

  defp send_policy([{_, {_, _, pid}} | rest], tag, flag, d, p) do
    Codec.unit(flag, d)
    send(pid, {tag, :policy, p})
    send_policy(rest, tag, flag, d, p)
  end

  defp send_rows([], _, _, _, _), do: :ok

  defp send_rows([{i, row} | rest], tag, flag, d, workers) do
    Codec.unit(flag, d)
    pid = owner(:maps.to_list(workers), i)
    send(pid, {tag, :row, i, row})
    send_rows(rest, tag, flag, d, workers)
  end

  defp owner([{_, {lo, hi, pid}} | _], i) when i >= lo and i <= hi, do: pid
  defp owner([_ | rest], i), do: owner(rest, i)
  defp send_done([], _, _, _), do: :ok

  defp send_done([{_, {_, _, pid}} | rest], tag, flag, d) do
    Codec.unit(flag, d)
    send(pid, {tag, :rows_done})
    send_done(rest, tag, flag, d)
  end
end
