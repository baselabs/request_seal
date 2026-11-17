defmodule RequestSeal.JOSE.JWE.Bounds do
  @moduledoc false
  @item_words 4_096
  @policy_words 4_096
  @handle_words 4_096
  @binary_bytes 16_384
  @permitted_name_bytes 16_384
  @max_tokens 10_000
  @base_teardown_us 20_000
  @per_item_teardown_us 15
  @preflight_us 5_000
  @finalization_us 100_000

  def item_words, do: @item_words
  def policy_words, do: @policy_words
  def handle_words, do: @handle_words
  def binary_bytes, do: @binary_bytes
  def permitted_name_bytes, do: @permitted_name_bytes
  def max_tokens, do: @max_tokens
  def teardown(n), do: @base_teardown_us + @per_item_teardown_us * n
  def preflight, do: @preflight_us
  def finalization, do: @finalization_us
  def before?(now, deadline), do: now < deadline
  def now, do: :erlang.monotonic_time(:microsecond)

  # Monotonic time may be negative. Integer ceil must work on both sides of zero.
  def milliseconds(us) when us > 0, do: div(us + 999, 1_000)
  def milliseconds(us), do: div(us, 1_000)
  def remaining(at), do: max(0, milliseconds(at - now()))

  def within?(term, words, bytes \\ :infinity) do
    case walk([term], words, bytes) do
      {:ok, _, _} -> :erts_debug.flat_size(term) <= words
      :over -> false
    end
  end

  defp walk(_, words, _) when words < 0, do: :over
  defp walk(_, _, bytes) when is_integer(bytes) and bytes < 0, do: :over
  defp walk([], words, bytes), do: {:ok, words, bytes}
  defp walk([[] | rest], words, bytes), do: walk(rest, words, bytes)

  defp walk([[h] | rest], words, bytes), do: walk([h | rest], words - 2, bytes)

  defp walk([[h | t] | rest], words, bytes),
    do: walk([h, t | rest], words - 2, bytes)

  defp walk([v | rest], words, bytes) when is_bitstring(v) do
    # Ref-counted binaries are shared; small binaries are copied inline.
    cost = if byte_size(v) > 64, do: 6, else: 2 + div(byte_size(v) + 7, 8)
    bytes = if bytes == :infinity, do: bytes, else: bytes - byte_size(v)
    walk(rest, words - cost, bytes)
  end

  defp walk([v | rest], words, bytes) when is_map(v) do
    if map_size(v) > words do
      :over
    else
      map_walk(:maps.iterator(v), rest, words - 4, bytes)
    end
  end

  defp walk([v | rest], words, bytes) when is_tuple(v) do
    if tuple_size(v) + 1 > words,
      do: :over,
      else: walk(:erlang.tuple_to_list(v) ++ rest, words - tuple_size(v) - 1, bytes)
  end

  defp walk([v | rest], words, bytes) when is_function(v) do
    {:env, env} = :erlang.fun_info(v, :env)
    fun_walk(env, rest, words, bytes)
  end

  defp walk([v | rest], words, bytes) when is_integer(v),
    do: walk(rest, words - :erts_debug.flat_size(v), bytes)

  defp walk([v | rest], words, bytes) when is_atom(v), do: walk(rest, words, bytes)
  # These leaves cannot expand. The final flat-size check supplies their exact
  # architecture-dependent size, including references, ports and floats.
  defp walk([_ | rest], words, bytes), do: walk(rest, words, bytes)

  defp fun_walk([], rest, words, bytes), do: walk(rest, words, bytes)

  defp fun_walk([value | env], rest, words, bytes) do
    case walk([value], words - 1, bytes) do
      {:ok, left, remaining_bytes} -> fun_walk(env, rest, left, remaining_bytes)
      :over -> :over
    end
  end

  defp map_walk(iterator, rest, words, bytes) when words >= 0 do
    case :maps.next(iterator) do
      :none ->
        walk(rest, words, bytes)

      {k, v, next} ->
        case walk([k, v], words - 2, bytes) do
          {:ok, left, remaining_bytes} -> map_walk(next, rest, left, remaining_bytes)
          :over -> :over
        end
    end
  end

  defp map_walk(_, _, _, _), do: :over
end
