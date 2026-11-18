defmodule RequestSeal.JWEOpenBoundsTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Custody, JOSE.JWE}
  alias RequestSeal.Custody.{Context, Sink}
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Resolver}
  alias RequestSeal.Test.JWEOpenRuntime, as: Runtime
  @after_compile Runtime

  setup do
    {handle, token} = Runtime.real_key()
    on_exit(fn -> Custody.release(handle) end)
    %{handle: handle, token: token, p: Runtime.policy(handle)}
  end

  test "bounded word walk counts shared occurrences and closure environments", %{p: p} do
    Runtime.with_peer(fn ->
      shared = Enum.reduce(1..25, [0], fn _, acc -> [acc, acc] end)
      :erlang.trace_pattern({Bounds, :walk, 3}, true, [:call_count])
      :erlang.trace_pattern({Bounds, :walk, 3}, :restart, [:call_count])

      try do
        refute Bounds.within?(shared, Bounds.item_words()), "walk must stop at W_item"
        {:call_count, steps} = :erlang.trace_info({Bounds, :walk, 3}, :call_count)
        assert steps <= Bounds.item_words() + 8, "walk must stop at W_item"
      after
        :erlang.trace_pattern({Bounds, :walk, 3}, false, [:call_count])
      end
    end)

    shared = Enum.reduce(1..25, [0], fn _, acc -> [acc, acc] end)

    large = List.duplicate(0, 2_500)

    refute Bounds.within?(fn -> large end, Bounds.policy_words()),
           "fun environment must be counted"

    assert Bounds.within?(Runtime.near_cap(), Bounds.item_words())
    assert :erts_debug.flat_size(Runtime.near_cap()) in 4_000..4_096
    refs = List.duplicate(make_ref(), 1_000)
    assert :erts_debug.flat_size(refs) > Bounds.item_words()
    refute Bounds.within?(refs, Bounds.item_words()), "the copy bound must use exact flat size"
    hamt = Map.new(1..1_000, fn i -> {i, {make_ref(), i}} end)
    refute Bounds.within?(hamt, Bounds.item_words()), "the copy bound must include HAMT nodes"

    assert {:ok, [{:error, %{reason: :invalid_policy}}]} =
             JWE.decrypt_many([%{token: "", expected: shared}], p)

    assert {:error, %{reason: :invalid_policy}} = JWE.decrypt("", Runtime.single(p, shared))
  end

  test "policy bound starts no process", %{p: p, token: token} do
    large = List.duplicate(0, 2_500)

    callback = fn _ ->
      Process.put(:policy_environment, large)
      :error
    end

    observer = self()

    {caller, monitor} =
      spawn_monitor(fn ->
        receive do
          :go ->
            result =
              JWE.decrypt_many([%{token: token, expected: %{}}], %{p | key_resolver: callback})

            send(observer, {:policy_result, result})
        end
      end)

    :erlang.trace(caller, true, [:procs])
    send(caller, :go)

    assert_receive {:policy_result, {:error, %{reason: :invalid_policy}}},
                   1_000,
                   "fun environment must be counted"

    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}
    barrier = :erlang.trace_delivered(caller)
    assert_receive {:trace_delivered, ^caller, ^barrier}
    refute_receive {:trace, ^caller, :spawn, _, _}, 0, "oversized policy must start no process"
    smaller = List.duplicate(0, 1_900)

    callback = fn _ ->
      Process.put(:policy_environment, smaller)
      :error
    end

    assert {:ok, [{:error, %{reason: :unknown_key}}]} =
             JWE.decrypt_many([%{token: token, expected: %{}}], %{p | key_resolver: callback})
  end

  test "markers keep what accounting reads", %{p: p} do
    oversized = %{"x" => List.duplicate(0, 2_500)}

    for {item, reason} <- [
          {%{token: "", expected: oversized}, :invalid_policy},
          {%{token: "", expected: %{}, extra: true}, :invalid_serialization}
        ] do
      assert {:ok, [{:error, %{reason: ^reason}}]} =
               JWE.decrypt_many([item], %{p | max_total_input: 1})

      result = JWE.decrypt_many([%{item | token: "ab"}], %{p | max_total_input: 1})

      assert match?({:error, %{reason: :limit}}, result),
             "marker must preserve binary token accounting"

      assert {:error, %{reason: :limit}} =
               JWE.decrypt_many([%{item | token: "a.b.c.AAAA.e"}], %{p | max_total_plaintext: 1}),
             "marker must preserve ciphertext accounting"
    end
  end

  test "byte-bound units reject before UTF-8 work", %{p: p, token: token} do
    assert {:ok, [{:error, %{reason: :invalid_policy}}]} =
             JWE.decrypt_many([%{token: token, expected: %{"x" => :binary.copy("x", 20_000)}}], p),
           "expected binary bytes must be bounded"

    name = :binary.copy("x", 16_384)

    assert {:ok, [{:ok, _}]} =
             JWE.decrypt_many([%{token: token, expected: %{}}], %{
               p
               | protected: %{permitted: [name]}
             })

    for oversized_name <- [name <> "x", :binary.copy("x", 8_388_608)] do
      result = JWE.decrypt_many([], %{p | protected: %{permitted: [oversized_name]}})

      assert match?({:error, %{reason: :invalid_policy}}, result),
             "permitted name bytes must be bounded"
    end

    assert {:ok, [{:error, %{reason: :limit}}]} =
             JWE.decrypt_many([%{token: :binary.copy("x", 1_048_577), expected: %{}}], p)
  end

  test "compact scanning keeps exact parts and JSON refusal precedence" do
    whitespace = :binary.copy(" \t\r\n", 262_141) <> " \t\n"

    for token <- [
          "....",
          "a.b.c.d.e",
          " \t\r\na.b.c.d.e",
          <<255, 0, ?., ?., ?., ?.>>,
          whitespace <> "a.b.c.d.e"
        ] do
      assert {:ok, parts} = Codec.split(token)
      assert parts == :binary.split(token, ".", [:global])
    end

    for token <- [whitespace <> "{}", whitespace <> "[....]", whitespace] do
      reason =
        if token == whitespace, do: :invalid_serialization, else: :unsupported_serialization

      assert {:error, %{reason: ^reason}} = Codec.split(token)
    end

    for token <- ["", "...", ".....", "a.b.c.d.e.f", :binary.copy(".", 1_048_576)] do
      assert {:error, %{reason: :invalid_serialization}} = Codec.split(token)
    end

    for byte <- 0..255 do
      prefix = <<byte>>
      token = prefix <> "{a.b.c.d.e}"

      cond do
        byte in [32, 9, 10, 13, 123, 91] ->
          assert {:error, %{reason: :unsupported_serialization}} = Codec.split(token)

        byte == ?. ->
          assert {:error, %{reason: :invalid_serialization}} = Codec.split(token)

        true ->
          assert {:ok, [first | _]} = Codec.split(token)
          assert first == prefix <> "{a"
      end
    end

    for opening <- ["{", "["], prefix <- ["", " \t\r\n", :binary.copy(" \t\r\n", 262_143)] do
      assert {:error, %{reason: :unsupported_serialization}} = Codec.split(prefix <> opening)
    end

    token = :binary.copy(" ", 1_048_568) <> ".b.c.d.e"
    assert byte_size(token) == 1_048_576
    assert {:ok, [first, "b", "c", "d", "e"]} = Codec.split(token)
    assert byte_size(first) == 1_048_568
    # Concatenation can leave spare capacity in the token's writable binary.
    # A retained part references that allocation, not just the logical bytes.
    assert :binary.referenced_byte_size(first) == :binary.referenced_byte_size(token)
    assert {:error, %{reason: :limit}} = Codec.split(token <> ".")
  end

  test "RequestSeal owns every UTF-8 path", %{p: p, token: token} do
    for bytes <- [<<255>>, <<192, 128>>, <<237, 160, 128>>, <<244, 144, 128, 128>>] do
      refute Codec.utf8?(bytes)

      assert {:error, %{reason: :invalid_policy}} =
               JWE.decrypt_many([], %{p | protected: %{permitted: [bytes]}})

      assert {:ok, [{:error, %{reason: :invalid_policy}}]} =
               JWE.decrypt_many([%{token: token, expected: %{bytes => 1}}], p)

      assert {:ok, [{:error, %{reason: :invalid_policy}}]} =
               JWE.decrypt_many([%{token: token, expected: %{"x" => bytes}}], p)
    end

    assert Codec.utf8?("valid \u03bb")
    assert {:error, _} = Codec.object(<<123, 34, 255, 34, 58, 48, 125>>, 16_384)
  end

  defp producer(handle, callback) do
    tag = make_ref()
    slot = {:resolver, 0}
    notice = :ets.new(:producer_caller, [:private])
    table = :ets.new(:producer_child, [:private])
    r = Bounds.now() + 5_000_000
    pid = spawn(Resolver, :run, [tag, 0, self(), r, self(), slot, self(), notice])
    ref = Process.monitor(pid)

    try do
      :ets.give_away(table, pid, {tag, :slot, slot})
      send(pid, {tag, :request, %{algorithm: "A256KW"}, callback})
      assert_receive {^tag, :answer, 0, answer}
      {answer, :erts_debug.flat_size({tag, :answer, 0, answer})}
    after
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}
      :ets.delete(notice)
      _ = handle
    end
  end

  test "callback ingress bounds at production resolver and full call", %{
    handle: handle,
    p: p,
    token: token
  } do
    for {words, accepted} <- [{2_500, false}, {1_900, true}] do
      env = List.duplicate(0, words)
      original = handle.ref

      h = %{
        handle
        | ref: fn ->
            Process.put(:handle_environment, env)
            original.()
          end
      }

      table = :ets.new(:callback_handles, [:public])
      :ets.insert(table, {:handle, h})

      callback = fn _ ->
        [{:handle, selected}] = :ets.lookup(table, :handle)
        {:ok, %{algorithm: "A256KW", key: selected}}
      end

      {answer, size} = producer(handle, callback)

      if accepted do
        assert match?({:ok, "A256KW", _, <<_::256>>}, answer)

        assert size <= Bounds.handle_words() + 32,
               "resolver answer must be bounded at its producer"
      else
        assert answer == :key_resolver_failed, "resolver answer must be bounded at its producer"
        assert size < 32, "raw callback answer reached the worker"
      end

      result = JWE.decrypt_many([%{token: token, expected: %{}}], %{p | key_resolver: callback})

      if accepted,
        do: assert(match?({:ok, [{:ok, %{plaintext: "payload"}}]}, result)),
        else: assert(match?({:ok, [{:error, %{reason: :key_resolver_failed}}]}, result))

      :ets.delete(table)
    end
  end

  test "callback ingress counts binary bytes", %{handle: handle, p: p, token: token} do
    # Count the original handle as well as the new closure environment.
    base_bytes = binary_bytes(handle)

    for {bytes, accepted} <- [{16_384 - base_bytes, true}, {16_385 - base_bytes, false}] do
      blob = :binary.copy("x", bytes)
      original = handle.ref

      h = %{
        handle
        | ref: fn ->
            Process.put(:handle_environment, blob)
            original.()
          end
      }

      callback = fn _ -> {:ok, %{algorithm: "A256KW", key: h}} end
      {answer, _} = producer(handle, callback)
      assert match?({:ok, _, _, _}, answer) == accepted, "handle binary bytes must be bounded"
      result = JWE.decrypt_many([%{token: token, expected: %{}}], %{p | key_resolver: callback})
      assert match?({:ok, [{:ok, _}]}, result) == accepted, "handle binary bytes must be bounded"
    end
  end

  defp binary_bytes(value) when is_binary(value), do: byte_size(value)

  defp binary_bytes(value) when is_function(value) do
    {:env, env} = :erlang.fun_info(value, :env)
    binary_bytes(env)
  end

  defp binary_bytes(value) when is_map(value), do: binary_bytes(Map.to_list(value))
  defp binary_bytes(value) when is_tuple(value), do: binary_bytes(Tuple.to_list(value))
  defp binary_bytes([h | t]), do: binary_bytes(h) + binary_bytes(t)
  defp binary_bytes(_), do: 0

  test "Sink deliver normalizes in the sender" do
    sink =
      Sink.new([{0, "", %{}, 128}], %Context{
        owner: self(),
        deadline: System.monotonic_time(:millisecond) + 5_000
      })

    tag = Sink.tag(sink)

    try do
      :ok = Sink.deliver(sink, 0, {:bad, :binary.copy("x", 1_048_576)})
      assert_receive {^tag, 0, normalized}
      assert normalized == :error, "sink must normalize before send"
      assert :erts_debug.flat_size({tag, 0, normalized}) < 16
      Sink.deliver(sink, :unknown, {:ok, <<0::128>>})
      refute_receive {^tag, _, _}
      Sink.deliver(sink, 0, {:ok, <<0>>})
      assert_receive {^tag, 0, :error}
      Sink.deliver(sink, 0, {:ok, <<0::128>>})
      assert_receive {^tag, 0, {:ok, <<0::128>>}}
    after
      Sink.close(sink)
    end
  end

  test "rounding never fires early on either side of monotonic zero" do
    for us <- [-1_001, -1_000, -999, -1, 0, 1, 999, 1_000, 1_001] do
      assert Bounds.milliseconds(us) * 1_000 >= us, "absolute timers must round up"
      assert Bounds.milliseconds(us) * 1_000 < us + 1_000
    end
  end

  test "caller wake reserves scheduling time inside the unchanged wait bound" do
    assert Bounds.teardown(0) == 20_000
    assert Bounds.teardown(10_000) == 170_000

    for f <- [-1_000_001, -1_001, -1, 0, 1, 1_001], n <- [0, 1, 1_000, 10_000] do
      at = Bounds.caller_wait(f, n)
      wake = Bounds.milliseconds(at) * 1_000
      assert at == f + Bounds.teardown(n) - 10_000
      assert wake >= at
      assert f + Bounds.teardown(n) - wake > 9_000
      assert at > f
    end
  end

  test "serialization scan preserves JSON whitespace and compact refusals at the byte cap" do
    prefixes =
      for unit <- [" ", "\t", "\r", "\n", " \t\r\n"],
          size <- [0, 1, 7, 8, 31, 32, 33, 255, 256, 257, 511, 512, 513, 1_048_568],
          do: binary_part(:binary.copy(unit, div(size, byte_size(unit)) + 1), 0, size)

    for prefix <- prefixes do
      for opener <- ["{}", "[]"] do
        assert {:error, %{reason: :unsupported_serialization}} = Codec.split(prefix <> opener)
      end

      assert {:ok, [^prefix, "b", "c", "d", "e"]} = Codec.split(prefix <> ".b.c.d.e")
    end

    for size <- [0, 255, 256, 257, 511, 512, 513],
        byte <- 0..255,
        byte not in [32, 9, 10, 13] do
      first = :binary.copy(" ", size) <> <<byte>> <> "{}"

      case byte do
        46 ->
          assert {:error, %{reason: :invalid_serialization}} = Codec.split(first <> ".b.c.d.e")

        opener when opener in [123, 91] ->
          assert {:error, %{reason: :unsupported_serialization}} =
                   Codec.split(first <> ".b.c.d.e")

        _ ->
          assert {:ok, [^first, "b", "c", "d", "e"]} = Codec.split(first <> ".b.c.d.e")
      end
    end

    for size <- [255, 256, 257, 511, 512, 513] do
      suffix = binary_part(:binary.copy(" \t\r\n", div(size, 4) + 1), 0, size)
      assert {:ok, %{}} = Codec.object("{}" <> suffix, 16_384)
      assert {:error, %{reason: :invalid_header}} = Codec.object("{}" <> suffix <> "x", 16_384)
    end
  end

  test "codec regression preserves admission order and content objects", %{handle: handle, p: p} do
    {:ok, token} = JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "{\"x\":1}", handle)

    assert {:ok, [{:ok, %{object: %{"x" => 1}}}]} =
             JWE.decrypt_many([%{token: token, expected: %{}}], Map.put(p, :content, :object))

    assert {:ok, %{"x" => %{"a" => %{"b" => %{"c" => 0}}}}} =
             Codec.object("{\"x\":{\"a\":{\"b\":{\"c\":0}}}}", 16_384)

    for bytes <- [
          "{\"x\":1,\"x\":2}",
          "[]",
          "{\"x\":1.5}",
          "{\"x\":{\"a\":{\"b\":{\"c\":{\"d\":0}}}}}"
        ] do
      assert {:error, _} = Codec.object(bytes, 16_384)
    end

    assert {:error, %{reason: :unsupported_serialization}} = Codec.split(" \n{}")
    assert {:error, %{reason: :invalid_base64}} = catch_codec(fn -> Codec.decode("AB") end)
  end

  defp catch_codec(fun) do
    try do
      fun.()
    catch
      :throw, {:jose_error, reason, layer} -> Codec.error(reason, layer)
    end
  end
end
