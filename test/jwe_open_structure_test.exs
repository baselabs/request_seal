defmodule RequestSeal.JWEOpenStructureTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Test.JWEOpenAnalyzer, as: Analyzer

  alias RequestSeal.JOSE.JWE.{
    Bounds,
    Codec,
    Coordinator,
    Guard,
    Open,
    Preflight,
    Resolver,
    Worker
  }

  test "14 derived roots no caller code and exact notice sites" do
    result = Analyzer.check()
    assert length(result.roots) == 6, "derived roots must cover every role"
    assert result.roles[Resolver] == :caller_code
    assert result.roles[Guard] == :guard
    assert Enum.all?(result.allowlist, fn {_, reason} -> is_binary(reason) and reason != "" end)
  end

  test "coordinator has no input codec digest or CEK work" do
    calls = Analyzer.forms(Coordinator) |> Analyzer.calls()

    for {:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, _} <- calls do
      refute module in [Codec, :json, :base64, :binary, String, Enum, IO, :telemetry],
             "codec work belongs in preflight or range worker"

      refute function in [:term_to_binary, :hash, :crypto_one_time_aead],
             "coordinator must not receive input or keys"
    end
  end

  test "library entries keep sensitivity and closed atom exits" do
    for module <- [Preflight, Worker, Resolver, RequestSeal.JOSE.JWE.Unwrap] do
      calls = Analyzer.forms(module) |> Analyzer.calls()

      assert Enum.any?(calls, fn
               {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :process_flag}},
                [{:atom, _, :sensitive}, {:atom, _, true}]} ->
                 true

               _ ->
                 false
             end),
             "production sensitivity must remain enabled"
    end

    for module <- [Guard, Coordinator, Preflight, Worker] do
      source = module |> Module.split() |> List.last() |> Macro.underscore()
      text = File.read!("lib/request_seal/jose/jwe/#{source}.ex")
      refute text =~ "System.get_env", "mutations must be patches, never library switches"
    end
  end

  test "reaction reads owners before dequeue and closes causes at the flip" do
    source = File.read!("lib/request_seal/jose/jwe/guard.ex")
    assert source =~ "s = check(s)", "guard must check owners before dequeue"
    assert source =~ ":ets.info(map_get(:registry, s), :owner) == self()",
           "registry owner is the end marker"
    assert source =~ "defp check(s), do: s", "causes must close at coordinator end"

    assert source =~ "stop_at(anchor, :atomics.get(map_get(:flag, s), 2))",
           "stop_at reads accepted cardinality at flip"

    assert source =~ "min(now, map_get(:d, s))", "D must remain the teardown anchor"
    assert source =~ "{:outcome, :replied}", "reason must come from the outcome row"
  end

  test "notice deletion precedes the ended forward" do
    source = File.read!("lib/request_seal/jose/jwe/guard.ex")
    {deleted, _} = :binary.match(source, ":ets.delete(tid)")
    {forwarded, _} = :binary.match(source, "send(coordinator, {tag, :ended, slot})")
    assert deleted < forwarded, "notice deletion must precede ended forward"
  end

  test "cardinality accepted before preflight ok" do
    forms = Analyzer.forms(Coordinator)

    writes =
      for {:function, _, function, _, body} <- forms,
          {:call, _, {:remote, _, {:atom, _, :atomics}, {:atom, _, :put}},
           [_, {:integer, _, 2}, _]} <- Analyzer.calls(body),
          do: function

    assert writes == [:cardinality], "accepted cardinality must be written at acceptance"
    source = File.read!("lib/request_seal/jose/jwe/coordinator.ex")
    assert source =~ "when tc < map_get(:d, s)", "cardinality stamp must decide the D boundary"
  end

  test "preflight checkpoints before every bounded unit and row send" do
    text = File.read!("lib/request_seal/jose/jwe/preflight.ex")

    for function <- [
          :take_policy,
          :take_count,
          :intake,
          :handoff,
          :send_policy,
          :send_rows,
          :send_done
        ] do
      assert Enum.any?(Analyzer.forms(Preflight), fn
               {:function, _, ^function, _, body} ->
                 Enum.any?(Analyzer.calls(body), fn
                   {:call, _, {:remote, _, {:atom, _, Codec}, {:atom, _, :unit}}, _} -> true
                   _ -> false
                 end)

               _ ->
                 false
             end),
             "every preflight unit needs a deadline check"
    end

    assert text =~ "send(pid, {tag, :row, i, row})", "handoff must copy one bounded row"
    refute text =~ "send(pid, {tag, :rows, rows})", "handoff must copy one bounded row"
    assert text =~ ":atomics.put(flag, 1, 1)", "preflight must stop caller intake"
    coordinator = File.read!("lib/request_seal/jose/jwe/coordinator.ex")

    assert coordinator =~ ":erlang.process_flag(:message_queue_data, :off_heap)",
           "coordinator mailbox must be off heap"
  end

  test "zero start gate is adjacent to production callback" do
    source = File.read!("lib/request_seal/jose/jwe/resolver.ex")

    assert source =~ ":ets.info(notice, :owner) == caller and Bounds.now() < r",
           "resolver needs the zero start gate"

    {:ok, index} =
      case :binary.match(source, "if :ets.info") do
        {i, _} -> {:ok, i}
      end

    {callback, _} = :binary.match(source, "answer = resolve(callback, request)")
    between = binary_part(source, index, callback - index)
    refute between =~ "receive", "no receive may separate gate and callback"
    unwrap = File.read!("lib/request_seal/jose/jwe/unwrap.ex")
    {sink, _} = :binary.match(unwrap, "sink = Sink.routed(routes, context)")
    {gate, _} = :binary.match(unwrap, "if :ets.info(notice, :owner) == caller")
    assert sink < gate, "sink setup must precede the custody gate"
  end

  test "R12-8 contributions deduplicate by worker id" do
    text = File.read!("lib/request_seal/jose/jwe/unwrap.ex")
    assert text =~ "is_map_key(entries, w)", "contributor and down must share one key"

    assert text =~ ":maps.put(w, {items, worker}, entries)",
           "contributor and down must share one key"

    assert text =~ ":maps.put(w, {[], nil}, entries)", "contributor and down must share one key"
  end

  test "caller bootstrap has one item per send and same accepted cardinality bound" do
    text = File.read!("lib/request_seal/jose/jwe/open.ex")

    assert text =~ "send(pid, {s.tag, :item, i, kind, token, expected})",
           "bootstrap must copy one item"

    assert text =~ ":atomics.get(s.flag, 1) == 0", "caller must read the input stop flag"
    assert text =~ "s.f + Bounds.teardown(:atomics.get(s.flag, 2))", "caller wait must be bounded"
    assert text =~ ":maps.remove(:expected, protected)", "single policy must not carry expected"
    assert Bounds.teardown(10_000) == 170_000
    assert Open.wait_end(123) == 123
  end

  test "outcome row is immediately before reply send" do
    {:function, _, :reply, 2, body} =
      Enum.find(Analyzer.forms(Coordinator), fn
        {:function, _, :reply, 2, _} -> true
        _ -> false
      end)

    markers =
      body
      |> Analyzer.calls()
      |> Enum.flat_map(fn
        {:call, _, {:remote, _, {:atom, _, :ets}, {:atom, _, :insert}},
         [_, {:tuple, _, [{:atom, _, :outcome}, {:atom, _, :replied}]}]} ->
          [:outcome]

        {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :send}},
         [_, {:tuple, _, [_, {:atom, _, :reply} | _]}]} ->
          [:reply]

        _ ->
          []
      end)

    assert markers == [:outcome, :reply], "outcome row must precede reply"
  end
end
