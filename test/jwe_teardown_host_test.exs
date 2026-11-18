defmodule RequestSeal.JWETeardownHostTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Test.JWETeardownGate, as: Gate

  test "zero elapsed CPU windows are rejected and retried" do
    before = "cpu 100 0 0 900 0 0 0 0 20 0"
    assert Gate.steal_percent(before, before) == nil
    refute Gate.host_admitted?(%{time: 1}, Gate.steal_percent(before, before))
    assert Gate.steal_percent(before, "cpu 195 0 0 900 0 0 0 5 20 0") == 5.0
    assert Gate.host_admitted?(%{time: 1}, 5.0)
    refute Gate.host_admitted?(%{time: 1}, 5.1)
    refute Gate.host_admitted?(nil, 0.0)
    assert Gate.steal_percent(before, "cpu 99 0 0 900 0 0 0 0") == nil
    assert Gate.steal_percent(before, "cpu 99 0 0 900 0 0 0 2") == nil
    source = File.read!("test/support/jwe_teardown_gate.ex")
    # OTP's JSON encoder serializes nil as the string "nil"; rejected windows
    # must retain JSON null so the independent Python replay sees None.
    assert source =~ "steal: if(steal == nil, do: :null, else: steal)"

    assert :json.encode(%{steal: :null}) |> IO.iodata_to_binary() |> :json.decode() == %{
             "steal" => :null
           }

    assert source =~ "if host_admitted?(result, steal) do"
    assert source =~ "host_sample(fun, online, attempts - 1, seen)"
  end

  test "unit setup loads code without executing a measured operation" do
    for module <- [RequestSeal.JOSE.JWE.Codec, RequestSeal.JOSE.JWE.Worker] do
      {:module, ^module} = :code.ensure_loaded(module)
    end

    :erlang.trace_pattern({RequestSeal.JOSE.JWE.Codec, :split, 1}, true, [])
    :erlang.trace_pattern({RequestSeal.JOSE.JWE.Worker, :authenticate, 4}, true, [])
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        receive do
          :prepare -> send(parent, {:setup, Gate.prepare_units()})
        end

        receive do
          :control ->
            RequestSeal.JOSE.JWE.Codec.split("")
            send(parent, :control_done)
        end

        receive do
          :stop -> :ok
        end
      end)

    :erlang.trace(pid, true, [:call])

    try do
      send(pid, :prepare)
      assert_receive {:setup, setup}, 5_000
      delivered = :erlang.trace_delivered(pid)
      assert_receive {:trace_delivered, ^pid, ^delivered}, 5_000
      assert length(setup) == 2
      assert Enum.all?(setup, &is_boolean(&1.loaded_before))
      assert Enum.all?(setup, &(&1.load_us >= 0))
      assert Enum.all?(setup, &(:code.is_loaded(&1.module) != false))
      refute_received {:trace, _, :call, {RequestSeal.JOSE.JWE.Codec, :split, _}}
      refute_received {:trace, _, :call, {RequestSeal.JOSE.JWE.Worker, :authenticate, _}}
      send(pid, :control)
      assert_receive {:trace, ^pid, :call, {RequestSeal.JOSE.JWE.Codec, :split, [""]}}, 5_000
      assert_receive :control_done, 5_000
    after
      Process.exit(pid, :kill)

      receive do
        {:DOWN, ^ref, :process, ^pid, _} -> :ok
      after
        5_000 -> flunk("unit setup tracer did not end")
      end

      :erlang.trace_pattern({RequestSeal.JOSE.JWE.Codec, :split, 1}, false, [])
      :erlang.trace_pattern({RequestSeal.JOSE.JWE.Worker, :authenticate, 4}, false, [])
    end
  end

  test "host admission uses available logical processors with scheduler fallback" do
    expected =
      case :erlang.system_info(:logical_processors_available) do
        n when is_integer(n) and n > 0 -> n
        _ -> System.schedulers_online()
      end

    assert Gate.host_cpus() == expected
  end
end
