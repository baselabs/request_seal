defmodule RequestSeal.JWETeardownHostTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Test.{HostConditions, JWETeardownGate}

  test "zero elapsed CPU windows are rejected and record null percentages" do
    cpu = "cpu 10 20 30 1000 50 60 70 0 15 19"
    process = [process_stat(20, 10)]
    assert HostConditions.percentages(cpu, cpu, process, process) == {nil, nil}
    refute HostConditions.admitted?(nil, nil)

    assert :json.encode(%{steal: :null, foreign_cpu: :null})
           |> IO.iodata_to_binary()
           |> :json.decode() == %{"steal" => :null, "foreign_cpu" => :null}
  end

  test "host admission subtracts the measured process and rejects skew" do
    before = "cpu 10 20 30 1000 50 60 70 0 15 19"
    after_cpu = "cpu 30 25 40 1020 80 65 75 5 32 24"
    process = [process_stat(20, 10)]

    cases = [{45, 0.0, true}, {35, 10.0, true}, {34, 11.0, false}, {46, -1.0, false}]

    for {system, foreign, admitted?} <- cases do
      assert HostConditions.percentages(before, after_cpu, process, [process_stat(30, system)]) ==
               {5.0, foreign}

      assert HostConditions.admitted?(5.0, foreign) == admitted?
    end

    high_steal = "cpu 30 25 40 1019 80 65 75 6 32 24"
    assert HostConditions.percentages(before, high_steal, process, [process_stat(30, 45)]) ==
             {6.0, 0.0}

    refute HostConditions.admitted?(6.0, 0.0)
  end

  test "live and reaped descendants contribute only observed window CPU" do
    before_cpu = "cpu 10 20 30 1000 50 60 70 0 15 19"
    after_cpu = "cpu 30 25 40 1020 80 65 75 5 32 24"
    before_root = process_stat(20, 10, waited: 100)
    after_root = process_stat(23, 12, waited: 131)
    unrelated = process_stat(90, 0, pid: 128)

    before =
      HostConditions.process_tree(before_root, [
        unrelated,
        process_stat(10, 5, pid: 124, parent: 123),
        process_stat(8, 2, pid: 125, parent: 123, waited: 3),
        process_stat(4, 0, pid: 126, parent: 124)
      ])

    after_processes =
      HostConditions.process_tree(after_root, [
        unrelated,
        process_stat(20, 10, pid: 124, parent: 123),
        process_stat(7, 0, pid: 126, parent: 124),
        process_stat(40, 5, pid: 127, parent: 123)
      ])

    refute unrelated in before
    refute unrelated in after_processes
    assert length(before) == 4
    assert length(after_processes) == 4
    assert HostConditions.percentages(before_cpu, after_cpu, before, after_processes) == {5.0, 4.0}
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
          :prepare -> send(parent, {:setup, JWETeardownGate.prepare_units()})
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
  defp process_stat(user, system, options \\ []) do
    pid = Keyword.get(options, :pid, 123)
    parent = Keyword.get(options, :parent, 1)
    waited = Keyword.get(options, :waited, 0)
    "#{pid} (beam ) smp) S #{parent} 2 3 0 -1 0 0 0 0 0 #{user} #{system} #{waited} 0 20 0 8 0 1234"
  end
end
