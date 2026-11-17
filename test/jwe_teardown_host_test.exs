defmodule RequestSeal.JWETeardownHostTest do
  use ExUnit.Case, async: true
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

  test "host admission uses available logical processors with scheduler fallback" do
    expected =
      case :erlang.system_info(:logical_processors_available) do
        n when is_integer(n) and n > 0 -> n
        _ -> System.schedulers_online()
      end

    assert Gate.host_cpus() == expected
  end
end
