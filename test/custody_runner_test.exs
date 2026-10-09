defmodule RequestSeal.CustodyRunnerTest do
  use ExUnit.Case, async: true
  alias RequestSeal.Custody
  alias RequestSeal.Custody.{Context, Error}

  test "runs callbacks in sensitive processes and returns tagged results" do
    owner = self()

    assert {:ok, {runner, middle}} =
             Custody.run(context(), fn ->
               send(self(), :sensitivity_probe)
               assert Process.info(self(), :messages) == {:messages, []}
               assert_receive :sensitivity_probe
               {:links, [middle]} = Process.info(self(), :links)
               send(middle, :sensitivity_probe)
               assert Process.info(middle, :messages) == {:messages, []}
               refute self() == owner
               {:ok, {self(), middle}}
             end)

    refute Process.alive?(runner)
    refute Process.alive?(middle)
    assert {:ok, :ok} = Custody.run(context(), fn -> :ok end)
    assert {:error, :declined} = Custody.run(context(), fn -> {:error, :declined} end)
    assert {:messages, []} = Process.info(self(), :messages)
  end

  test "absolute deadlines beyond one receive interval do not crash" do
    assert {:ok, :completed} =
             Custody.run(context(4_294_967_296), fn -> {:ok, :completed} end)

    assert {:messages, []} = Process.info(self(), :messages)
  end

  test "expired contexts never start the callback" do
    owner = self()

    assert {:error, %Error{reason: :deadline_exceeded, retryable: true}} =
             Custody.run(context(-1), fn ->
               send(owner, :started)
               {:ok, :late}
             end)

    refute_receive :started
  end

  test "deadline kills a blocked callback even if it traps exits" do
    owner = self()

    caller =
      Task.async(fn ->
        Custody.run(context(150), fn ->
          Process.flag(:trap_exit, true)
          {:links, [middle]} = Process.info(self(), :links)
          send(owner, {:workers, self(), middle})

          receive do
            :finish -> {:ok, :late}
          end
        end)
      end)

    assert_receive {:workers, runner, middle}
    refs = monitor_all([runner, middle])
    assert {:error, %Error{reason: :deadline_exceeded}} = Task.await(caller)
    assert_down(refs)
  end

  test "caller death cancels blocked callbacks and all nested runs" do
    owner = self()

    caller =
      spawn(fn ->
        Custody.run(context(), fn ->
          {:links, [middle]} = Process.info(self(), :links)
          send(owner, {:outer, self(), middle})

          Custody.run(context(), fn ->
            Process.flag(:trap_exit, true)
            {:links, [middle]} = Process.info(self(), :links)
            send(owner, {:inner, self(), middle})

            receive do
              :finish -> {:ok, :late}
            end
          end)
        end)
      end)

    assert_receive {:outer, outer, outer_middle}
    assert_receive {:inner, inner, inner_middle}
    refs = monitor_all([caller, outer, outer_middle, inner, inner_middle])
    Process.exit(caller, :kill)
    assert_down(refs)
  end

  test "context owner death also cancels a run invoked by another caller" do
    owner =
      spawn(fn ->
        receive do
          :finish -> :ok
        end
      end)

    test_pid = self()

    caller =
      Task.async(fn ->
        Custody.run(%{context() | owner: owner}, fn ->
          send(test_pid, {:runner, self()})

          receive do
            :finish -> {:ok, :late}
          end
        end)
      end)

    assert_receive {:runner, runner}
    refs = monitor_all([runner])
    Process.exit(owner, :kill)
    assert {:error, %Error{reason: :custodian_failure}} = Task.await(caller)
    assert_down(refs)
  end

  test "exceptions, throws, exits and invalid results are bounded failures" do
    for callback <- [
          fn -> raise "SECRET-CANARY" end,
          fn -> throw("SECRET-CANARY") end,
          fn -> exit("SECRET-CANARY") end,
          fn -> Process.exit(self(), :kill) end,
          fn -> :unexpected end
        ] do
      assert {:error, %Error{reason: :custodian_failure, retryable: false} = error} =
               Custody.run(context(), callback)

      refute inspect(error) =~ "SECRET-CANARY"
      assert {:messages, []} = Process.info(self(), :messages)
    end
  end

  test "recognized validation failures retain only bounded custody reasons" do
    for {tag, reason} <- [{:custody_error, :key_not_found}, {:crypto_error, :invalid_key}] do
      assert {:error, %Error{reason: ^reason, retryable: false}} =
               Custody.run(context(), fn -> throw({tag, reason}) end)
    end

    assert {:error, %Error{reason: :custodian_failure}} =
             Custody.run(context(), fn -> throw({:custody_error, "SECRET-CANARY"}) end)

    assert {:messages, []} = Process.info(self(), :messages)
  end

  test "nested successes and inner deadline failures preserve outer mailbox" do
    assert {:ok, :nested} =
             Custody.run(context(), fn ->
               Custody.run(context(), fn -> {:ok, :nested} end)
             end)

    assert {:ok, :contained} =
             Custody.run(context(), fn ->
               assert {:error, %Error{reason: :deadline_exceeded}} =
                        Custody.run(context(20), fn ->
                          receive do
                            :finish -> {:ok, :late}
                          end
                        end)

               assert {:messages, []} = Process.info(self(), :messages)
               {:ok, :contained}
             end)

    assert {:messages, []} = Process.info(self(), :messages)
  end

  test "outer deadline cancels a nested run with a later deadline" do
    owner = self()

    caller =
      Task.async(fn ->
        Custody.run(context(150), fn ->
          Custody.run(context(), fn ->
            {:links, [middle]} = Process.info(self(), :links)
            send(owner, {:nested, self(), middle})

            receive do
              :finish -> {:ok, :late}
            end
          end)
        end)
      end)

    assert_receive {:nested, runner, middle}
    refs = monitor_all([runner, middle])
    assert {:error, %Error{reason: :deadline_exceeded}} = Task.await(caller)
    assert_down(refs)
  end

  test "queued duplicate replies are drained and later replies are discarded" do
    for mode <- [:success, :expired] do
      owner = self()

      caller =
        Task.async(fn ->
          result =
            Custody.run(context(500), fn ->
              send(owner, {:ready, self()})

              receive do
                :finish -> {:ok, :completed}
              end
            end)

          send(owner, {:returned, result})

          receive do
            :collect -> Process.info(self(), :messages)
          end
        end)

      assert_receive {:ready, runner}
      assert :erlang.suspend_process(caller.pid)

      {reply, {:ok, :completed}} =
        packet =
        try do
          send(runner, :finish)
          packet = await_packet(caller.pid)
          # Reuse the real runner reply to exercise duplicate and delayed delivery.
          send(caller.pid, packet)
          if mode == :expired, do: Process.sleep(550)
          packet
        after
          :erlang.resume_process(caller.pid)
        end

      if mode == :success do
        assert_receive {:returned, {:ok, :completed}}, 1_000
      else
        assert_receive {:returned, {:error, %Error{reason: :deadline_exceeded}}}, 1_000
      end

      # The actual reply destination is revoked before run/2 returns.
      send(reply, packet)
      send(caller.pid, :collect)
      assert {:messages, []} = Task.await(caller)
    end
  end

  test "cleanup preserves unrelated caller messages" do
    send(self(), :unrelated)
    assert {:ok, :completed} = Custody.run(context(), fn -> {:ok, :completed} end)
    assert_received :unrelated
    assert {:messages, []} = Process.info(self(), :messages)
  end

  test "invalid contexts and callbacks return invalid_options" do
    for ctx <- [nil, %Context{}, %{context() | deadline: :infinity}, %{context() | owner: nil}] do
      assert {:error, %Error{reason: :invalid_options}} =
               Custody.run(ctx, fn -> {:ok, :unused} end)
    end

    assert {:error, %Error{reason: :invalid_options}} = Custody.run(context(), nil)
  end

  defp await_packet(pid, attempts \\ 100)
  defp await_packet(_, 0), do: flunk("runner did not send its actual result")

  defp await_packet(pid, attempts) do
    {:messages, messages} = Process.info(pid, :messages)

    case Enum.find(messages, fn
           {ref, {:ok, :completed}} -> is_reference(ref)
           _ -> false
         end) do
      nil ->
        Process.sleep(5)
        await_packet(pid, attempts - 1)

      packet ->
        packet
    end
  end

  defp context(timeout \\ 5_000),
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}

  defp monitor_all(pids), do: Enum.map(pids, &{&1, Process.monitor(&1)})

  defp assert_down(refs) do
    for {pid, ref} <- refs do
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 1_000
      refute Process.alive?(pid)
    end
  end
end
