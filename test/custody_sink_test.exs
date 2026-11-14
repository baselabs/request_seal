defmodule RequestSeal.CustodySinkTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Custody
  alias Custody.{Context, Sink}
  alias RequestSeal.Test.UnwrapCustodian

  @wrapped Base.decode16!("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
  @cek Base.decode16!("00112233445566778899AABBCCDDEEFF")
  @item {@wrapped, %{}, 128}

  defp call(mode, timeout \\ 500) do
    handle = UnwrapCustodian.start(mode, self())
    on_exit(fn -> Custody.release(handle) end)
    observer = self()
    items = List.duplicate(@item, if(mode == :duplicates, do: 3, else: 2))

    task =
      Task.async(fn ->
        result = Custody.unwrap(handle, items, timeout: timeout)
        send(observer, {:sink_owner_mailbox, self(), Process.info(self(), :messages)})
        result
      end)

    assert_receive {:holder_ready, holder, runner, sink, context}, 1000
    {task, holder, runner, sink, context}
  end

  test "01 a finished prefix survives a later holder stall through Custody.run" do
    {task, holder, _, _, _} = call(:stall, 150)
    send(holder, :deliver)
    assert {:ok, [{:ok, @cek}, {:error, :deadline_exceeded}]} = Task.await(task)
  end

  test "02 delivered prefix survives a callback error" do
    {task, holder, _, _, _} = call(:error)
    send(holder, :deliver)
    assert {:ok, [{:ok, @cek}, {:error, :decryption_failed}]} = Task.await(task)
  end

  test "03 delivered prefix survives Custody.run late-result rejection" do
    {task, holder, runner, _, context} = call(:lost, 200)
    {:links, [middle]} = Process.info(runner, :links)
    {:monitored_by, monitors} = Process.info(middle, :monitored_by)
    helper = Enum.find(monitors, &(&1 != task.pid)) || hd(monitors)
    assert :erlang.suspend_process(helper)

    try do
      send(holder, :deliver)
      assert_receive {:prefix_sent, ^holder}

      receive do
      after
        max(Context.remaining(context) + 20, 0) -> :ok
      end
    after
      :erlang.resume_process(helper)
    end

    assert {:ok, [{:ok, @cek}, {:error, :deadline_exceeded}]} = Task.await(task)
  end

  test "04 duplicates are inert malformed first deliveries fail and unknown indices create nothing" do
    {task, holder, _, _, _} = call(:duplicates)
    send(holder, :deliver)

    assert {:ok, [{:ok, @cek}, {:error, :decryption_failed}, {:error, :decryption_failed}]} =
             Task.await(task)
  end

  test "05 a delivery queued before revocation is drained and times out" do
    {task, holder, _, sink, context} = call(:stall, 200)
    assert :erlang.suspend_process(task.pid)

    try do
      send(holder, :deliver)
      assert_receive {:prefix_sent, ^holder}

      receive do
      after
        max(Context.remaining(context) + 20, 0) -> :ok
      end
    after
      :erlang.resume_process(task.pid)
    end

    assert {:ok, [{:error, :deadline_exceeded}, {:error, :deadline_exceeded}]} = Task.await(task)
    owner = task.pid
    assert_receive {:sink_owner_mailbox, ^owner, {:messages, messages}}
    refute Enum.any?(messages, &match?({tag, _, _} when tag == sink.tag, &1))
  end

  test "06 delivery after alias revocation never arrives at its owner" do
    context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 60}
    sink = Sink.new([{0, @wrapped, %{}, 128}], context)
    handle = UnwrapCustodian.start(:stall, self())

    try do
      # The callback crosses the real run boundary; the sink stays test-owned.
      task =
        Task.async(fn -> Custody.unwrap(handle, [{0, @wrapped, %{}, 128}], sink, context) end)

      assert_receive {:holder_ready, holder, _, _, _}

      assert Sink.collect(sink, fn ->
               monitor = Process.monitor(task.pid)
               receive do: ({:DOWN, ^monitor, _, _, _} -> :ok)
             end) == [:timeout]

      Task.await(task)
      send(holder, :deliver)
      assert_receive {:prefix_sent, ^holder}
      tag = sink.tag
      refute_receive {^tag, _, _}
    after
      Sink.close(sink)
      Custody.release(handle)
    end
  end

  test "07 ok summary settles undelivered indices as error" do
    {task, holder, _, _, _} = call(:ok)
    send(holder, :deliver)
    assert {:ok, [{:ok, @cek}, {:error, :decryption_failed}]} = Task.await(task)
  end

  test "sink oracle observes the positive control then ICV failure with no CEK envelope" do
    kek = Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    {:ok, handle} = Custody.Local.new({:jwe, "A256KW"}, {:aes, kek})

    try do
      for {wrapped, expected} <- [{@wrapped, {:ok, @cek}}, {<<0::192>>, :error}] do
        context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 1000}
        items = [{0, wrapped, %{}, 128}]
        sink = Sink.new(items, context)

        try do
          task = Task.async(fn -> Custody.unwrap(handle, items, sink, context) end)
          tag = sink.tag
          assert_receive {^tag, 0, ^expected}
          assert Task.await(task) == {:ok, :ok}
          refute_receive {^tag, _, {:ok, _}}
        after
          Sink.close(sink)
        end
      end
    after
      Custody.release(handle)
    end
  end
end
