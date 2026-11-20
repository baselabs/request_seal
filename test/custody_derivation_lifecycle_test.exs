defmodule RequestSeal.CustodyDerivationLifecycleTest do
  use ExUnit.Case, async: true
  alias RequestSeal.Custody
  alias RequestSeal.Custody.{Cleanup, Local}

  # A real custodian: all keys and transitions live in Local holders. Messages
  # control only callback completion and an explicit release refusal, never
  # crypto results or a simulated service.
  defmodule Controlled do
    @behaviour Custody
    def derive(ref, request, context) do
      {local, controller, mode} = ref.()
      if mode == :derive_refusal do
        {:error, :custodian_rejected}
      else
        with {:ok, child} <- Local.derive(local, request, context) do
          ref = fn -> {child, controller, mode} end
          send(controller, {:candidate, ref, self(), context})
          if mode == :derive_loss, do: wait()
          {:ok, ref}
        end
      end
    end

    def commit(ref, token, context) do
      {local, controller, mode} = ref.()
      if mode == :commit_refusal do
        send(controller, :explicit_refusal)
        {:error, :unavailable}
      else
        with :ok <- Local.commit(local, token, context) do
          send(controller, {:committed, ref, self(), context})
          wait()
          :ok
        end
      end
    end

    def release(ref, context) do
      {local, controller, _} = ref.()
      send(controller, {:release_attempt, self(), context, System.monotonic_time(:millisecond)})
      receive do
        :refuse -> {:error, :custodian_unavailable}
        :raise -> raise "release refused"
        :release -> Local.release(local, context)
      end
    end

    def sign(ref, algorithm, bytes, context) do
      {local, _, _} = ref.()
      Local.sign(local, algorithm, bytes, context)
    end

    def public_key(ref) do
      {local, _, _} = ref.()
      Local.public_key(local)
    end

    def identity(ref) do
      {local, _, _} = ref.()
      Local.identity(local)
    end

    defp wait do
      receive do
        :continue -> :ok
      end
    end
  end

  test "failed derivation and explicit commit refusal are ordinary errors without release" do
    for {mode, reason} <- [derive_refusal: :custodian_rejected, commit_refusal: :unavailable] do
      {owner, owner_down, parent} = begin_derive(mode, 500)
      assert_receive {:result, {:error, %Custody.Error{reason: ^reason}}}, 2000
      if mode == :commit_refusal do
        assert_receive {:candidate, ref, _, _}
        assert_receive :explicit_refusal
        down = Process.monitor(holder(ref))
        assert_receive {:DOWN, ^down, :process, _, _}, 1500
      end
      refute_receive {:release_attempt, _, _, _}, 20
      finish(owner, owner_down, parent)
    end
  end

  test "derive runner loss leaves only an expiring uncommitted child and returns a bare error" do
    {owner, owner_down, parent} = begin_derive(:derive_loss, 500)
    assert_receive {:candidate, ref, runner, _}, 2000
    down = Process.monitor(holder(ref))
    Process.exit(runner, :kill)
    assert_receive {:result, {:error, %Custody.Error{reason: :custodian_failure}}}, 1500
    assert_receive {:DOWN, ^down, :process, _, _}, 1500
    refute_receive {:release_attempt, _, _, _}, 20
    finish(owner, owner_down, parent)
  end

  test "lost commit result releases once under a fresh 1000 ms context and confirms DOWN" do
    {owner, owner_down, parent} = begin_derive(:commit_loss, 500)
    assert_receive {:committed, ref, _runner, original}, 2000
    down = Process.monitor(holder(ref))
    assert_receive {:release_attempt, release, cleanup_context, observed}, 2000
    assert cleanup_context.owner == owner
    assert cleanup_context.deadline > original.deadline
    assert cleanup_context.deadline - observed in 1..1000
    send(release, :release)
    assert_receive {:result, {:error, %Custody.Error{reason: :deadline_exceeded}}}, 2000
    assert_receive {:DOWN, ^down, :process, _, _}, 1000
    refute_receive {:release_attempt, _, _, _}, 20
    finish(owner, owner_down, parent)
  end

  test "runner death after acknowledged commitment also attempts confirmed cleanup" do
    {owner, owner_down, parent} = begin_derive(:commit_loss, 5000)
    assert_receive {:committed, ref, runner, _}, 2000
    down = Process.monitor(holder(ref))
    Process.exit(runner, :kill)
    assert_receive {:release_attempt, release, _, _}, 1000
    send(release, :release)
    assert_receive {:result, {:error, %Custody.Error{reason: :custodian_failure}}}, 1000
    assert_receive {:DOWN, ^down, :process, _, _}, 1000
    finish(owner, owner_down, parent)
  end

  test "unconfirmed destruction returns a redacted idempotent cleanup capability for error and raise" do
    for failure <- [:refuse, :raise] do
      {owner, owner_down, parent} = begin_derive(:commit_loss, 500)
      assert_receive {:committed, ref, _, _}, 2000
      down = Process.monitor(holder(ref))
      assert_receive {:release_attempt, release, _, _}, 2000
      send(release, failure)
      assert_receive {:result, {:cleanup_required, %Cleanup{} = cleanup, %Custody.Error{reason: :deadline_exceeded}}}, 2000
      assert inspect(cleanup) == "#RequestSeal.Custody.Cleanup<>"
      assert Process.alive?(holder(ref))
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.sign(cleanup, "denied")
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.public_key(cleanup)
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.identity(cleanup)
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.release(cleanup)
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.derive(cleanup, "ed25519", "d", timeout: 5000)
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.wrap(cleanup, <<0::128>>)
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.unwrap(cleanup, [{<<>>, %{}, 128}])
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.verify(cleanup, "d", <<0>>)

      for opts <- [[], [timeout: 0], [timeout: :infinity], [timeout: 300_001], [timeout: 1, timeout: 2], [timeout: 1, curve: "P-256"]] do
        assert {:error, %Custody.Error{reason: :invalid_options}} = Custody.cleanup(cleanup, opts)
      end
      assert {:error, %Custody.Error{reason: :invalid_handle}} = Custody.cleanup(parent, timeout: 1000)

      for _ <- 1..2 do
        task = Task.async(fn -> Custody.cleanup(cleanup, timeout: 1000) end)
        assert_receive {:release_attempt, release, _, _}, 1000
        send(release, :release)
        assert Task.await(task, 2000) == :ok
      end
      assert_receive {:DOWN, ^down, :process, _, _}, 1000
      finish(owner, owner_down, parent)
    end
  end

  test "native suspension makes cleanup time out without treating it as destruction" do
    {owner, owner_down, parent} = begin_derive(:commit_loss, 500)
    assert_receive {:committed, ref, _, original}, 2000
    child = holder(ref)
    down = Process.monitor(child)
    :erlang.suspend_process(child)
    try do
      assert_receive {:release_attempt, release, cleanup_context, observed}, 2000
      assert cleanup_context.deadline > original.deadline
      assert cleanup_context.deadline - observed in 1..1000
      send(release, :release)
      assert_receive {:result, {:cleanup_required, cleanup, %Custody.Error{reason: :deadline_exceeded}}}, 2500
      assert Process.alive?(child)
      refute_receive {:DOWN, ^down, :process, ^child, _}, 0
      assert inspect(cleanup) == "#RequestSeal.Custody.Cleanup<>"
      send(self(), {:cleanup_to_retry, cleanup})
    after
      :erlang.resume_process(child)
    end
    assert_receive {:cleanup_to_retry, cleanup}
    task = Task.async(fn -> Custody.cleanup(cleanup, timeout: 1000) end)
    assert_receive {:release_attempt, release, _, _}, 1000
    send(release, :release)
    assert Task.await(task, 2000) == :ok
    assert_receive {:DOWN, ^down, :process, ^child, _}, 1000
    finish(owner, owner_down, parent)
  end

  test "successful acknowledged commit returns a usable handle owned by the original caller" do
    {owner, owner_down, parent} = begin_derive(:commit_loss, 5000)
    assert_receive {:committed, ref, runner, _}, 2000
    send(runner, :continue)
    assert_receive {:result, {:ok, child}}, 2000
    assert {:ok, _signature} = Custody.sign(child, "usable child")
    assert child.ref == ref
    down = Process.monitor(holder(ref))
    finish(owner, owner_down, parent)
    assert_receive {:DOWN, ^down, :process, _, _}, 1000
  end

  defp begin_derive(mode, timeout) do
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, <<8::256>>})
    controller = self()
    original = parent.ref
    wrapped = %{parent | custodian: Controlled, ref: fn -> {original, controller, mode} end}
    {owner, down} = spawn_monitor(fn ->
      result = Custody.derive(wrapped, "ed25519", "domain", timeout: timeout)
      send(controller, {:result, result})
      receive do
        :stop -> :ok
      end
    end)
    on_exit(fn ->
      monitor = Process.monitor(owner)
      Process.exit(owner, :kill)
      receive do
        {:DOWN, ^monitor, :process, ^owner, _} -> :ok
      end
    end)
    {owner, down, parent}
  end

  defp holder(ref) do
    {local, _, _} = ref.()
    {pid, _} = local.()
    pid
  end

  defp finish(owner, down, parent) do
    send(owner, :stop)
    assert_receive {:DOWN, ^down, :process, ^owner, :normal}, 1000
    assert :ok = Custody.release(parent)
  end
end
