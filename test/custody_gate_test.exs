defmodule RequestSeal.CustodyGateTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Crypto, Custody, Message, SignatureBase}
  alias RequestSeal.Custody.{Context, Gate, Local}
  alias RequestSeal.Replay.ETS

  @now 1_700_000_000
  @components ~s[("@method" "@path")]
  @input ~s[("@method" "@path");created=1700000000;expires=1700000030;nonce="one";tag="release";keyid="local"]

  defmodule PendingWrite do
    @moduledoc false
    @behaviour RequestSeal.Replay

    @impl true
    def claim({store, observer, :before}, claim, context) do
      pause(observer)
      ETS.claim(store, claim, context)
    end

    def claim({store, observer, :after}, claim, context) do
      result = ETS.claim(store, claim, context)
      pause(observer)
      result
    end

    @impl true
    def sweep({store, _, _}, now, context), do: ETS.sweep(store, now, context)

    defp pause(observer) do
      send(observer, {:claim_pending, self()})

      receive do
        :continue -> :ok
      end
    end
  end

  setup do
    {:ok, store} = ETS.start_link(max_entries: 10)
    {:ok, message} = Message.request("GET", "https://example.test/items", [], "")
    {:ok, commitment} = Gate.commitment(message, @components)
    {:ok, base} = SignatureBase.build(message, @input)

    admission = %Gate.Admission{
      decision: "decision-1",
      commitment: commitment,
      nonce: "one",
      not_after: @now + 30
    }

    config = %{
      port: fn _, _ -> {:allow, admission} end,
      once: {:store, ETS.store(store), "release-keys"},
      required_components: [~s["@method"], ~s["@path"]],
      max_lifetime: 30,
      clock: fn -> @now end,
      skew: 0,
      tag: "release",
      keyid: "local"
    }

    %{store: store, base: base, message: message, config: config, admission: admission}
  end

  test "cryptography runs after single-use admission and reports digests before release", ctx do
    owner = self()

    config =
      Map.put(ctx.config, :record, fn event, _ ->
        send(owner, {:signed, event})
        :ok
      end)

    {:ok, handle} = gated(config)
    {:ok, public} = Custody.public_key(handle)

    results =
      1..4
      |> Task.async_stream(fn _ -> sign(handle, ctx.base) end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert [{:ok, signature}] = Enum.filter(results, &match?({:ok, _}, &1))
    assert Enum.count(results, &match?({:error, %{reason: :gate_spent}}, &1)) == 3
    assert :ok = Crypto.verify("ed25519", ctx.base, signature, public)

    assert_receive {:signed, %Gate.Signed{} = record}
    assert record.base_sha256 == :crypto.hash(:sha256, ctx.base)
    assert record.signature_sha256 == :crypto.hash(:sha256, signature)
    refute inspect(record) =~ "decision-1"
  end

  test "malformed bases, wrong coverage, nonce, tag and key ID refuse before the port", ctx do
    owner = self()

    {:ok, handle} =
      gated(%{ctx.config | port: fn _, _ -> send(owner, :port_called) end})

    assert_error(sign(handle, "invalid"), :gate_malformed_base)

    for input <- [
          String.replace(@input, ~s[ "@path"], ""),
          String.replace(@input, ~s[;nonce="one"], ""),
          String.replace(@input, ~s[tag="release"], ~s[tag="other"]),
          String.replace(@input, ~s[keyid="local"], ~s[keyid="other"])
        ] do
      {:ok, base} = SignatureBase.build(ctx.message, input)
      assert_error(sign(handle, base), :gate_coverage)
    end

    refute_received :port_called
  end

  test "invalid wire types leave the port, replay store and recorder untouched", ctx do
    owner = self()
    admission = ctx.admission

    config =
      ctx.config
      |> Map.put(:port, fn _, _ ->
        send(owner, :port_called)
        {:allow, admission}
      end)
      |> Map.put(:record, fn _, _ ->
        send(owner, :record_called)
        :ok
      end)

    {:ok, handle} = gated(config)

    for {from, to} <- [
          {~s[tag="release"], "tag=release"},
          {~s[nonce="one"], "nonce=one"},
          {~s[keyid="local"], "keyid=local"},
          {"created=1700000000", ~s[created="1700000000"]}
        ] do
      malformed = String.replace(ctx.base, from, to)
      assert {:error, %{reason: :malformed}} = SignatureBase.parse(malformed)
      assert_error(sign(handle, malformed), :gate_malformed_base)
    end

    refute_received :port_called
    refute_received :record_called
    assert {:ok, 0} = ETS.sweep(ctx.store, @now + 31)

    assert {:ok, _} = sign(handle, ctx.base)
    assert_received :port_called
    assert_received :record_called
  end

  test "an unassigned gated key refuses raw use and verifies only valid HTTP bases", ctx do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = Gate.new("ed25519", {:ed25519, seed}, ctx.config)
    assert_error(Custody.sign(handle, ctx.base), :unsupported_operation)
    assert {:ok, signature} = Custody.sign(handle, ctx.base, operation: :http)
    assert_error(Custody.verify(handle, ctx.base, signature), :unsupported_operation)
    assert :ok = Custody.verify(handle, ctx.base, signature, operation: :http)

    malformed = "not an HTTP signature base"
    assert {:ok, invalid_signature} = Crypto.sign("ed25519", malformed, {:ed25519, seed})
    assert {:ok, public} = Custody.public_key(handle)
    assert :ok = Crypto.verify("ed25519", malformed, invalid_signature, public)
    assert_error(
      Custody.verify(handle, malformed, invalid_signature, operation: :http),
      :invalid_data
    )
  end

  test "derived values are checked before signing, verification, or admission", ctx do
    observer = self()
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, assigned} = Local.new("ed25519", {:ed25519, seed}, issued_for: :release)
    {:ok, gated} = gated(%{ctx.config | port: fn _, _ -> send(observer, :admitted) end})
    opts = [issued_for: :release, operation: :http]

    for {from, to} <- [
          {~s["@method": GET], ~s["@method": GET ]},
          {~s["@path": /items], ~s["@path": /items?query]}
        ] do
      invalid = String.replace(ctx.base, from, to)
      assert {:error, %{reason: :malformed}} = SignatureBase.parse(invalid)
      assert {:ok, signature} = Crypto.sign("ed25519", invalid, {:ed25519, seed})
      assert_error(Custody.sign(assigned, invalid, opts), :invalid_data)
      assert_error(Custody.verify(assigned, invalid, signature, opts), :invalid_data)
      assert_error(Custody.sign(gated, invalid, opts), :gate_malformed_base)
    end

    refute_received :admitted
    assert {:ok, 0} = ETS.sweep(ctx.store, @now + 31)
  end

  test "impossible component and modifier forms fail before custody or admission", ctx do
    observer = self()
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, assigned} = Local.new("ed25519", {:ed25519, seed}, issued_for: :release)
    {:ok, gated} = gated(%{ctx.config | port: fn _, _ -> send(observer, :admitted) end})
    opts = [issued_for: :release, operation: :http]

    for {identifier, value} <- [
          {~s["@status";req], "204"},
          {~s["@status"], "204"},
          {~s["@path";tr], "/items"},
          {~s["@request-target"], "/another-path"},
          {~s["@target-uri"], "https://example.test/another-path"},
          {~s["@request-target"], "*"},
          {~s["@query-param"], "value"},
          {~s["@query-param";name="q"], "a%2fb"},
          {~s["@query-param";name="q"], String.duplicate("a", 16_384)},
          {~s["x-test";bs], "word"},
          {~s["x-test";bs], ":YQ==:,:Yg==:"},
          {~s["x-test";bs], ":IA==:"},
          {~s["x-test";bs;sf], ":YQ==:"},
          {~s["x-test";sf], "a,b"},
          {~s["x-test";key="BAD"], "1"},
          {~s["x-test";key="a"], "1, 2"},
          {~s["x-test";tr=?0], "value"},
          {~s["x-test"], " value"},
          {~s["x-test"], String.duplicate("a", 65_537)}
        ] do
      invalid =
        ~s["@method": GET\n"@path": /items\n#{identifier}: #{value}\n] <>
          ~s["@signature-params": ("@method" "@path" #{identifier});created=1700000000] <>
          ~s[;expires=1700000030;nonce="one";tag="release";keyid="local"]

      assert {:error, %{reason: :malformed}} = SignatureBase.parse(invalid)
      assert {:ok, signature} = Crypto.sign("ed25519", invalid, {:ed25519, seed})
      assert_error(Custody.sign(assigned, invalid, opts), :invalid_data)
      assert_error(Custody.verify(assigned, invalid, signature, opts), :invalid_data)
      assert_error(Custody.sign(gated, invalid, opts), :gate_malformed_base)
    end

    refute_received :admitted
  end

  test "port refusals, invalid replies, mismatches and time bounds are closed", ctx do
    for {response, reason} <- [
          {:deny, :gate_denied},
          {{:allow, %{ctx.admission | decision: ""}}, :gate_unavailable},
          {{:allow, %{ctx.admission | commitment: <<0::256>>}}, :gate_mismatch},
          {{:allow, %{ctx.admission | nonce: "two"}}, :gate_mismatch},
          {{:allow, %{ctx.admission | not_after: @now + 29}}, :gate_window}
        ] do
      {:ok, handle} = gated(%{ctx.config | port: fn _, _ -> response end})
      assert_error(sign(handle, ctx.base), reason)
      assert :ok = Local.release(handle)
    end

    {:ok, faulted} = gated(%{ctx.config | port: fn _, _ -> raise "unexpected" end})
    assert_error(sign(faulted, ctx.base), :gate_unavailable)

    {:ok, expired} = gated(%{ctx.config | clock: fn -> @now + 30 end})
    assert_error(sign(expired, ctx.base), :gate_window)

    {:ok, wrong_clock} = gated(%{ctx.config | clock: fn -> :bad end})
    assert_error(sign(wrong_clock, ctx.base), :gate_window)
  end

  test "record failure keeps the claim spent and store failures refuse signing", ctx do
    {:ok, handle} = gated(Map.put(ctx.config, :record, fn _, _ -> :error end))
    assert_error(sign(handle, ctx.base), :gate_unrecorded)
    assert_error(sign(handle, ctx.base), :gate_spent)

    GenServer.stop(ctx.store)
    assert_error(sign(handle, ctx.base), :gate_store_failed)
  end

  test "caller death cancels a pending spend and preserves a committed spend", ctx do
    observer = self()

    for {phase, spent} <- [{:before, 0}, {:after, 1}] do
      {:ok, store} = ETS.start_link(max_entries: 10)
      delayed = %{ETS.store(store) | adapter: PendingWrite, ref: {store, observer, phase}}
      {:ok, handle} = gated(%{ctx.config | once: {:store, delayed, "release-keys"}})

      caller = Task.async(fn -> sign(handle, ctx.base) end)
      assert_receive {:claim_pending, worker}, 1_000
      monitor = Process.monitor(worker)
      Task.shutdown(caller, :brutal_kill)

      assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
      assert {:ok, _} = Custody.public_key(handle)
      assert {:ok, ^spent} = ETS.sweep(store, @now + 31)
      assert :ok = Local.release(handle)
      assert :ok = GenServer.stop(store)
    end
  end

  test "creator death cancels admission on a transferred handle", ctx do
    observer = self()

    config = %{
      ctx.config
      | port: fn _, _ ->
          send(observer, {:pending_admission, self()})

          receive do
            :allow -> {:allow, ctx.admission}
          end
        end
    }

    creator =
      Task.async(fn ->
        {:ok, handle} = gated(config)
        send(observer, {:transferred, handle})

        receive do
          :finish -> :ok
        end
      end)

    assert_receive {:transferred, handle}, 1_000
    caller = Task.async(fn -> sign(handle, ctx.base) end)
    assert_receive {:pending_admission, worker}, 1_000
    monitor = Process.monitor(worker)
    assert Process.alive?(caller.pid)
    Task.shutdown(creator, :brutal_kill)

    assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
    assert_error(Task.await(caller, 1_000), :key_not_found)
    assert {:ok, 0} = ETS.sweep(ctx.store, @now + 31)
  end

  test "externally checked admission returns the exact base digest and spends atomically", ctx do
    config = Map.put(ctx.config, :algorithm, "ed25519")
    context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
    assert {:ok, admitted} = Gate.check(ctx.base, config, context)
    assert admitted.base_sha256 == :crypto.hash(:sha256, ctx.base)
    assert admitted.not_after == @now + 30
    assert_error(Gate.check(ctx.base, config, context), :gate_spent)

    expired = %{context | deadline: System.monotonic_time(:millisecond) - 1}
    assert_error(Gate.check(ctx.base, config, expired), :deadline_exceeded)
    assert_error(Gate.check(ctx.base, ctx.config, context), :invalid_options)
  end

  test "rejects invalid options and operation families", ctx do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)

    for invalid <- [
          %{ctx.config | skew: -1},
          %{ctx.config | once: {:store, nil, ""}},
          %{ctx.config | required_components: [~s["@path"], ~s["@path"]]},
          Map.put(ctx.config, :extra, :unsupported)
        ] do
      assert_error(Gate.new("ed25519", {:ed25519, seed}, invalid), :invalid_options)
    end

    assert_error(
      Gate.new({:jws, "EdDSA"}, {:ed25519, seed}, ctx.config),
      :unsupported_algorithm
    )
  end

  defp sign(handle, bytes),
    do: Custody.sign(handle, bytes, operation: :http, issued_for: :release)

  defp gated(config) do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    Gate.new("ed25519", {:ed25519, seed}, config, issued_for: :release)
  end

  defp assert_error(result, reason) do
    assert {:error, %Custody.Error{reason: ^reason}} = result
  end
end
