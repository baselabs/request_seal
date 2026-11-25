defmodule RequestSeal.CustodyGateTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Crypto, Custody, Message, SignatureBase}
  alias RequestSeal.Custody.{Context, Gate, Local}
  alias RequestSeal.Replay.ETS

  @now 1_700_000_000
  @components ~s[("@method" "@path")]
  @input ~s[("@method" "@path");created=1700000000;expires=1700000030;nonce="one";tag="release";keyid="local"]

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
      |> Task.async_stream(fn _ -> Custody.sign(handle, ctx.base, issued_for: :release) end)
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

    assert_error(Custody.sign(handle, "invalid"), :gate_malformed_base)

    for input <- [
          String.replace(@input, ~s[ "@path"], ""),
          String.replace(@input, ~s[;nonce="one"], ""),
          String.replace(@input, ~s[tag="release"], ~s[tag="other"]),
          String.replace(@input, ~s[keyid="local"], ~s[keyid="other"])
        ] do
      {:ok, base} = SignatureBase.build(ctx.message, input)
      assert_error(Custody.sign(handle, base), :gate_coverage)
    end

    refute_received :port_called
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
      assert_error(Custody.sign(handle, ctx.base), reason)
      assert :ok = Local.release(handle)
    end

    {:ok, faulted} = gated(%{ctx.config | port: fn _, _ -> raise "unexpected" end})
    assert_error(Custody.sign(faulted, ctx.base), :gate_unavailable)

    {:ok, expired} = gated(%{ctx.config | clock: fn -> @now + 30 end})
    assert_error(Custody.sign(expired, ctx.base), :gate_window)

    {:ok, wrong_clock} = gated(%{ctx.config | clock: fn -> :bad end})
    assert_error(Custody.sign(wrong_clock, ctx.base), :gate_window)
  end

  test "record failure keeps the claim spent and store failures refuse signing", ctx do
    {:ok, handle} = gated(Map.put(ctx.config, :record, fn _, _ -> :error end))
    assert_error(Custody.sign(handle, ctx.base), :gate_unrecorded)
    assert_error(Custody.sign(handle, ctx.base), :gate_spent)

    GenServer.stop(ctx.store)
    assert_error(Custody.sign(handle, ctx.base), :gate_store_failed)
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

  defp gated(config) do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    Gate.new("ed25519", {:ed25519, seed}, config, issued_for: :release)
  end

  defp assert_error(result, reason) do
    assert {:error, %Custody.Error{reason: ^reason}} = result
  end
end
