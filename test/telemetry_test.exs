defmodule RequestSeal.TelemetryTest do
  @moduledoc false
  use ExUnit.Case, async: false
  import RequestSeal.MultiSignatureSupport
  alias RequestSeal.Replay.ETS

  @events RequestSeal.Telemetry.events()

  setup do
    handler = fn event, measurements, metadata, _config ->
      send(self(), {:telemetry, event, measurements, metadata})
    end

    :telemetry.attach_many("telemetry-contract-test", @events, handler, nil)

    on_exit(fn -> :telemetry.detach("telemetry-contract-test") end)
  end

  test "the v1 event list is exactly the documented five events" do
    assert @events == [
             [:request_seal, :verify, :stop],
             [:request_seal, :verify_quorum, :stop],
             [:request_seal, :web_bot_auth, :verify, :stop],
             [:request_seal, :replay, :claim],
             [:request_seal, :custody, :sign, :stop]
           ]
  end

  test "verify/3 emits one stop event with bounded outcome metadata" do
    m = signed(["sig-b21"])
    assert {:ok, _} = RequestSeal.verify(m, policy(), label: "sig-b21")

    assert_received {:telemetry, [:request_seal, :verify, :stop], measurements, metadata}
    assert %{outcome: :ok, reason: nil, layer: nil, detail: nil} = metadata
    assert %{duration: duration} = measurements
    assert is_integer(duration) and duration >= 0

    assert {:error, _} = RequestSeal.verify(m, policy(), label: "absent")

    assert_received {:telemetry, [:request_seal, :verify, :stop], _, error_metadata}
    assert %{outcome: :error, reason: :unknown_label, layer: :fields} = error_metadata
  end

  test "verify/3 metadata never carries labels, key IDs, or secrets" do
    m = signed(["sig-b21"])

    for _ <- 1..3, do: RequestSeal.verify(m, policy(), label: "sig-b21")

    assert_received {:telemetry, [:request_seal, :verify, :stop], _, metadata}

    for canary <- ["sig-b21", "test-shared-secret", "test-key"] do
      refute inspect(metadata) =~ canary
      refute inspect(@events) =~ canary
    end
  end

  test "verify_quorum/3 emits its stop event, including deadline exhaustion" do
    m = signed(["sig-b21"])
    q = quorum([slot(:valid, label: "sig-b21")], mode: :any)
    assert {:ok, _} = RequestSeal.verify_quorum(m, q, [])

    assert_received {:telemetry, [:request_seal, :verify_quorum, :stop], _, metadata}
    assert %{outcome: :ok} = metadata

    assert {:error, _} =
             RequestSeal.verify_quorum(
               m,
               quorum(
                 [
                   slot(:valid,
                     label: "sig-b21",
                     principal: "shared",
                     role: :valid,
                     required: false
                   )
                 ],
                 mode: :any,
                 unit: {:role, shared_principal: false}
               ),
               deadline: System.monotonic_time(:millisecond) - 1
             )

    assert_received {:telemetry, [:request_seal, :verify_quorum, :stop], _, deadline_metadata}
    assert %{outcome: :error, reason: :deadline, layer: :quorum} = deadline_metadata
  end

  test "web bot auth verification emits its stop event" do
    assert {:error, _} = RequestSeal.WebBotAuth.verify(unsigned(), :not_a_policy)

    assert_received {:telemetry, [:request_seal, :web_bot_auth, :verify, :stop], _, metadata}
    assert %{outcome: :error, reason: :invalid_policy, layer: :input} = metadata
  end

  test "the shared replay commit emits claim outcomes" do
    pid = start_supervised!({ETS, max_entries: 16})

    p =
      policy(
        freshness: %{clock: fn -> 1_618_884_473 end, max_age: 60, skew: 0, require_expires: false},
        replay: %{
          identifier: :nonce,
          namespace: "telemetry-claims",
          commitment: fn facts -> {:ok, facts.identifier} end,
          store: ETS.store(pid),
          timeout: 1000
        }
      )

    m = signed(["sig-b21"])

    assert {:ok, _} = RequestSeal.verify(m, p, label: "sig-b21")
    assert_received {:telemetry, [:request_seal, :replay, :claim], _, %{outcome: :claimed} = meta}
    assert meta.reason == nil

    assert {:error, _} = RequestSeal.verify(m, p, label: "sig-b21")

    assert_received {:telemetry, [:request_seal, :replay, :claim], _,
                     %{outcome: :already_claimed, reason: :replayed}}
  end

  test "the shared custody signing path emits its stop event" do
    {public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
    {:ok, _key} = RequestSeal.PublicKey.import({:ed25519, public}, :raw)

    spec = %{
      label: "sig",
      algorithm: "ed25519",
      components: ~s[("@method" "@path")],
      expires_in: 60
    }

    {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)

    assert {:ok, signed} = RequestSeal.sign(message, spec, handle, clock: fn -> 1_700_000_000 end)
    assert is_map(signed)

    assert_received {:telemetry, [:request_seal, :custody, :sign, :stop], _,
                     %{outcome: :ok} = meta}

    assert meta.reason == nil

    :ok = RequestSeal.Custody.Local.release(handle)

    assert {:error, _} = RequestSeal.sign(message, spec, handle, clock: fn -> 1_700_000_000 end)

    assert_received {:telemetry, [:request_seal, :custody, :sign, :stop], _,
                     %{outcome: :error, reason: :key_not_found}}
  end
end
