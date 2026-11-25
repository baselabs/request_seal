defmodule RequestSeal.QuorumTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody, Message, Policy, Quorum, Replay}
  alias RequestSeal.Custody.Local

  @now 1_760_000_000
  @components ~s[("@method" "@target-uri")]
  @operation {:operation, [~s["@method"], ~s["@target-uri"]]}

  setup do
    keys =
      for name <- ["primary", "optional", "third"], into: %{} do
        {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = Local.new("ed25519", {:ed25519, seed})
        {:ok, public} = Custody.public_key(handle)
        on_exit(fn -> Local.release(handle) end)
        {name, {handle, public}}
      end

    {:ok, message} = Message.request("GET", "https://example.test/operation", [], nil)
    pid = start_supervised!({Replay.ETS, max_entries: 4})
    %{keys: keys, message: message, store: Replay.ETS.store(pid), pid: pid}
  end

  test "relabeling or deleting any optional signature does not open a new claim", ctx do
    required = sign(ctx.message, ctx.keys, "primary", "main", "session")
    both = sign(required, ctx.keys, "optional", "extra", "other")
    relabeled = sign(ctx.message, ctx.keys, "primary", "renamed", "new")

    quorum =
      quorum(ctx, @operation, [
        slot(ctx, :main, "primary", true),
        slot(ctx, :optional, "optional", false)
      ])

    assert {:ok, %{count: 2, authorization: :not_evaluated, replay: %Replay.Receipt{}}} =
             RequestSeal.verify_quorum(both, quorum, [])

    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(required, quorum, [])
    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(relabeled, quorum, [])
    assert {:ok, 1} = Replay.ETS.sweep(ctx.pid, @now + 120)
  end

  test "an unassigned qualifying nonce disagreement never claims", ctx do
    first = sign(ctx.message, ctx.keys, "primary", "main", "first")
    both = sign(first, ctx.keys, "optional", "extra", "second")

    quorum =
      quorum(ctx, {:nonce, :shared}, [
        slot(ctx, :main, "primary", true),
        slot(ctx, :optional, "optional", false)
      ])

    assert {:error, %{reason: :replay_identity_mismatch, layer: :replay}} =
             RequestSeal.verify_quorum(both, quorum, [])

    assert {:ok, %{count: 1}} = RequestSeal.verify_quorum(first, quorum, [])
    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(first, quorum, [])
  end

  test "aliases cannot count twice and a rejected threshold leaves the replay store empty", ctx do
    first = sign(ctx.message, ctx.keys, "primary", "one", "session")
    aliases = sign(first, ctx.keys, "primary", "two", "session")
    valid = sign(first, ctx.keys, "optional", "two", "session")

    slots = [
      slot(ctx, :one, nil, true),
      slot(ctx, :two, nil, true)
    ]

    quorum = quorum(ctx, @operation, slots, {:threshold, 2})

    assert {:error, %{reason: :quorum_not_met, layer: :quorum}} =
             RequestSeal.verify_quorum(aliases, quorum, [])

    assert {:ok, %{count: 2}} = RequestSeal.verify_quorum(valid, quorum, [])
  end

  test "bindings pass before a claim and enforce the selected authenticated parameter", ctx do
    first = sign(ctx.message, ctx.keys, "primary", "one", "first")
    mismatch = sign(first, ctx.keys, "optional", "two", "second")
    match = sign(first, ctx.keys, "optional", "two", "first")
    slots = [slot(ctx, :one, "primary", true), slot(ctx, :two, "optional", true)]
    quorum = quorum(ctx, @operation, slots)
    quorum = %{quorum | bindings: [{:same_parameter, "nonce", [:one, :two]}]}

    assert {:error, %{reason: :binding_unsatisfied}} =
             RequestSeal.verify_quorum(mismatch, quorum, [])

    assert {:ok, _} = RequestSeal.verify_quorum(match, quorum, [])
  end

  test "policy requires one composite claim, mandatory coverage, and a live deadline", ctx do
    slot = slot(ctx, :main, "primary", true)
    valid = quorum(ctx, @operation, [slot])

    assert {:error, %{reason: :invalid_quorum}} =
             Quorum.new(Map.from_struct(%{valid | replay: :not_required}))

    invalid = put_in(valid.replay.identifier, {:operation, [~s["@authority"]]})
    assert {:error, %{reason: :invalid_quorum}} = Quorum.new(Map.from_struct(invalid))

    signed = sign(ctx.message, ctx.keys, "primary", "main", "session")
    deadline = System.monotonic_time(:millisecond)

    assert {:error, %{reason: :deadline}} =
             RequestSeal.verify_quorum(signed, valid, deadline: deadline)

    assert {:ok, _} = RequestSeal.verify_quorum(signed, valid, [])
  end

  test "fixed retention refuses a signature with a longer window before claiming", ctx do
    signed = sign(ctx.message, ctx.keys, "primary", "main", "session")
    policy = quorum(ctx, @operation, [slot(ctx, :main, "primary", true)])
    too_short = put_in(policy.replay.retain_until, @now + 59)

    assert {:error, %{reason: :retention_exceeded}} =
             RequestSeal.verify_quorum(signed, too_short, [])

    assert {:ok, _} = RequestSeal.verify_quorum(signed, policy, [])
  end

  test "principal scope comes from all configured slots and role counts obey principal sharing",
       ctx do
    request = sign(ctx.message, ctx.keys, "primary", "one", "attempt")
    both = sign(request, ctx.keys, "optional", "two", "attempt")

    slots = [
      slot(ctx, :first, "primary", true) |> Map.merge(%{principal: "same", role: :writer}),
      slot(ctx, :second, "optional", true) |> Map.merge(%{principal: "same", role: :reviewer})
    ]

    policy = quorum(ctx, {:nonce, :shared}, slots)
    policy = %{policy | unit: {:role, shared_principal: false}}
    policy = put_in(policy.replay.scope, :principals)

    assert {:error, %{reason: :quorum_not_met}} = RequestSeal.verify_quorum(both, policy, [])

    shared = %{policy | unit: {:role, shared_principal: true}}
    assert {:ok, %{count: 2}} = RequestSeal.verify_quorum(both, shared, [])
    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(both, shared, [])
  end

  test "signature negotiation checks the covered challenge before claiming", ctx do
    label = "main"
    signed = sign(ctx.message, ctx.keys, "primary", label, "session")
    policy = quorum(ctx, @operation, [slot(ctx, :main, "primary", true)])

    {:ok, requests} =
      RequestSeal.AcceptSignature.parse("main=" <> @components <> ~s(;nonce="bad"),
        target: :request
      )

    assert {:error, %{reason: :negotiation_unfulfilled, layer: :negotiation}} =
             RequestSeal.verify_quorum(signed, policy, accept_signature: requests)

    {:ok, requests} =
      RequestSeal.AcceptSignature.parse("main=" <> @components <> ~s(;nonce="session"),
        target: :request
      )

    assert {:ok, %{negotiation: :fulfilled}} =
             RequestSeal.verify_quorum(signed, policy, accept_signature: requests)
  end

  test "unexpected and invalid labels follow their explicit policies", ctx do
    slot = Map.put(slot(ctx, :main, "primary", true), :label, "one")
    policy = quorum(ctx, @operation, [slot])
    policy = %{policy | unexpected: :reject, invalid: :reject}
    unexpected = sign(ctx.message, ctx.keys, "optional", "two", "session")
    invalid = sign(ctx.message, ctx.keys, "optional", "one", "session")

    assert {:error, %{reason: :unexpected_signature}} =
             RequestSeal.verify_quorum(unexpected, policy, [])

    assert {:error, %{reason: :nonqualifying_signature}} =
             RequestSeal.verify_quorum(invalid, policy, [])

    valid = sign(ctx.message, ctx.keys, "primary", "one", "session")
    assert {:ok, _} = RequestSeal.verify_quorum(valid, policy, [])
  end

  test "bounded assignment refuses an impossible dense policy without claiming", ctx do
    ids = [:one, :two, :three, :four, :five, :six, :seven, :eight, :nine, :ten]
    signer_ids = Enum.map(Enum.take(ids, 9), &Atom.to_string/1)

    {keys, signed} =
      Enum.reduce(signer_ids, {%{}, ctx.message}, fn id, {keys, signed} ->
        {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, signer} = Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = Custody.public_key(signer)
        on_exit(fn -> Local.release(signer) end)
        keys = Map.put(keys, id, {signer, key})
        {keys, sign(signed, keys, id, id, "session")}
      end)

    ctx = %{ctx | keys: keys}
    slots = Enum.map(ids, &slot(ctx, &1, nil, true))
    policy = quorum(ctx, @operation, slots, {:threshold, 10})

    assert {:error, %{reason: :limit, layer: :input}} =
             RequestSeal.verify_quorum(signed, policy, [])

    accepting = %{policy | slots: Enum.take(slots, 1), mode: :all}
    assert {:ok, %{count: 1}} = RequestSeal.verify_quorum(signed, accepting, [])
  end

  test "unknown HMAC equivalence cannot fill a required key slot", ctx do
    {:ok, signer} = Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)})
    on_exit(fn -> Local.release(signer) end)

    {:ok, signed} =
      RequestSeal.sign(
        ctx.message,
        %{
          label: "hmac",
          components: @components,
          algorithm: "hmac-sha256",
          expires_in: 60
        },
        signer, clock: fn -> @now end)

    slot = slot(ctx, :main, "primary", true)

    policy = %{
      slot.policy
      | algorithms: ["hmac-sha256"],
        key_resolver: fn _ -> {:ok, %{algorithm: "hmac-sha256", key: signer}} end
    }

    quorum = quorum(ctx, @operation, [%{slot | policy: policy}])

    assert {:error, %{reason: :ambiguous_key_identity, layer: :quorum}} =
             RequestSeal.verify_quorum(signed, quorum, [])
  end

  defp sign(message, keys, keyid, label, nonce) do
    {handle, _} = Map.fetch!(keys, keyid)

    {:ok, signed} =
      RequestSeal.sign(
        message,
        %{
          label: label,
          algorithm: "ed25519",
          signature_input:
            @components <>
              ~s(;created=#{@now};expires=#{@now + 60};nonce="#{nonce}";keyid="#{keyid}")
        },
        handle
      )

    signed
  end

  defp slot(ctx, id, keyid, required) do
    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: @components,
        key_resolver: fn facts ->
          with true <- keyid == nil or facts.keyid == keyid,
               {:ok, {_, key}} <- Map.fetch(ctx.keys, facts.keyid) do
            {:ok, %{algorithm: "ed25519", key: key}}
          else
            _ -> :error
          end
        end,
        freshness: %{clock: fn -> @now end, require_expires: true, max_age: 120, skew: 0},
        content: :not_required,
        replay: :not_required
      })

    %{id: id, policy: policy, required: required}
  end

  defp quorum(ctx, identifier, slots, mode \\ :all) do
    {:ok, quorum} =
      Quorum.new(%{
        mode: mode,
        unit: :key,
        slots: slots,
        unexpected: :ignore,
        invalid: :ignore,
        replay: %{
          identifier: identifier,
          scope: :namespace,
          namespace: "operation",
          store: ctx.store,
          timeout: 1000,
          retain_until: @now + 120
        }
      })

    quorum
  end
end
