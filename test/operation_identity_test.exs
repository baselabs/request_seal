defmodule RequestSeal.OperationIdentityTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody.Local, Idempotency, Journal, Message, Policy, Replay}

  @now 1_760_000_000
  @components ~s[("@method" "@target-uri" "content-digest" "idempotency-key")]

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, signer} = Local.new("ed25519", {:ed25519, seed})
    {:ok, key} = RequestSeal.Custody.public_key(signer)
    on_exit(fn -> Local.release(signer) end)
    %{signer: signer, key: key}
  end

  test "a new signed attempt recovers the response and a changed body conflicts", ctx do
    journal = start_supervised!({Journal, max_entries: 2})
    store = start_supervised!({Idempotency.ETS, max_entries: 2})
    replay = start_supervised!({Replay.ETS, max_entries: 8})
    opts = [namespace: "orders", principal: "account", now: @now, retention: 120]

    assert :recorded = Journal.record(journal, "orders", message("first"))
    assert :already_recorded = Journal.record(journal, "orders", message("first"))
    assert :conflict = Journal.record(journal, "orders", message("different"))

    assert {:ok, first} =
             Journal.reissue(journal, "orders", "create-1", spec("primary"), ctx.signer,
               clock: fn -> @now end
             )

    assert {:ok, retry} =
             Journal.reissue(journal, "orders", "create-1", spec("alias"), ctx.signer,
               clock: fn -> @now end
             )

    refute first.fields == retry.fields

    policy = policy(ctx.key, replay, :nonce)
    assert {:ok, record} = Idempotency.prepare(first, policy, "sig", opts)
    assert {:error, %{reason: :replayed}} = Idempotency.prepare(first, policy, "sig", opts)

    assert {:reserved, reservation} =
             Idempotency.reserve({Idempotency.ETS, store}, record, timeout: 1000)

    assert :in_progress = Idempotency.reserve({Idempotency.ETS, store}, record, timeout: 1000)

    response = %{
      status: 201,
      headers: [{"content-type", "text/plain"}, {"set-cookie", "secret"}],
      body: "created"
    }

    assert :stored =
             Idempotency.store({Idempotency.ETS, store}, reservation, response,
               timeout: 1000,
               allow_headers: ["content-type", "set-cookie"]
             )

    assert {:ok, same} = Idempotency.prepare(retry, policy, "sig", opts)
    assert same.fingerprint == record.fingerprint

    assert {:stored, %{body: "created", status: 201, headers: [{"content-type", "text/plain"}]}} =
             Idempotency.reserve({Idempotency.ETS, store}, same, timeout: 1000)

    assert {:ok, changed} =
             RequestSeal.sign(message("different"), spec("primary"), ctx.signer,
               clock: fn -> @now end
             )

    assert {:ok, conflict} = Idempotency.prepare(changed, policy, "sig", opts)
    assert :conflict = Idempotency.reserve({Idempotency.ETS, store}, conflict, timeout: 1000)

    assert {:reserved, _} =
             Idempotency.reserve({Idempotency.ETS, store}, %{same | principal: "another"},
               timeout: 1000
             )
  end

  test "operation commitment survives key rotation and fresh transport parameters", ctx do
    replay = start_supervised!({Replay.ETS, max_entries: 8})

    policy =
      policy(
        ctx.key,
        replay,
        {:operation,
         [~s["@method"], ~s["@target-uri"], ~s["content-digest"], ~s["idempotency-key"]]}
      )

    assert {:ok, first} =
             RequestSeal.sign(message("same"), spec("primary"), ctx.signer, clock: fn -> @now end)

    assert {:ok, _} = RequestSeal.verify(first, policy, label: "sig")

    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, rotated} = Local.new("ed25519", {:ed25519, seed})
    on_exit(fn -> Local.release(rotated) end)
    {:ok, key} = RequestSeal.Custody.public_key(rotated)
    second_policy = policy(key, replay, policy.replay.identifier)

    assert {:ok, second} =
             RequestSeal.sign(message("same"), spec("rotated"), rotated, clock: fn -> @now end)

    assert {:error, %{reason: :replayed}} =
             RequestSeal.verify(second, second_policy, label: "sig")
  end

  test "a replaced lease cannot complete and forbidden response shapes are refused" do
    pid = start_supervised!({Idempotency.ETS, max_entries: 1})
    store = Idempotency.ETS.store(pid)

    record = %Idempotency.Record{
      namespace: "orders",
      principal: "account",
      key: "request",
      fingerprint: <<0::256>>,
      now: @now,
      lease_until: @now + 5,
      retain_until: @now + 120
    }

    assert {:reserved, first} = Idempotency.reserve(store, record, timeout: 1000)
    renewed = %{record | now: @now + 5, lease_until: @now + 10}
    assert {:reserved, second} = Idempotency.reserve(store, renewed, timeout: 1000)
    opts = [timeout: 1000, allow_headers: []]

    assert {:error, %{reason: :invalid_response}} =
             Idempotency.store(store, second, %{status: 204, headers: [], body: "bad"}, opts)

    response = %{status: 202, headers: [], body: "accepted"}
    assert :not_reserved = Idempotency.store(store, first, response, opts)
    assert :stored = Idempotency.store(store, second, response, opts)
    assert :not_reserved = Idempotency.store(store, second, response, opts)
    assert {:ok, 0} = Idempotency.sweep(store, @now + 119, timeout: 1000)
    assert {:ok, 1} = Idempotency.sweep(store, @now + 120, timeout: 1000)
  end

  test "the journal rejects credential fields and caller nonce overrides", ctx do
    signed_intent = message("first")
    {:ok, entry} = Journal.entry("orders", signed_intent)

    assert {:error, :invalid_options} =
             Journal.reissue(entry, spec("primary"), ctx.signer, nonce: <<0::256>>)

    assert {:error, :invalid_intent} =
             Journal.reissue(%{entry | body: "different"}, spec("primary"), ctx.signer, [])

    adds_length = %{
      spec("primary")
      | components:
          ~s[("@method" "@target-uri" "content-digest" "idempotency-key" "content-length")]
    }

    assert {:error, :invalid_intent} = Journal.reissue(entry, adds_length, ctx.signer, [])

    {:ok, field} =
      RequestSeal.FieldOccurrence.new(%{
        name: "Authorization",
        value: "Bearer example",
        section: :headers
      })

    assert {:error, :invalid_intent} =
             Journal.entry("orders", %{signed_intent | fields: signed_intent.fields ++ [field]})
  end

  defp message(body) do
    {:ok, request} =
      Message.request(
        "POST",
        "https://api.example.test/orders",
        [{"idempotency-key", ~s["create-1"]}],
        body,
        digest: ["sha-256"]
      )

    request
  end

  defp spec(keyid),
    do: %{
      label: "sig",
      algorithm: "ed25519",
      components: @components,
      expires_in: 60,
      keyid: keyid
    }

  defp policy(key, replay, identifier) do
    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: @components,
        key_resolver: fn _ ->
          {:ok,
           %{algorithm: "ed25519", key: key, replay_scope: {:credential, :orders, "credential-1"}}}
        end,
        freshness: %{clock: fn -> @now end, max_age: 120, skew: 0, require_expires: true},
        content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
        replay: %{
          identifier: identifier,
          namespace: "orders",
          scope: :credential,
          store: Replay.ETS.store(replay),
          timeout: 1000,
          retain_until: @now + 120
        }
      })

    policy
  end
end
