defmodule RequestSeal.GuideIdempotencyTest do
  use ExUnit.Case, async: true
  alias RequestSeal.DocsExamples, as: E

  test "the guide example executes with real signing and replay storage" do
    binding = []

    E.eval(
      ~S'''
      alias RequestSeal.{Custody, Idempotency, Journal, Message, Policy, Replay}

      {:ok, signer} = Custody.Local.generate("ed25519", [])
      {:ok, key} = Custody.public_key(signer)
      {:ok, journal} = Journal.start_link(max_entries: 100)
      {:ok, nonce_pid} = Replay.ETS.start_link(max_entries: 100)
      {:ok, response_pid} = Idempotency.ETS.start_link(max_entries: 100)
      responses = Idempotency.ETS.store(response_pid)
      now = System.system_time(:second)
      clock = fn -> now end
      components = ~s[("@method" "@target-uri" "content-digest" "idempotency-key")]

      {:ok, request} =
        Message.request(
          "POST",
          "https://api.example.test/orders",
          [{"idempotency-key", ~s["order-7"]}],
          ~s({"item":"notebook"}),
          digest: ["sha-256"]
        )

      :recorded = Journal.record(journal, "orders", request)
      spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60}
      {:ok, first} = Journal.reissue(journal, "orders", "order-7", spec, signer, clock: clock)

      {:ok, policy} =
        Policy.new(%{
          algorithms: ["ed25519"],
          components: components,
          key_resolver: fn _ ->
            {:ok, %{algorithm: "ed25519", key: key, replay_scope: {:principal, "account-7"}}}
          end,
          freshness: %{clock: clock, max_age: 60, skew: 0, require_expires: true},
          content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
          replay: %{
            namespace: "orders",
            identifier: :nonce,
            scope: :principal,
            store: Replay.ETS.store(nonce_pid),
            timeout: 1_000,
            retain_until: now + 120
          }
        })

      intent = [namespace: "orders", principal: "account-7", now: now, retention: 3_600]
      {:ok, record} = Idempotency.prepare(first, policy, "sig", intent)
      {:reserved, lease} = Idempotency.reserve(responses, record, timeout: 1_000)

      # The application commits the effect under its durable unique operation key.
      response = %{status: 201, headers: [{"content-type", "text/plain"}], body: "created"}
      :stored = Idempotency.store(responses, lease, response, timeout: 1_000, allow_headers: ["content-type"])

      {:ok, retry} = Journal.reissue(journal, "orders", "order-7", spec, signer, clock: clock)
      {:ok, record} = Idempotency.prepare(retry, policy, "sig", intent)
      {:stored, ^response} = Idempotency.reserve(responses, record, timeout: 1_000)
      :ok = Custody.Local.release(signer)
      :ok = GenServer.stop(journal)
      :ok = GenServer.stop(nonce_pid)
      :ok = GenServer.stop(response_pid)
      ''',
      binding,
      "docs/guides/idempotency.md",
      1
    )

    E.assert_fences("docs/guides/idempotency.md", 1)
  end
end
