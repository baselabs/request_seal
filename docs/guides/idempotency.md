# Recovering the response to a signed request

Use stored-response recovery when your client may lose the response to a
request that changed application state. The client records the operation once
and makes a fresh signed attempt for each send. The server claims each nonce,
then checks the operation key against the earlier result.

The following example records a request, verifies the first attempt, stores
the response, and retrieves it on a freshly signed retry.

```elixir
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
```

A principal comes from trusted application state, and the selected policy's
resolver must authenticate only credentials belonging to that principal. Recheck
application permission before looking up or returning a response. Give
operations with different semantics separate namespaces or validate every
effect-relevant field against the endpoint's fixed expectations. By design the
fingerprint covers method, target, Content-Digest and exact body, independent of
nonce, signature and signer metadata. Applications must control other variation,
including content type, content encoding, and response negotiation. The
[Idempotency-Key Internet-Draft, revision 09](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header-09)
describes retry outcomes and recommended HTTP status codes.

A live reservation yields `:in_progress`. At admission the store checks the
prepared lease and retention bounds against its trusted clock. A delayed
record outside that window returns `:record_expired`. Prepare a new
authenticated attempt before retrying admission. An expired matching lease
may be renewed while its row is retained. Renewal invalidates the old token,
and completion requires the current token and an unexpired stored lease and
retention window. A different fingerprint conflicts while the row is
retained, including after completion.

A timeout may have committed a store operation. Reconcile the effect and
response before repeating the effect. Use consistent clocks and retention
settings across nodes. ETS defaults to the system Unix clock and accepts an
explicit `:clock`. Each clock read runs under the operation deadline, so a
stalled callback times out before any transition. Pass a cutoff at or before the store's current time to
`Idempotency.sweep/3`.

Reserve after authentication and authorization, then enforce the same unique
operation key in the transaction or service that commits the effect. If that
effect already committed, recover its outcome there and finish the response
record. The local ETS store loses state on restart. A durable adapter implements
the same atomic reserve, token-fenced completion and sweep callbacks. Keep
responses in storage only when repeating them to the same principal is safe.
The API accepts complete terminal responses with retained bodies up to 1 MiB.
It filters hop-by-hop fields, credentials, signatures, digests, and framing
headers. It also excludes Authentication-Info and Proxy-Authentication-Info,
and refuses stored responses containing these exchange-specific fields.
Use an explicit allowlist for the other end-to-end headers. Generate
transport-specific response fields and any new response signature at delivery.

For durable client recovery, persist the `Journal.entry/2` snapshot under its
unique namespace and key before sending. Before recording, it reconstructs
the HTTP(S) request and checks the captured method, target, and retained
body. It preserves the ordered field values and reserves enough room in the
message field budget to append both signature fields. Reissue checks the
complete snapshot and its digest before signing. Protect the journal against unauthorized reads and
writes. Keep custom credential headers out of persisted intent. The caller
controls retries and records send outcomes where needed.
