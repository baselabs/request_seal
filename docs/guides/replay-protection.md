# Reject repeated signed requests

**What you will build:** A verifier that accepts each signed nonce once, rejects duplicates, and reclaims expired claims. Install RequestSeal; this example defines its own key, request, and policy and uses a local ETS store. This local example applies [RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2) with one trusted key in one namespace.

## Prepare a signed request

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = handle
```

Build the request from its exact body bytes:

```elixir
{:ok, message} =
  RequestSeal.Message.request(
    "POST",
    "https://api.example.com/webhooks",
    [],
    ~s({"event":"created"})
  )
```

Select the trusted key, required coverage, freshness, body integrity, and replay rules:

```elixir
{:ok, policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
    key_resolver: fn
      %{keyid: "demo-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
      _ -> :error
    end,
    freshness: %{
      clock: fn -> System.system_time(:second) end,
      max_age: 60,
      skew: 5,
      require_expires: true
    },
    content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
    replay: :not_required
  })
```

Sign the request with a fresh nonce and a 60-second validity window:

```elixir
signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
  expires_in: 60,
  keyid: "demo-key",
  digest: ["sha-256"]
}

{:ok, signed} = RequestSeal.sign(message, signing, handle)
```

## 1. Start a store and require a nonce

```elixir
{:ok, replay_pid} = RequestSeal.Replay.ETS.start_link(max_entries: 10_000)

replay = %{
  identifier: :nonce,
  namespace: "demo-api",
  commitment: fn facts -> {:ok, facts.identifier} end,
  store: RequestSeal.Replay.ETS.store(replay_pid),
  timeout: 5_000
}

{:ok, replay_policy} = RequestSeal.Policy.new(%{Map.from_struct(policy) | replay: replay})
{:ok, accepted} = RequestSeal.verify(signed, replay_policy, label: "sig")
```

The accepted verification carries a replay receipt. A duplicate verification rejects:

```elixir
RequestSeal.verify(signed, replay_policy, label: "sig")
# => {:error, %RequestSeal.Error{reason: :replayed, ...}}
```

Your namespace and commitment define the security context. This example returns the nonce directly because the policy accepts one pinned key; it is not a general application commitment recipe. Supply your own binding for keys, profiles, and tenants. RequestSeal calls it after cryptography, coverage, freshness, and content checks, with authenticated facts, and accepts 1–256 returned bytes.

## 2. Sweep at the exclusive retention end

```elixir
retain_until = accepted.replay.retain_until
RequestSeal.Replay.ETS.sweep(replay_pid, retain_until - 1)
# => {:ok, 0}
```

At the retention boundary, the expired claim can be removed:

```elixir
RequestSeal.Replay.ETS.sweep(replay_pid, retain_until)
# => {:ok, 1}
```

Use a trusted clock consistent with verification. Retention ends at the first rejected second: the minimum of expiration plus skew and created plus max-age plus skew plus one. Multi-node operators sweep at `now - max_internode_skew`, so a claim remains while any verifier can still accept it. Use one freshness bound per namespace; duplicate claims never extend retention. Claims never evict entries, and no RequestSeal adapter schedules a background sweep.

## Move replay claims to a new store

Use `RequestSeal.Replay.Pair.store/2` while moving live claims to a destination
that can see every attempt at the same claim. For a distributed verifier, use a
shared durable destination such as PostgreSQL or AshOnetime. Every verifier
that may receive a claim, including after routing changes or restarts, must see
entries already written at the destination until their retention ends.
Independent node-local ETS destinations cannot satisfy this: after cutover a
retry routed to another node could find an empty destination there. The pair
refuses an ETS destination when the retiring adapter is anything other than
ETS. The two-ETS example applies to one verifier whose state remains live.

Put the destination first and use the returned handle as the policy's `store`.

```elixir
alias RequestSeal.Replay.{ETS, Pair}
{:ok, destination} = ETS.start_link(max_entries: 100)
{:ok, retiring} = ETS.start_link(max_entries: 100)
{:ok, store} = Pair.store(ETS.store(destination), ETS.store(retiring))
```

Keep the namespace, commitment function and freshness rules consistent during the
move. Start the retention clock when the last retiring-only verifier has finished
its last claim. Wait through the longest retention of any claim it could have
written, including skew and the exclusive endpoint, before switching any
verifier to destination only. When a policy admits arbitrarily distant expiry,
use the greatest possible retention endpoint or first establish a finite bound
and wait for previous claims to expire. Finish draining paired verifiers before
stopping the retiring store. A node-local store contributes its existing local
history, so keep it alive across the switch to paired operation.

A claim succeeds after two new writes. A retirement-side refusal leaves the
destination entry spent. Budget the policy timeout for two sequential operations
and continue sweeping both stores under their existing retention rules.
The shared deadline covers both adapters and synchronous telemetry, even on
direct pair calls. A blocked adapter, blocked event handler, or late reply
reports timeout. Direct calls require an integer deadline and an owner PID.
A completed write stays spent.
`RequestSeal.Replay.Pair.sweep/3` handles stores whose cleanup is external.
The receipt names the pair during migration. When an adapter returns within
the shared budget, the `[:request_seal, :replay, :pair]` event identifies its
position without logging claim data.

## Choose local or persistent storage

Supervise `RequestSeal.Replay.ETS` with an explicit `max_entries:` capacity (1 to 10,000,000) in your application. It serializes claims and sweeps and refuses claims at or before the greatest successful sweep cutoff, including after sweeps that remove zero entries. A late claim returns `:store_failed`. The local owner keeps the claims and cutoff in memory.
Before writing a queued claim, ETS checks that the calling process and
applicable local lifetime owners are still alive. A committed claim remains
spent after cancellation.

For durable replay, prefer `RequestSeal.Replay.AshOnetime` with optional
`{:ash_onetime, "~> 1.9 and >= 1.9.2", optional: true}` on Elixir 1.20 or newer. Install
ash_onetime's migrations in your existing repo using
`mix ash_onetime.gen.migrations --repo MyApp.Repo`, then `mix ecto.migrate`, as
specified by its public [migration task](https://hexdocs.pm/ash_onetime/Mix.Tasks.AshOnetime.Gen.Migrations.html)
and [transaction contract](https://hexdocs.pm/ash_onetime/AshOnetime.Transaction.html).
Given your existing `repo` and schema `prefix` (`nil` for its default schema):

```elixir
durable_store = RequestSeal.Replay.AshOnetime.store(repo,
  partition: "demo-api", prefix: prefix)
durable_replay = %{replay | store: durable_store}
{:ok, durable_policy} = RequestSeal.Policy.new(%{Map.from_struct(policy) | replay: durable_replay})
{:ok, durable_accepted} = RequestSeal.verify(signed, durable_policy, label: "sig")
```

Each claim commits in its own READ COMMITTED repo transaction under the remaining
deadline. Namespace and commitment bytes are base64url encoded. ash_onetime retains
the claim at least through RequestSeal's `retain_until`, with its additional safety
margin. The adapter reads `issued_at` from PostgreSQL's transaction clock in that
same transaction; retention therefore uses the database clock even if the
application clock differs. ash_onetime's freshness check can still reject skew.
Past or current `retain_until` values still block an immediate duplicate until
cleanup becomes eligible. Duplicate claims do not extend retention. A timeout is
indeterminate and never permits automatic retry: the insert may already have
committed, and a later claim then returns already-claimed. Invalid claim bytes and
deterministic argument errors return failure rather than transient unavailability.
`RequestSeal.Replay.AshOnetime.sweep/3` returns `{:error, :externally_managed}`;
use `mix ash_onetime.prune` or its Oban cleanup worker. For atomic nonce spending
with an application effect, verify with replay explicitly `:not_required` and
call `AshOnetime.Transaction.nonce/2` inside that application's transaction.

The Postgrex-only adapter remains available. For PostgreSQL, add `:postgrex` (`>= 0.22.4 and < 0.24.0`), start the Postgrex application and your connection, execute the SQL returned by `RequestSeal.Replay.Postgres.ddl("signature_replay")` and `RequestSeal.Replay.Postgres.ddl_index("signature_replay")`, and select `RequestSeal.Replay.Postgres.store(connection, table: "signature_replay")`. The adapter starts no database or pool. Table names are explicit lowercase ASCII identifiers; namespace/key columns form a primary key, and the index keeps caller-scheduled `sweep/3` deletes from scanning the whole table (`ddl_index/1` accepts names of at most 46 bytes so its derived index identifier fits PostgreSQL's 63-byte limit). Persistence follows your database configuration. See [replay-store testing](testing.md#replay-stores) for actual database, concurrency, and restart checks.
With that adapter, coordinate sweeps with in-flight verification and claims.
Only sweep a cutoff once every operation that could claim a retention end at
or below it has completed or been canceled.

For Web Bot Auth, give `RequestSeal.WebBotAuth.Policy` the same replay map. Its commitment receives the same facts map, with the signing agent as `agent` in place of `tag`; commit to `identifier`, `keyid`, and `agent[:identifier]`, as the [Web Bot Auth guide](web-bot-auth.md) shows in a runnable example. Required replay accepts exactly one selected Web Bot Auth signature per message and rejects more with `:unexpected_signature`; its claim follows that verified signature, and the facts never include the uncovered label. Generic single-label verification requires bounded freshness and a nonempty nonce.

## Errors

`:missing_replay_identifier` means the selected signature has no usable nonce. `:replayed` means a prior claim exists. `:commitment_failed` means your function failed or returned an invalid result. `:store_unavailable`, `:store_timeout`, and `:store_failed` reject authentication, including full stores. A single deadline covers commitment and atomic storage; caller cancellation stops work but cannot undo a committed claim. A timeout may already have committed, so no replay error permits automatic retry. `:retention_exceeded` means the derived retention end is above 253,402,300,799 and rejects before commitment. `RequestSeal.Policy.new/1` returns `:invalid_policy` when required replay lacks bounded freshness (`require_expires: true` or a `max_age`). The [errors guide](errors.md) reproduces `:replayed` and `:missing_replay_identifier`.

Module docs: `RequestSeal.Policy`, `RequestSeal.Replay`, `RequestSeal.Replay.ETS`, `RequestSeal.Replay.AshOnetime`, `RequestSeal.Replay.Postgres`, `RequestSeal.Replay.Store`, `RequestSeal.Replay.Receipt`, `RequestSeal.Error`.

## Library-built nonce and operation commitments

Set `replay` to a map with `:identifier`, `:scope`, `:namespace`, `:store`,
`:timeout` and `:retain_until` in a generic `RequestSeal.Policy`.
Choose `:nonce` for a fresh RFC 9421 attempt. Choose
`{:operation, [~s["@method"], ~s["@target-uri"], ...]}` for single-use operation
semantics, with exact identifiers from the policy's required coverage. Include
every covered value that determines the operation and require verified content
when it has a body. Choose a separate namespace for each distinct trust and
freshness policy. Verification refuses a signature window extending past the
fixed exclusive `:retain_until`. Keep the bound and namespace consistent
across aliases and rotation, and allow for clock skew and in-flight verification
when scheduling a sweep.

With `:scope` set to `:credential` or `:principal`, the trusted key resolver
adds `replay_scope: {:credential, purpose, id}` or
`replay_scope: {:principal, id}`. A credential may use `nil` for the purpose.
Choose `:key` when the identity should follow key material. Symmetric handles
need a caller-supplied opaque key identity. Key IDs on the wire can locate keys
but do not enter the commitment. Inspect the deterministic construction with
`RequestSeal.Replay.Commitment.key/2`.

Use nonce replay with [stored-response recovery](idempotency.md) when a fresh
retry should retrieve a prior response.
