<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Reject repeated signed requests

**What you will build:** A verifier that accepts each signed nonce once, rejects duplicates, and reclaims expired claims. Install RequestSeal; this example defines its own key, request, and policy and uses a local ETS store. This local example applies [RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2) with one trusted key in one namespace.

## Prepare a signed request

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
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
    components: ~s[("@method" "@authority" "@path" "content-digest")],
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
  components: ~s[("@method" "@authority" "@path" "content-digest")],
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

Use a trusted clock consistent with verification. Retention ends at the first rejected second: the minimum of expiration plus skew and created plus max-age plus skew plus one. Multi-node operators sweep at `now - max_internode_skew`, so a claim remains while any verifier can still accept it. Use one freshness bound per namespace; duplicate claims never extend retention. Claims never evict entries, and neither adapter schedules a background sweep.

## Choose local or persistent storage

Supervise `RequestSeal.Replay.ETS` with an explicit capacity in your application. It serializes atomic claims and sweeps; owner termination loses the claims. It is local, not a distributed store.

For durable replay, prefer `RequestSeal.Replay.AshOnetime` with optional
`{:ash_onetime, "~> 1.5", optional: true}` on Elixir 1.20 or newer. Install
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
margin. Keep application and database clocks synchronized. Duplicate claims do not
extend retention. A timeout is indeterminate and never permits automatic retry.
`RequestSeal.Replay.AshOnetime.sweep/3` returns `{:error, :externally_managed}`;
use `mix ash_onetime.prune` or its Oban cleanup worker. For atomic nonce spending
with an application effect, verify with replay explicitly `:not_required` and
call `AshOnetime.Transaction.nonce/2` inside that application's transaction.

The Postgrex-only adapter remains available. For PostgreSQL, add `:postgrex` (`~> 0.22.4`), start the Postgrex application and your connection, execute SQL returned by `RequestSeal.Replay.Postgres.ddl("signature_replay")`, and select `RequestSeal.Replay.Postgres.store(connection, table: "signature_replay")`. The adapter starts no database or pool. Table names are explicit lowercase ASCII identifiers; namespace/key columns form a primary key. Persistence follows your database configuration. See [replay-store testing](testing.md#replay-stores) for actual database, concurrency, and restart checks.

For Web Bot Auth, use the same generic replay policy fields on its policy. Bind the draft's nonce, key ID, and stable agent identifier in your commitment; one claim follows the complete verified envelope. Generic single-label verification requires bounded freshness and a nonempty nonce. Quorum verification rejects required replay until a composite claim contract is implemented.

## Errors

`:missing_replay_identifier` means the selected signature has no usable nonce. `:replayed` means a prior claim exists. `:commitment_failed` means your function failed or returned an invalid result. `:store_unavailable`, `:store_timeout`, and `:store_failed` reject authentication, including full stores. A single deadline covers commitment and atomic storage; caller cancellation stops work but cannot undo a committed claim. A timeout may already have committed, so no replay error permits automatic retry.

Module docs: `RequestSeal.Policy`, `RequestSeal.Replay`, `RequestSeal.Replay.ETS`, `RequestSeal.Replay.AshOnetime`, `RequestSeal.Replay.Postgres`, `RequestSeal.Replay.Store`, `RequestSeal.Replay.Receipt`, `RequestSeal.Error`.
