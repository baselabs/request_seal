<!-- Status: current · Kind: guide · Updated: 2026-10-16 · Governed by: public architecture · Review when: an error struct, reason, layer, or retry rule changes -->

# Diagnose and handle errors

**What you will build:** A signed request and a table of changes to it, each asserted against the exact `reason` and `layer` RequestSeal returns, plus logging and retry rules you can apply to every error. Prerequisite: RequestSeal installed; no framework or network is needed.

## Read an error

Every failure is a bounded struct with a closed `reason` atom. No error carries request bytes, key material, key IDs, URLs, or exception text, so you can log the fields below without redaction.

| Struct | Returned by | Fields to use | Retryable |
| --- | --- | --- | --- |
| `RequestSeal.Error` | `sign/4`, `verify/3`, `verify_quorum/3`, `Policy.new/1`, Web Bot Auth, Ash scope, negotiation | `reason`, `layer`, `detail`, `correlation`, `source` | Only `:deadline` |
| `RequestSeal.Adapter.Error` | Req, Finch, Plug | `reason`, `adapter`, `stage`, `attempt`, `correlation`, `source` | Never |
| `RequestSeal.Custody.Error` | `RequestSeal.Custody`, key handles | `reason`, `retryable` | `:deadline_exceeded`, `:custodian_unavailable` |
| `RequestSeal.JOSE.Error` | JWS, JWE, nested JOSE, key management | `reason`, `layer` | `:deadline_exceeded` |
| `RequestSeal.Discovery.Error` | Discovery fetch and cache | `reason`, `retryable` | `:connect_failed`, `:deadline_exceeded`, `:resolution_failed`, `:source_unavailable`, `:cache_overloaded`, and `:unexpected_status` for a 5xx response |
| `RequestSeal.Replay.Error` | `RequestSeal.Replay.claim/3` | `reason` | Never; a timeout may already have committed |
| `RequestSeal.Message.Error`, `RequestSeal.Digest.Error`, `RequestSeal.SignatureBase.Error`, `RequestSeal.StructuredFields.Error`, `RequestSeal.Crypto.Error` | Message construction, digests, signature bases, Structured Fields, primitives | `reason` | Correct the input |

Each struct's module documentation lists every reason with its meaning. For `RequestSeal.Error`, match `layer` first: it names the check that rejected the message (`:input`, `:fields`, `:policy`, `:key`, `:crypto`, `:content`, `:freshness`, `:replay`, `:quorum`, `:negotiation`, `:binding`, `:profile`, or `:internal`), and `reason` names the rule. A `:signing_failed` error keeps the custody failure in `source`; an adapter's `:request_rejected` or `:response_rejected` keeps the core error in `source`.

## Log safely

Log the closed fields and the random `correlation` token, which lets you match a client report to your log line without recording the request:

```elixir
log_fields = fn
  %RequestSeal.Error{} = error ->
    %{reason: error.reason, layer: error.layer, detail: error.detail, correlation: error.correlation}

  %RequestSeal.Adapter.Error{} = error ->
    %{reason: error.reason, adapter: error.adapter, stage: error.stage, correlation: error.correlation}

  %{reason: reason} ->
    %{reason: reason}
end
```

Do not log `verification.signature.parameters`, `verification.signature.keyid`, or header values; default inspection already hides them.

## Observe with telemetry

From 0.5.0, RequestSeal emits a versioned `:telemetry` contract (`RequestSeal.Telemetry` documents every event name and key): a stop event for `RequestSeal.verify/3`, `RequestSeal.verify_quorum/3`, and Web Bot Auth verification with `outcome`, `reason`, `layer`, and `detail`, plus a claim event for every replay commitment and a stop event for the shared custody signing path. Metadata carries only closed reason and layer atoms — never labels, key IDs, URLs, or bytes — so a handler can record it unredacted:

```elixir
:telemetry.detach("request-seal-ops")

:telemetry.attach_many("request-seal-ops", [
  [:request_seal, :verify, :stop],
  [:request_seal, :verify_quorum, :stop]
], fn _event, _measurements, metadata, _config ->
  send(self(), {:verified, metadata.outcome})
end, nil)

:telemetry.detach("request-seal-ops")
```

Resource exhaustion is observable the same way: a `:limit` reason marks a documented bound and the retryable `:deadline` reason marks the caller wall-clock bound on `verify_quorum/3`. An `:internal` reason at layer `:internal` marks an unexpected internal fault, not a property of the input; its `detail` is the exception class, and the correlation token pairs it with your logs.

## Reproduce each rejection

Sign one request with a covered body digest and an explicit policy. The policy requires replay protection, so the store is part of the setup:

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, store} = RequestSeal.Replay.ETS.start_link(max_entries: 1_000)
components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]
now = System.system_time(:second)

signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: components,
  expires_in: 60,
  keyid: "docs-key"
}

build = fn url, body ->
  RequestSeal.Message.request("PUT", url, [], body, digest: ["sha-256"])
end

{:ok, message} = build.("https://files.example.com/reports/q3.pdf", "report bytes")
{:ok, signed} = RequestSeal.sign(message, signing, handle, clock: fn -> now end)

policy_fields = %{
  algorithms: ["ed25519"],
  components: components,
  key_resolver: fn
    %{keyid: "docs-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
    _ -> :error
  end,
  freshness: %{clock: fn -> now end, max_age: 60, skew: 5, require_expires: true},
  content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
  replay: %{
    identifier: :nonce,
    namespace: "errors-guide",
    commitment: fn facts -> {:ok, facts.identifier} end,
    store: RequestSeal.Replay.ETS.store(store),
    timeout: 5_000
  }
}

{:ok, policy} = RequestSeal.Policy.new(policy_fields)
```

Each row changes one thing and states the error it must produce. Verification of an unchanged request succeeds once and then rejects as a replay:

```elixir
headers = Enum.map(signed.fields, &{&1.name, &1.value})
{:ok, other_path} = RequestSeal.Message.request("PUT", "https://files.example.com/reports/q4.pdf", headers, "report bytes")
{:ok, other_body} = RequestSeal.Message.request("PUT", "https://files.example.com/reports/q3.pdf", headers, "edited bytes")
{:ok, uncovered} = build.("https://files.example.com/reports/q3.pdf", "report bytes")

{:ok, uncovered} =
  RequestSeal.sign(uncovered, %{signing | components: ~s[("@method" "@scheme" "@authority" "@path")]},
    handle, clock: fn -> now end)

{:ok, nonceless} = build.("https://files.example.com/reports/q3.pdf", "report bytes")
{:ok, nonceless} = RequestSeal.sign(nonceless, Map.put(signing, :nonce, nil), handle, clock: fn -> now end)

policy_with = fn changes ->
  {:ok, changed} = RequestSeal.Policy.new(Map.merge(policy_fields, changes))
  changed
end

at = fn clock -> %{policy_fields.freshness | clock: fn -> clock end} end

cases = [
  {"path changed", other_path, policy, :crypto, :invalid_signature},
  {"body changed", other_body, policy, :content, :digest_mismatch},
  {"after expiry", signed, policy_with.(%{freshness: at.(now + 120)}), :freshness, :expired},
  {"before created", signed, policy_with.(%{freshness: at.(now - 600)}), :freshness, :created_in_future},
  {"older than max age", signed,
   policy_with.(%{freshness: %{at.(now + 45) | max_age: 30}}), :freshness,
   :too_old},
  {"unknown key", signed, policy_with.(%{key_resolver: fn _ -> :error end}), :key, :unknown_key},
  {"algorithm not allowed", signed, policy_with.(%{algorithms: ["ecdsa-p256-sha256"]}), :policy,
   :algorithm_not_permitted},
  {"extra coverage", signed,
   policy_with.(%{components: ~s[("@method")], extra_components: :reject}), :policy,
   :unexpected_component},
  {"digest not required or signed", uncovered, policy, :policy, :missing_required_component},
  {"digest not signed", uncovered,
   policy_with.(%{components: ~s[("@method" "@scheme" "@authority" "@path")]}), :content,
   :digest_not_covered},
  {"no nonce", nonceless, policy, :replay, :missing_replay_identifier}
]

for {name, request, case_policy, layer, reason} <- cases do
  {:error, %{layer: ^layer, reason: ^reason}} = RequestSeal.verify(request, case_policy, label: "sig")
  {name, reason}
end

{:error, %{layer: :fields, reason: :unknown_label}} = RequestSeal.verify(signed, policy, label: "other")
{:ok, _first} = RequestSeal.verify(signed, policy, label: "sig")
{:error, %{layer: :replay, reason: :replayed}} = RequestSeal.verify(signed, policy, label: "sig")
```

Signing failures follow the same shape. A released key handle reports `:signing_failed` with the custody reason in `source`:

```elixir
:ok = RequestSeal.Custody.Local.release(handle)

{:error, %{reason: :signing_failed, layer: :crypto, source: %{reason: :key_not_found}}} =
  RequestSeal.sign(message, signing, handle)

GenServer.stop(store)
```

Replay is claimed only after every other check passes, so a rejected request never consumes its nonce: the unchanged request above still verified once after all the rejections.

## Retry rules

Retry only an error whose struct says `retryable: true`: custody `:deadline_exceeded` or `:custodian_unavailable`, JOSE `:deadline_exceeded`, and the discovery reasons in the table above. Retrying never authorizes repeating an application operation; decide that separately.

Never retry a `RequestSeal.Error` by resending the same signed bytes: the verifier rejects them for the same reason, or as a replay. A replay store `:store_timeout` is indeterminate because the claim may have committed; treat that request as rejected and ask the sender to sign a new one.

The one retryable `RequestSeal.Error` is `:deadline` at `:quorum` (from 0.5.0): the caller's `:deadline` wall-clock bound on `verify_quorum/3` expired during the assignment search. Verification established nothing, so retrying with a later deadline is safe and can succeed under less load.

Next: [signing and verifying](signing-and-verifying.md) for the full policy, [replay protection](replay-protection.md) for store failures, and [key custody](key-custody.md) for handle lifecycles.
