# Diagnose and handle errors

**What you will build:** A signed request and a table of changes to it, each asserted against the exact `reason` and `layer` RequestSeal returns, plus logging and retry rules you can apply to every error. Prerequisite: RequestSeal installed; no framework or network is needed.

## Read an error

Every failure is a bounded struct with a closed `reason` atom. No error carries request bytes, key material, key IDs, URLs, or exception text, so you can log the fields below without redaction.

| Struct | Returned by | Fields to use | Retryable |
| --- | --- | --- | --- |
| `RequestSeal.Error` | `sign/4`, `verify/3`, `Policy.new/1`, Web Bot Auth, Ash scope, negotiation | `reason`, `layer`, `detail`, `correlation`, `source` | No |
| `RequestSeal.Adapter.Error` | Req, Finch, Plug | `reason`, `adapter`, `stage`, `attempt`, `correlation`, `source` | Never |
| `RequestSeal.Custody.Error` | `RequestSeal.Custody`, key handles | `reason`, `retryable` | `:deadline_exceeded`, `:custodian_unavailable` |
| `RequestSeal.JOSE.Error` | JWS, JWE, nested JOSE, key management | `reason`, `layer` | `:deadline_exceeded` |
| `RequestSeal.Discovery.Error` | Discovery fetch and cache | `reason`, `retryable` | `:connect_failed`, `:deadline_exceeded`, `:resolution_failed`, `:source_unavailable`, `:cache_overloaded`, and `:unexpected_status` for a 5xx response |
| `RequestSeal.Replay.Error` | `RequestSeal.Replay.claim/3` | `reason` | Never; a timeout may already have committed |
| `RequestSeal.Message.Error`, `RequestSeal.Digest.Error`, `RequestSeal.SignatureBase.Error`, `RequestSeal.StructuredFields.Error`, `RequestSeal.Crypto.Error` | Message construction, digests, signature bases, Structured Fields, primitives | `reason` | Correct the input |

Each struct's module documentation lists every reason with its meaning. For `RequestSeal.Error`, match `layer` first: it names the check that rejected the message (`:input`, `:fields`, `:policy`, `:key`, `:crypto`, `:content`, `:freshness`, `:replay`, `:negotiation`, `:binding`, `:profile`, or `:internal`), and `reason` names the rule. A `:signing_failed` error keeps the custody failure in `source`; an adapter's `:request_rejected` or `:response_rejected` keeps the core error in `source`.

On Req attempt two or later, RequestSeal's final error step returns
`{:error, %RequestSeal.Adapter.Error{reason: :transport_failed, adapter: :req,
stage: :transport, attempt: n, source: nil}}`. It discards the framework
exception and its details after Req has decided whether to retry. An HTTP/2
stream or pool refusal with a non-nil sent Finch body produces this error on
any attempt, including attempt one: Finch can discard and rerun a partially
sent body internally. Even `""` is non-nil; a nil body rules out that earlier
send. Other first-attempt transport errors retain Req's own shape. A later
signing refusal still has its original reason at stage `:sign` and its final
attempt number. Both mean unknown delivery for the whole call: an earlier
redirect or retry attempt may already have sent the operation. Use
`RequestSeal.Req.classify/1` for delivery evidence before repeating an operation;
the adapter error's `retryable: false` remains unchanged. For Finch, pass the
result and the exact sent `Finch.Request` to `RequestSeal.Finch.classify/2`.
It applies the same HTTP/2 body rule, and a non-request second argument returns
unknown delivery. Raw DNS and ALPN failures remain pre-send refusals; HTTP/2
background connection failures surface as pool errors subject to the body rule.

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

RequestSeal emits a versioned `:telemetry` contract (`RequestSeal.Telemetry` documents every event name and key): a stop event for `RequestSeal.verify/3` and Web Bot Auth verification with `outcome`, `reason`, `layer`, and `detail`, plus a claim event for every replay commitment and a stop event for the shared custody signing path. Metadata carries only closed reason and layer atoms — never labels, key IDs, URLs, or bytes — so a handler can record it unredacted. Attach a named module function; `:telemetry` warns that anonymous handlers carry a performance penalty:

```elixir
defmodule MyApp.RequestSealTelemetry do
  def handle_event(event, %{duration: duration}, metadata, destination) do
    send(destination, {:seal_event, event, duration, metadata})
  end
end

:telemetry.detach("request-seal-ops")

:ok =
  :telemetry.attach_many(
    "request-seal-ops",
    RequestSeal.Telemetry.events(),
    &MyApp.RequestSealTelemetry.handle_event/4,
    self()
  )
```

Resource exhaustion is observable the same way: a `:limit` reason marks a documented bound. An `:internal` reason at layer `:internal` marks an unexpected internal fault, not a property of the input; its `detail` is the exception class, and the correlation token pairs it with your logs.

## Reproduce each rejection

Sign one request with a covered body digest and an explicit policy. The policy requires replay protection, so the store is part of the setup:

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
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

Next: [signing and verifying](signing-and-verifying.md) for the full policy, [replay protection](replay-protection.md) for store failures, and [key custody](key-custody.md) for handle lifecycles.


`Custody.derive/4` has a third result shape: `{:cleanup_required, cleanup, error}`.
It means a commit result was lost and destruction of the possibly committed child
is unconfirmed. The enclosed bounded error describes the original failure;
`cleanup_required` is not a reason. Call `Custody.cleanup/2` with a required
`timeout:` until `:ok`. A release timeout does not establish destruction.
An explicit commit refusal or a failed derive returns an ordinary error.
Custody `:unavailable` is nonretryable and marks uncommitted or refused commit
state; it differs from transport `:custodian_unavailable`.

`JOSE.decode_object/2` requires exactly `max_bytes:` (1 through 1,048,576).
Invalid options return `:invalid_options`; malformed JSON, a non-object root,
invalid UTF-8 and floats return `:invalid_header`; duplicate names at any depth
return `:duplicate_member`. Exceeding the byte, four-container depth, 64-entry
width, 16,384-byte string/name or ±999,999,999,999,999 integer bound returns
`:limit`. All are nonretryable input errors. For JWE `content: :object`, these
same decode errors occur only after authentication and contain no plaintext.
Key closures reject before invocation: signing and wrapping use `:invalid_options`,
resolver key results use `:key_resolver_failed`. Accept-Signature fulfillment
selects a matching custody handle or returns `:negotiation_unfulfillable`.

## Complete reason inventory

These closed vocabularies are checked against source emissions and each error
module's `reason` type. Each module documents their meanings.

### RequestSeal.Error

`:actor_unbound`, `:agent_unresolved`, `:algorithm_mismatch`, `:algorithm_not_permitted`, `:body_unavailable`, `:commitment_failed`, `:created_in_future`, `:digest_mismatch`, `:digest_not_covered`, `:digest_unsupported`, `:duplicate_label`, `:duplicate_parameter`, `:expired`, `:inapplicable_component`, `:internal`, `:invalid_accept_signature`, `:invalid_binding`, `:invalid_clock`, `:invalid_keyid`, `:invalid_message`, `:invalid_options`, `:invalid_policy`, `:invalid_profile`, `:invalid_request`, `:invalid_signature`, `:invalid_signature_agent`, `:invalid_signature_field`, `:invalid_signature_input`, `:invalid_verification`, `:key_resolver_failed`, `:label_in_use`, `:label_mismatch`, `:lifetime_exceeded`, `:limit`, `:missing_created`, `:missing_expires`, `:missing_replay_identifier`, `:missing_required_component`, `:missing_signature`, `:missing_signature_input`, `:negotiation_unfulfillable`, `:nested_coverage_incomplete`, `:no_web_bot_auth_signature`, `:replayed`, `:retention_exceeded`, `:signature_base_failed`, `:signer_algorithm_mismatch`, `:signer_failed`, `:signing_failed`, `:store_failed`, `:store_timeout`, `:store_unavailable`, `:tenant_unbound`, `:test_key_rejected`, `:too_old`, `:unattributed`, `:unexpected_component`, `:unexpected_signature`, `:unknown_key`, `:unknown_label`, `:unsupported_component`, `:verifier_failed`, `:issued_for_mismatch`, `:key_issued_for_mismatch`, `:scope_unbound`.

### RequestSeal.SignatureBase.Error

`:invalid_message`, `:invalid_options`, `:invalid_signature_parameters`, `:limit`, `:malformed`, `:invalid_component`, `:unknown_component`, `:duplicate_component`, `:invalid_component_parameters`, `:incompatible_parameters`, `:wrong_message_kind`, `:missing_request_context`, `:unavailable_origin`, `:unavailable_trailers`, `:missing_field`, `:non_ascii`, `:unknown_field_schema`, `:invalid_field_schema`, `:invalid_structured_field`, `:missing_dictionary_key`, `:noncanonical_query_name`, `:invalid_query_encoding`, `:missing_query_parameter`, `:ambiguous_query_parameter`.

### RequestSeal.JOSE.Error

`:invalid_options`, `:invalid_policy`, `:limit`, `:invalid_serialization`, `:invalid_base64`, `:invalid_header`, `:duplicate_member`, `:unsupported_header`, `:unsupported_serialization`, `:compression_unsupported`, `:detached_payload`, `:algorithm_not_permitted`, `:algorithm_mismatch`, `:unsupported_critical_header`, `:unknown_key`, `:key_resolver_failed`, `:invalid_signature`, `:signer_failed`, `:invalid_iv`, `:invalid_tag`, `:decryption_failed`, `:entropy_failure`, `:deadline_exceeded`, `:nesting_depth`, `:content_type_mismatch`, `:unexpected_member`, `:protected_mismatch`, `:internal_failure`, `:issued_for_mismatch`.

### RequestSeal.Custody.Error

`:invalid_handle`, `:invalid_options`, `:unsupported_algorithm`, `:unsupported_operation`, `:invalid_key`, `:key_mismatch`, `:invalid_data`, `:invalid_signature`, `:unsupported_format`, `:invalid_signing_output`, `:no_public_key`, `:key_not_found`, `:unavailable`, `:deadline_exceeded`, `:custodian_unavailable`, `:custodian_rejected`, `:custodian_protocol`, `:custodian_failure`, `:decryption_failed`, `:limit`, `:gate_coverage`, `:gate_denied`, `:gate_malformed_base`, `:gate_mismatch`, `:gate_spent`, `:gate_store_failed`, `:gate_unavailable`, `:gate_unrecorded`, `:gate_window`, `:issued_for_mismatch`.

### RequestSeal.Replay.Error

`:invalid_store`, `:invalid_claim`, `:invalid_options`, `:store_unavailable`, `:store_timeout`, `:store_full`, `:store_failed`.

### RequestSeal.Discovery.Error

`:invalid_source`, `:invalid_options`, `:domain_not_found`, `:transport_unavailable`, `:resolution_failed`, `:address_denied`, `:connect_failed`, `:tls_failed`, `:deadline_exceeded`, `:redirect_denied`, `:redirect_limit`, `:unexpected_status`, `:unexpected_media_type`, `:limit`, `:invalid_response`, `:invalid_key_set`, `:client_id_mismatch`, `:ambiguous_key_source`, `:directory_unsigned`, `:directory_signature_invalid`, `:unknown_key`, `:revoked_key`, `:source_unavailable`, `:cache_overloaded`.

### RequestSeal.Digest.Error

`:body_unavailable`, `:conflicting_digest`, `:invalid_body`, `:invalid_chunk`, `:invalid_digest_length`, `:invalid_field`, `:invalid_kind`, `:invalid_message`, `:invalid_options`, `:invalid_preference`, `:invalid_state`, `:limit`, `:mismatch`, `:representation_required`, `:uncomputed_algorithm`, `:unsupported_algorithm`.

### RequestSeal.Message.Error

`:invalid_body`, `:invalid_field`, `:invalid_message`, `:invalid_transport`.

### RequestSeal.Adapter.Error

`:invalid_options`, `:invalid_request`, `:not_final_step`, `:cross_origin_redirect`, `:unsupported_delivery`, `:unsupported_component`, `:body_unavailable`, `:digest_conflict`, `:limit`, `:signing_failed`, `:transport_failed`, `:response_rejected`, `:not_captured`, `:already_verified`, `:parser_order`, `:untrusted_proxy`, `:request_rejected`, `:already_scoped`, `:ambiguous_path`, `:body_uninspected`, `:invalid_query`, `:invalid_scope`, `:path_not_covered`, `:path_rewritten`, `:scope_in_body`, `:scope_in_header`, `:scope_in_query`, `:template_mismatch`, `:tenant_lookup_timeout`, `:tenant_mismatch`, `:unverified`.

### RequestSeal.Crypto.Error

`:invalid_data`, `:invalid_key`, `:invalid_options`, `:invalid_signature`, `:key_mismatch`, `:unsupported_algorithm`, `:unsupported_format`.

### RequestSeal.StructuredFields.Error

`:duplicate_key`, `:duplicate_parameter`, `:invalid_field`, `:invalid_limits`, `:invalid_message`, `:invalid_schema`, `:invalid_value`, `:limit`, `:missing_field`, `:revision_type`, `:schema_type`, `:syntax`, `:unavailable_section`.
