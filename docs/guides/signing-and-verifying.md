<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Sign and verify HTTP messages

**What you will build:** A signed request, an explicit verification policy, and a quorum that requires your sender's signature. Prerequisite: RequestSeal installed; no framework or network is needed. These examples use locally generated keys and [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) with [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) body integrity.

## 1. Generate an example key

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
```

Reuse the handle in a long-lived owner in your application; see [key custody](key-custody.md). Trust the public key through configuration, not a message-supplied key ID.

## 2. Build the request

```elixir
{:ok, message} = RequestSeal.Message.request("POST", "https://api.example.com/webhooks", [], ~s({"event":"created"}), digest: ["sha-256"])
```

The builder preserves header order, repeats, case, explicit ports, percent escapes,
and query bytes. `nil` and `""` both retain empty content. Its optional `digest:`
adds Content-Digest over those exact bytes. Transport declarations remain unknown
and trailers unavailable; it does not establish a connection. Invalid values
return `RequestSeal.Message.Error` through the same validation as `Message.new/1`.
Bodies use `Body.new/1`'s 1 MiB retention limit. Existing digest headers reject
when generating a digest; omit `digest:` to preserve them.

For a response, retain its exact body and optionally link the request:

```elixir
{:ok, response} = RequestSeal.Message.response(200, [{"content-type", "text/plain"}], "accepted", request: message, digest: ["sha-256"])
```

The linked request supplies components selected with `req`; no request is inferred.

## 3. Choose acceptance rules

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

All six choices are required: algorithms, components, key resolver, freshness, content, and replay. `extra_components: :reject` requires exactly your selected coverage; the default allows additional coverage. A representation digest needs an explicitly selected complete representation; a content body does not substitute. For streams, feed `Digest.init/3` and `update/2` through EOF, then pass `digest_state:`.

## 4. Sign and verify

```elixir
signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: ~s[("@method" "@authority" "@path" "content-digest")],
  parameters: %{created: true, expires_in: 60, nonce: :random, alg: true, keyid: "demo-key", tag: nil},
  digest: ["sha-256"],
  field_schemas: %{}
}
{:ok, signed} = RequestSeal.sign(message, signing, handle)
```

This is the same six-key spec accepted by Req and Finch. All six parameter keys
are explicit. The signer's `clock:` defaults to system seconds; `created: true`
records it, and `expires_in: 60` adds 60 seconds. `nonce: :random` generates 32
CSPRNG bytes encoded as unpadded Base64url. `alg: true` records the selected HTTP
algorithm; JWS algorithms require `alg: false`. Nil `keyid`, `tag`, expiration,
or nonce omit that parameter. The shared pipeline adds or checks Content-Digest
and supplies covered Content-Length only over retained bytes. Existing conflicting
digests reject. It refuses `host` and trailer components; cover `@authority`
instead. Responses can cover related-request components.

Spec signing accepts a custody handle or an arity-two signer `(algorithm, base)`.
Both use monitored custody workers; `signing_timeout:` defaults to 5,000 ms and
accepts 1–300,000 ms. Optional `nonce:` supplies caller-owned 32-byte entropy
instead of generating it; callers must provide fresh entropy for each signing
attempt. It is ignored when the spec omits nonce. Unknown or duplicate options,
callback faults, malformed results, and reused labels reject with bounded
`RequestSeal.Error` values.

```elixir
{:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
verification.signature.crypto
# => :valid
verification.authorization
# => :not_evaluated
```

The label selects exactly one signature. Policy still requires all six acceptance
choices; construction and signing do not select verification or authorization rules.

## 5. Require a signer with a quorum

```elixir
{:ok, quorum} =
  RequestSeal.Quorum.new(%{
    mode: :all,
    unit: :key,
    unexpected: :reject,
    invalid: :reject,
    slots: [%{id: :sender, label: "sig", required: true, policy: policy}]
  })

{:ok, result} = RequestSeal.verify_quorum(signed, quorum, [])
result.count
# => 1
result.satisfied
# => [:sender]
```

Choose `:all`, `:any`, or `{:threshold, n}` and count distinct keys, caller-bound principals, or roles. Each assigned signature independently meets its complete policy; coverage is never pooled. Counting bindings establish no identity attribution. Required replay and representation digests reject in quorum policies; required content digests need retained bytes.

## Build messages by hand

Use `Message.new/1` for other target forms, separate trailers, body availability,
retention bounds, provenance, or transport declarations. This path preserves every
caller-supplied value and runs the same validation as the builders. Compute a
content digest explicitly when needed:

```elixir
{:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"event":"created"})})
{:ok, digest} = RequestSeal.Digest.compute(body, ["sha-256"])
{:ok, digest_wire} = RequestSeal.Digest.serialize(digest)

{:ok, digest_field} =
  RequestSeal.FieldOccurrence.new(%{
    name: "content-digest",
    value: digest_wire,
    section: :headers
  })
```

Supply the fields and authoritative origin without inferring them from headers:

```elixir
{:ok, transport} = RequestSeal.TransportFacts.new(%{})

{:ok, message} =
  RequestSeal.Message.new(%{
    kind: :request,
    method: "POST",
    raw_target: "/webhooks",
    target_form: :origin,
    scheme: "https",
    authority: "api.example.com",
    fields: [digest_field],
    trailers: :unavailable,
    body: body,
    transport: transport
  })
```

For exact signature metadata, the original `sign/4` contract remains available.
It accepts a serialized Inner List or `StructuredFields.Value` and appends the
signature fields without generating parameters. This example intentionally omits
freshness; the earlier freshness policy would reject it:

```elixir
{:ok, low_level_signed} = RequestSeal.sign(message, %{
  label: "manual", algorithm: "ed25519",
  signature_input: ~s[("@method" "@authority" "@path" "content-digest");alg="ed25519";keyid="demo-key"]
}, signer, field_schemas: %{})
```

The explicit-input path retains its synchronous callback contract; callers bound
external work themselves or delegate to custody. Use the spec path for generated
parameters and bounded signer execution.

## Read the result

`RequestSeal.Verification` reports the selected label, profile, covered identifiers, authoritative algorithm, signature parameters, digest checks, freshness checks, and replay receipt. Generic results have `principal: :unattributed` and `authorization: :not_evaluated`. A cryptographically valid shared-secret signature also supplies no identity attribution. Do not log parameters or key IDs; default inspection hides them.

`RequestSeal.Quorum.Verification.signatures` maps assigned labels to those results. `qualifying` records assigned slots and caller counting bindings; `count` counts distinct configured units. `required` lists required slots and `satisfied` includes assigned optional slots. Negotiation checks the verified eligible pool: a valid `Accept-Signature` challenge can be fulfilled without being assigned or appearing in the result map. Nested bindings require both inner signature dictionary members; equal-parameter bindings require the same non-nil value. See `RequestSeal.AcceptSignature` and `RequestSeal.Quorum` for negotiation and assignment limits.

## Errors and next steps

| Reason | Meaning and action |
| --- | --- |
| `:invalid_policy` | Supply all six valid policy choices. |
| `:unknown_key` | Configure a trusted resolver entry for this key ID. |
| `:missing_required_component` | Require the sender to cover the needed identifier and parameters. |
| `:invalid_signature` | Reject: signed bytes or the selected key differ. |
| `:digest_mismatch` | Reject: body bytes differ from the signed digest. |
| `:expired` | Reject: the expiration is exclusive; check your clocks and validity window. |
| `:quorum_not_met` | The required slots or distinct counting units are not satisfied. |

See [the public contract](../design/architecture.md) for the separate representation, construction, cryptography, profile, trust, integrity, and replay layers. Named application profiles use `RequestSeal.Profile` in extension packages; this extension surface is unstable, so pin RequestSeal exactly. Extensions must enforce their source-specific rules and trusted attribution; a profile stamp alone is no proof.

Module docs: `RequestSeal`, `RequestSeal.Message`, `RequestSeal.SignatureBase`, `RequestSeal.Policy`, `RequestSeal.Verification`, `RequestSeal.Quorum`, `RequestSeal.Quorum.Verification`, `RequestSeal.Digest`, `RequestSeal.Profile`, `RequestSeal.Error`. [Testing](testing.md) distinguishes published vectors, local round trips, independent verifiers, and deployed-peer acceptance. Proposed contracts in design pages do not establish implemented capability.
