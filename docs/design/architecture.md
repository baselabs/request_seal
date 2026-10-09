<!-- Status: current · Kind: design · Updated: 2026-10-08 · Governed by: accepted ADRs 0001–0011 and 0013 · Review when: a supported standard, profile, public contract, or trust boundary changes -->

# RequestSeal architecture


RequestSeal is one framework-independent, Elixir-only library for signing and verifying HTTP messages and generic compact JOSE, with Web Bot Auth protocol-00 and an explicit named-profile extension surface. The TypeScript counterpart is deferred, not planned for the current release. The lossless message value model (the Message/occurrence/body/transport portion of
ADR 0002) is implemented by `RequestSeal.Message`, `FieldOccurrence`,
`Body`, and `TransportFacts`; their module documentation is the API reference.
Structured Fields parsing, serialization, and explicit type schemas are implemented
by `RequestSeal.StructuredFields`; its module documentation defines limits and errors.
RFC 9421 signature-base construction is implemented by `RequestSeal.SignatureBase`;
its module documentation defines component rules, input forms, limits, and errors.
Generic single-label RFC 9421 signing and verification are implemented by
`RequestSeal` with explicit `RequestSeal.Policy`; their module documentation defines
the current API. Composite verification and signature negotiation are implemented by
`RequestSeal.Quorum`, `RequestSeal.verify_quorum/3`, and `RequestSeal.AcceptSignature`.
Caller-owned custody, bounded discovery, nonce replay, optional Req/Finch and
Plug/Phoenix adapters, Ash scope mapping, generic compact JWS/JWE, and one-level
JWS-in-JWE nesting are implemented.
Web Bot Auth protocol-00 signing and verification are implemented by
`RequestSeal.WebBotAuth`, composing explicit trust, discovery, nested coverage,
and one whole-envelope replay claim.
Body sinks/spools and reverse-proxy adapters remain **proposed public shapes**.

## Architectural contract

The library owns five pieces of knowledge:

1. Lossless HTTP message representation and RFC 9421 signature-base construction.
2. RFC 9651 Structured Fields parsing/serialization under the field schema each standard actually references.
3. Explicit policies for generic RFC 9421 and the named Web Bot Auth draft, with a bounded extension surface for application profiles.
4. A layered verification result that separates valid cryptography, authenticated principal, content integrity, freshness/replay, and caller authorization.
5. Independently sourced vector fixtures exercised by Elixir tests; the portable conformance corpus and its cross-language format remain designs for later use.

It does not own an application server, general-purpose HTTP client or connection pool, global key store, replay database, identity provider, authorization engine, or payment execution. The optional discovery adapter implements bounded HTTP/1.1 GET over caller-started OTP TLS under explicit source policy; its cache is caller-started. Importing the package starts no process and performs no network or storage operation. Optional adapters translate those boundaries without moving their policy into the core.

```text
Req / Finch / Plug / Phoenix / Ash / reverse proxy
                         │ lossless adapter contract
                         ▼
              Profiles and policy evaluation
    RFC 9421 │ WBA draft │ explicit application extensions
                         │
            Verification result and signed output
                         │
        HTTP wire model · Structured Fields · digest
                         │
             crypto / key / discovery / replay ports
                         │
       caller-owned handles and optional concrete adapters
```

The deletion test keeps these boundaries honest. Deleting the lossless HTTP layer makes every adapter relearn component derivation, duplicate-field ordering, raw-target preservation, trailer timing, and response/request association. Deleting profiles makes every caller relearn externally owned policy. Deleting the boundary ports forces network, custody, and storage into pure protocol code. Conversely, a pass-through module that only renames an OTP or framework call fails the test and must be inlined into its owning adapter.

## Generic JOSE contracts

Generic compact JWS/JWE and one-level JWS-in-JWE nesting are implemented by
`RequestSeal.JOSE.JWS`, `RequestSeal.JOSE.JWE`, and `RequestSeal.JOSE.Nested`.
Their module documentation defines per-call algorithm pinning, protected-byte
preservation, bounded inputs, caller-owned key callbacks, and explicit-access
results. Published vectors and reciprocal Node WebCrypto/OpenSSL checks exercise
these generic contracts. Node WebCrypto is an independent verifier for tests,
not a TypeScript product.

JWS/JWE serialization stays separate from RFC 9421 signature bases and Structured
Fields. Shared custody, exact final-body ownership, resource limits, and safe
results do not imply a common wire format or application trust. Authenticated
decryption establishes recipient integrity; origin, identity, request association,
and authorization require independently selected caller policy.

## Public data model and authentication APIs

The lossless model preserves the following semantics. Its executable module documentation
defines constructor options, validation, limits, and errors. Generic single-label
signing and verification are implemented with the following signatures:

```elixir
# Implemented message model and generic single-label API.
@type message :: %RequestSeal.Message{
  kind: :request | :response,
  method: binary() | nil,
  raw_target: binary() | nil,
  target_form: :origin | :absolute | :authority | :asterisk | nil,
  scheme: binary() | nil,
  authority: binary() | nil,
  status: 100..599 | nil,
  fields: [RequestSeal.FieldOccurrence.t()],
  trailers: [RequestSeal.FieldOccurrence.t()] | :pending | :unavailable,
  body: RequestSeal.Body.t(),
  related_request: RequestSeal.Message.t() | nil,
  transport: RequestSeal.TransportFacts.t()
}

@type signature_spec :: %{
  label: binary(),
  signature_input: binary() | RequestSeal.StructuredFields.Value.t(),
  algorithm: RequestSeal.Crypto.algorithm()
}

@spec RequestSeal.sign(RequestSeal.Message.t(), signature_spec(), RequestSeal.Policy.signer(), keyword()) ::
        {:ok, RequestSeal.Message.t()} | {:error, RequestSeal.Error.t()}

@spec RequestSeal.verify(RequestSeal.Message.t(), RequestSeal.Policy.t(), keyword()) ::
        {:ok, RequestSeal.Verification.t()} | {:error, RequestSeal.Error.t()}
```

`RequestSeal.verify/3` requires an explicit `RequestSeal.Policy` and a `:label`
option selecting exactly one signature. `RequestSeal.Policy.new/1` requires
algorithms, components, key resolver, freshness, content, and replay choices;
replay is explicitly `:not_required` or a bounded nonce/namespace/commitment/store policy. The explicit-input form of `RequestSeal.sign/4` accepts one
specification map with exactly `:label`, `:signature_input`, and `:algorithm`.
Its arity-two signer receives `(algorithm, base)` and returns
`{:ok, signature_bytes}` or `{:error, term}`. The signature input is a serialized
Inner List or a `RequestSeal.StructuredFields.Value`. Signing returns the message
with appended `Signature-Input` and `Signature` header occurrences. Options
default to `[]`, also exposing `sign/3`; `:field_schemas` is its only option.
Both APIs return bounded `RequestSeal.Error` values on rejection.

`Message.request/5` and `Message.response/4` build validated messages from
ordered header tuples and exact retained body bytes. Optional `digest:` adds
Content-Digest without re-encoding. `RequestSeal.sign/4` also accepts the six-key
`t:RequestSeal.signing_spec/0` used by Req and Finch, through one shared internal
pipeline. It generates explicit metadata with a caller clock and optional
caller-owned nonce entropy, and accepts an opaque custody handle or function
with bounded execution. The original explicit-input contract remains unchanged.

Composite verification returns `RequestSeal.Quorum.Verification`, including plural
`signatures`, the qualifying label/slot set, counting facts, bindings, and negotiation:

```elixir
# Implemented composite verification API.
@spec RequestSeal.verify_quorum(RequestSeal.Message.t(), RequestSeal.Quorum.t(), keyword()) ::
        {:ok, RequestSeal.Quorum.Verification.t()} | {:error, RequestSeal.Error.t()}
```

Spec-list signing and `SignedMessage` remain **proposed extensions**. Current signing
accepts one specification and a caller function, which may delegate exact bytes to
`RequestSeal.Custody.sign/3` with an opaque handle; verification resolves public keys
or caller-owned verification functions through `Policy.key_resolver`.

```elixir
# PROPOSED EXTENSION — current sign/4 accepts one specification.
@spec RequestSeal.sign(RequestSeal.Message.t(), [signature_spec()], RequestSeal.Policy.signer(), keyword()) ::
        {:ok, RequestSeal.SignedMessage.t()} | {:error, RequestSeal.Error.t()}
```

`FieldOccurrence` preserves one field name and raw value; ordered occurrence lists retain repeats, source section (`:headers` or `:trailers`), and adapter provenance. It never collapses duplicates into a map. `Body` distinguishes bytes already retained, a one-pass stream, consumed content, and an unavailable body. A stream handle can remain unread after transport completes; known trailers do not imply body consumption. `RequestSeal.Digest` implements bounded caller-fed incremental hashing without promising replayability. Single-label verification accepts `:digest_state` at caller-established EOF and never reads a stream handle. The Req adapter bounds retained response chunks and withholds delivery until verification succeeds; Finch exposes caller-fed digest verification. Plug capture retains bounded request bytes before downstream parsing and replays them through Plug readers. Generic body sinks/spools and returned body-disposition facts remain proposed: a caller-selected retained-body sink or spool would preserve bytes before downstream parsing. Required content checks fail before replay consumption when the needed body or digest state is unavailable. `transport` records only enumerated HTTP-version and TLS declarations with `evidence: :declared`. Authoritative scheme and authority belong to the Message, selected by caller policy; forwarded headers never supply them implicitly.

Parsed `RequestSeal.StructuredFields.Value` parameters preserve order and exact typed values; verification exposes decoded parameters in its result. Implemented RFC 9421 signature-base components include all nine derived components plus field components and the `sf`, `key`, `bs`, `tr`, `req`, and `@query-param`'s required `name` parameters. Requests, responses, related-request context, and trailers are implemented. `RequestSeal.AcceptSignature` implements signature requests, fulfillment, and challenge matching; `RequestSeal.Quorum` declares explicit signer slots and composite counting/binding policies. Caller counting bindings establish no authenticated attribution; required replay remains a separate contract. The implemented HTTP algorithm registry covers `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, and `ed25519`. RFC 9421's JWS-algorithm extension follows a separate explicit registry mapping. Algorithm identifiers remain exact wire tokens; HTTP, JOSE, and case variants never share implicit normalization.

## Algorithm and digest fidelity

The implemented `RequestSeal.Crypto` boundary fixes wire encodings independently of runtime defaults.
[RFC 9421 Section 3.3](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3)
requires P-256/P-384 ECDSA signatures as fixed-width `r || s` (64/96 bytes), and
RSA-PSS SHA-512 with MGF1 SHA-512 and a 64-byte salt for signing and verification.
Translate ECDSA to/from the runtime representation at that boundary. Reject malformed
integers, widths, and algorithm/key mismatches. HMAC verification uses a constant-time
comparison inside the custodian, such as OTP's
[`crypto:hash_equals/2`](https://www.erlang.org/doc/apps/crypto/crypto.html#hash_equals/2).
No runtime default substitutes for the selected algorithm contract.

The implemented generic authentication digest policy permits `sha-256` and `sha-512`.
Weak, unknown, or unselected algorithms cannot satisfy integrity policy. A profile
may eventually select both fields; the implemented policy selects either
`Content-Digest` or `Repr-Digest`, its algorithms, and its header or trailer section
explicitly, and requires complete signature coverage. Those fields never substitute
for one another. Hash the exact
content or representation each field defines, including content encoding and range/HEAD
semantics. A digest observed without the required coverage is not authenticated integrity.

## Protocol and profile ownership

The protocol core accepts no implicit default profile. A generic RFC 9421 policy must still state its required components, permitted algorithms, key resolver, freshness, replay, and content-digest rules because RFC 9421 assigns those choices to applications. A valid signature establishes only that the selected key signed the reconstructed base.

Named profiles are immutable source-bound definitions:

| Profile | Source identity | Required distinction |
| --- | --- | --- |
| Generic HTTP Message Signatures | [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), [IANA registry](https://www.iana.org/assignments/http-message-signature) | Caller-supplied application policy; no authentication claim from generic validity alone. |
| Web Bot Auth draft | [`draft-ietf-webbotauth-httpsig-protocol-00`](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00) | Dictionary-member `Signature-Agent`, thumbprint key IDs, tag, signed discovery and nested signatures. |

There is no permissive fallback from one profile to another. Source revision
selection is explicit in configuration and result data. Web Bot Auth accepts
only the selected draft's field representation and predicates.
[ADR 0003](../adr/0003-source-bound-profiles.md) defines source-bound acceptance.
[ADR 0013](../adr/0013-extension-profile-boundary.md) defines the unstable
`RequestSeal.Profile` extension surface: package-namespaced names, bounded
metadata, explicit verification predicates, and consumer allowlists. A profile
stamp records selection, not proof that an extension's rules ran.

## Multiple-signature policy

The caller selects `all`, `any`, or an explicit threshold over trusted eligible signers.
Every mode fills every required slot and at least one qualifying signature; `all`
requires at least one required slot. Each assigned label and merged identity class
occupies at most one slot. Observations of the same label merge known identities
and any unknown observation; unknown observations share one pool. Assignment
maximizes the configured counting units, then filled slots, in canonical order.
Unbound key, principal, and shared-principal role units use polynomial matching;
other assignments use exact search bounded to 131,072 nodes. On exhaustion, a
best-so-far assignment succeeds only if its mode, required slots, and bindings hold;
otherwise verification returns `:limit` at `:input`. Output lists retain configured
slot order. Unexpected and invalid labels follow explicit rejection/ignore policy.
Optional additions can reduce capacity when new evidence bridges identity classes.
Each assigned result retains its single-label verification facts; caller counting
bindings establish no attribution.

A threshold declares its counting unit: distinct trusted principals, distinct cryptographic keys, or required roles. Labels never count. Key identity is algorithm appropriate and trusted, never an attacker-provided `keyid` alias. Asymmetric keys use canonical public components. HMAC accepts an opaque nonsecret key-equivalence identity supplied by the custodian; RequestSeal never derives it. Within the declared trust scope, aliases and imports of the same secret must resolve to one identity. Per-handle IDs alone are insufficient. If equivalence or distinctness cannot be established across custodians, a key-distinct threshold rejects; the caller may instead explicitly select an adequately trusted principal/role policy. Secret bytes and key-equivalence identifiers never appear in general results or diagnostics. Principal thresholds deduplicate all keys and rotations mapped to the same trusted principal. Key thresholds explicitly permit separate authorized keys of one principal to count, while aliases of one key still count once. Role thresholds use caller-owned role bindings and state whether one principal may satisfy multiple roles; `shared_principal: false` requires distinct principals for distinct required roles. Slots without explicit trusted caller principal/role bindings cannot satisfy those counting policies; single-label results remain unattributed. Unknown counting units or ambiguous bindings reject policy construction.

A nested binding requires the outer signature to cover both the inner label's `"signature-input";key="<inner-label>"` and `"signature";key="<inner-label>"` dictionary members. Repeated labels and parameter names reject in signature verification and Accept-Signature parsing; generic Structured Fields parsing retains its RFC last-value behavior. Optional unknown key identities do not count in key-unit quorums; required slots whose only candidates have unknown identity reject with `:ambiguous_key_identity`.

Each qualifying signature independently covers every component required for its signer/role and its explicit linked-signature bindings. There is no implicit component-union acceptance: two insufficient signatures cannot complete each other's coverage. Explicit composite policies enumerate every role-to-component obligation and cross-signature binding and return those facts individually. The accepted result does not manufacture a single principal from unrelated signers. Quorum verification requires `replay: :not_required` in every slot and rejects required replay before callbacks run. It accepts only retained-body Content-Digest policies; representation digests and caller-fed digest state are rejected. Single-label and Web Bot Auth replay use the caller commitment contract below.

Acceptance includes duplicated labels, aliased key IDs, HMAC aliases/imports of the same secret, distinct HMAC identities and unknown cross-custodian equivalence, rotated keys of one principal, multiple roles, partial-coverage unions, mixed trust, and optional-signature addition/removal/reordering under `any` and threshold policies. Quorum tests assert the assigned signer set, counting units, bindings, negotiation, and rejection of required replay as well as the final decision.

## Keys, discovery, and replay

Private key material never enters a general message or result structure. A `KeyHandle` is an opaque caller value understood only by the selected signing, verification, or key-unwrapping custodian. The generic signer callback returns signature bytes, never a secret. Custody exposes public metadata through separate operations. Asymmetric verification resolves public key material; symmetric HMAC verification resolves an arity-three verification function that can invoke an opaque custody handle, keeping the secret inside its custodian. HMAC proves shared-secret possession, not a unique signer or public verifiability. Generic policy resolution supplies an authoritative algorithm and public key or verification function, with optional trusted key-equivalence identity. `Discovery.Resolution` separately exposes source type, location, origin, fetched-at time, expiry, revision, and possession-proof status. The generic resolver bridge returns only algorithm and key; Web Bot Auth applies explicit caller trust before recording an agent association and provenance.

`RequestSeal.Custody` implements a cancellation- and deadline-aware contract for opaque, algorithm-bound `KeyHandle` values. `Custody.Local` holds OTP signing and RSA-OAEP recipient descriptors in sensitive per-handle processes, imports unencrypted private PEM/PKCS #8 DER/JWK, and verifies HMAC within custody. Unwrap-only handles bind exactly one RSA-OAEP algorithm; JWE resolvers can return them so private RSA decryption stays in the sensitive holder; the CEK passes through the sensitive custody runner and middle process to the sensitive JWE worker for content authentication. JWE's outer middle process and the decrypt caller receive only the authenticated result. Direct unwrap callers receive unwrapped bytes and own their protection. OAEP rejection retains random-CEK fallback and the same complete error as GCM authentication failure. `Custody.SSHAgent` optionally signs through an explicit caller-owned OpenSSH agent socket, selects exact public components, and verifies every returned signature before release. Operations run in monitored workers; deadline expiry or caller death terminates the worker and closes its connections. Local handles reference only the holder PID and token. The holder monitors its creator and exits on creator death or explicit `Local.release/1`; stopped holders return `:key_not_found`. Private state is excluded from handle serialization, function environments, process inspection, and system introspection. Symmetric equivalence is a caller-supplied nonsecret value or remains unknown. These operations establish mathematical validity only; additional KMS/HSM custodians implement the same contract. Discovery is an explicit caller-configured adapter with HTTPS requirements, redirect policy, address/range restrictions, response and decompression limits, key-count limits, bounded caches, and rotation/removal semantics. `Discovery.Source` is caller-configured; a signature key ID never selects a URL. `Discovery.fetch/2` performs a bounded fetch only on explicit invocation, with SSL started by the caller. The generic resolver accepts a snapshot or caller-started cache/source pair. Cache refresh, removal, and invalidation are explicit, with no background timers or stale-key fallback. IDs default to RFC thumbprints; JWKS/CIMD may select directory-assigned IDs while retaining thumbprints for revocation and removal. Directory sources require thumbprint IDs. Freshness honors HTTP cache directives and key/proof expiry; CIMD failures are not negatively cached.

Replay protection is an optional but profile-required port where applicable. The caller supplies a bounded commitment function binding a verified nonce, challenge, or transaction identifier to a caller-defined scope. RequestSeal does not derive this commitment. The store exposes one atomic operation over its result:

```elixir
# Implemented RequestSeal.Replay callback.
@callback claim(term(), RequestSeal.Replay.Claim.t(), RequestSeal.Custody.Context.t()) ::
  :claimed | :already_claimed | {:error, :unavailable | :timeout | :full | :failure}
```

[ADR 0005](../adr/0005-atomic-replay-envelope.md) is the canonical replay contract.
The selected profile validates its required replay identifier. Only after validation
does the caller commitment function receive the authenticated facts; missing or
ambiguous required inputs fail closed. Retention metadata does not alter its result.
The generic profile selects the authenticated nonce parameter. Required replay uses
bounded freshness, one shared commitment/store deadline, and caller cancellation.
ETS is caller-supervised and local; Postgres uses a caller connection and explicit DDL.
Claims never evict, and explicit sweeps delete only at the exclusive retention end.
Expiration is exclusive; max-age is inclusive. Thus retention ends at the minimum
of `expires + skew` and `created + max_age + skew + 1`, over present bounds.
Validate the complete envelope and body before one atomic claim. Missing or failed required storage rejects authentication.
Direct and framework construction paths preserve that same identity. Actual backend
concurrency evidence establishes the advertised store guarantee.


## Layered verification and authorization boundary

The implemented `RequestSeal.Verification` is returned only after every required
policy layer succeeds and contains one explicitly selected label:

| Layer | Meaning |
| --- | --- |
| `label` | The explicitly selected signature label. |
| `signature` | Authoritative resolver algorithm, canonical ordered covered identifiers including parameters, decoded signature parameters, optional keyid, and `crypto: :valid`; no signature bytes, base bytes, or keys. |
| `profile` | Generic `%{name: :rfc9421}`, Web Bot Auth name and exact draft revision, or a package-namespaced `{package, kind}` name via `RequestSeal.Profile`. |
| `content` | `:not_required` or digest facts: `kind`, `checked`, `bytes`, and `unsupported`. |
| `freshness` | `:not_evaluated` or `now`, `created`, `expires`, `max_age`, and `skew`. |
| `replay` | `:not_required` or `RequestSeal.Replay.Receipt` after one atomic claim. |
| `principal` | Generic `:unattributed`, or a Web Bot Auth agent association from a trusted source or held-key thumbprint. |
| `authorization` | Always `:not_evaluated` in RequestSeal. |

`RequestSeal.Quorum.Verification` implements a plural label-keyed `signatures` map,
the assigned `qualifying` label/slot list, configured counting unit, required slot IDs,
all satisfied slot IDs (including optional slots), deduplicated count,
nonqualifying reasons, bindings, and negotiation. Each qualifying signature retains
its own single-label verification facts. Caller principal/role counting bindings do
not establish attribution; quorum replay stays `:not_required`. Negotiation checks
the verified eligible pool, so fulfilled challenges need not appear in assigned
`signatures`. Inspection exposes slot IDs and counts, but omits signature labels
and metadata.
`RequestSeal.WebBotAuth.Verification` maps independently validated labels to
these per-signature facts, records nested coverage evidence, and claims replay
once after every selected signature succeeds. A directory agent identifier is
the resolved well-known URL; origin remains a separate principal field. Other
named application profiles compose the implemented extension surface in separate
packages; the generic and Web Bot Auth APIs use nonce. A policy rejection returns an error without a partial verification
value. `RequestSeal.Ash.scope/2` maps successful verification through explicit
caller actor/tenant bindings into bounded context and an authorization-enabled scope.
Unattributed results require an explicit anonymous or rejection choice;
caller authorization remains outside RequestSeal.

## Adapters

- **Req:** signs after final URI/header/body transformations; every retry regenerates selected time/nonce parameters and re-signs; redirects require explicit cross-origin policy; response verification retains the associated request.
- **Finch:** translates a finalized Finch request/response without starting a pool. Caller supervision and transport remain outside RequestSeal.
- **Plug/Phoenix:** captures ordered headers and bounded request bytes before parsers; replays retained bytes through Plug readers; trusted external origin is explicit; verification facts go into private connection state; response signing runs after registered callbacks. Unavailable exact target or trailer evidence rejects required coverage. Pending response cookies reject `set-cookie` coverage, and later server transformations must be disabled when covering response bytes. See `RequestSeal.Plug` for supported components and delivery limits.
- **Ash:** maps successful verification through explicit caller actor/tenant bindings into bounded context and an authorization-enabled scope. Authorization stays in Ash policies and actions.
- **Reverse proxy (planned):** reconstructs external message facts only from an explicit trusted-proxy policy; raw ingress and reconstructed facts remain separately visible for diagnostics.

Each adapter must refuse when its framework cannot supply a required component faithfully. It cannot synthesize a plausible value and call the signature valid.

## Deferred TypeScript counterpart

RequestSeal is Elixir only. The TypeScript counterpart is deferred, not planned for the current release. The cross-language corpus format remains a design for later use. That design stores inputs, exact signature bases, outputs, rejection rule IDs, provenance, and externally owned source references; consumers must not generate their own expected values during a conformance run.

## Sources

Primary standards: [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html), [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html). These sources define mechanisms; the verification plan distinguishes reading them from executing conformance evidence.
