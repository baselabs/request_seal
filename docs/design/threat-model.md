# RequestSeal threat model

**Status:** current · **Kind:** design · **Updated:** 2026-10-08 · **Governed by:** architecture and ADRs 0002–0007 · **Review when:** a trust boundary, profile, adapter, data shape, or external effect changes

RequestSeal processes attacker-controlled wire data at an authentication boundary. Its primary security goal is to report exactly what was cryptographically established, by which trusted association, under which profile, without granting caller authorization or payment authority.

RequestSeal is Elixir only. The TypeScript counterpart is deferred, not planned for the current release; the cross-language corpus format remains a design for later use.

## Assets and trust boundaries

Assets are private signing authority, verified message bytes, content-integrity state, principal attribution, replay uniqueness, nested signature binding, and diagnostic confidentiality. Trust boundaries exist between wire input and the lossless model; model and profile; profile and key/discovery; verification and replay store; RequestSeal and each framework adapter; independent corpus data and the Elixir consumer; and authenticated principal and caller authorization.

The caller controls accepted profiles, trusted origins/proxies, trust anchors, discovery endpoints, key handles, clocks, replay adapter, resource limits, and authorization. An input message controls none of those merely by naming a key, URL, label, algorithm, tag, or identity.

## Security invariants

1. Verified means exact selected bytes validated under an explicitly selected source-bound profile.
2. A signature authenticates only its covered components. A signed digest field authenticates body content only after digest recomputation succeeds.
3. Key possession is not identity. Identity requires a trusted, profile-valid key association with provenance.
4. Authentication is not authorization. RequestSeal never permits an application action or payment.
5. Replay success requires one atomic claim over the complete authenticated-envelope namespace.
6. Private keys stay behind custody handles. No error, telemetry, inspection, or serialization path exports them.
7. Failed or incomplete verification never yields a partially trusted principal object that a caller can mistake for success.
8. Profile labels do not weaken rules. There is no generic or legacy fallback after a named-profile failure.

## Threats and controls

| Threat | Control | Required proof |
| --- | --- | --- |
| Canonicalization confusion | Preserve raw target, ordered field occurrences, trailers, parameter order, and ordered JSON occurrences; derive through one source-bound rule set. | Published vectors, mutation cases, and real adapter preservation. |
| Algorithm/key confusion | Exact algorithm identifiers; profile allowlist; key-type/use/operation checks; separate HTTP and JOSE mappings. | Every active IANA algorithm plus cross-algorithm and wrong-key tests. |
| Component omission | Profiles require coverage explicitly; results expose covered components; digest recomputation is independent. | Removal/substitution of every required component and body mutation. |
| Multi-signature substitution | Count explicitly selected distinct keys/principals/roles using trusted bindings; labels never count. Enforce each signer/role coverage independently; composite coverage requires explicit obligations and cross-bindings. | Duplicate labels/key aliases, key rotation, role overlap, mixed trust, partial-coverage union, nested/outer mismatch, optional-signature changes under any/threshold policies. |
| Replay race or poisoning | Validate signature/profile/linked objects before invoking the caller commitment function or atomic store. Bind the selected verified nonce, challenge, or transaction identifier to caller-defined scope; reject ambiguous required inputs and required callback/store failures. | Real concurrent backend race; same identifier through direct and every adapter constructor; caller-scope checks; callback error/cancellation; unauthenticated poison attempt. |
| Discovery SSRF | Caller-controlled allowlist; HTTPS; no automatic redirects; DNS/IP revalidation; private/link-local/loopback denial; response/decompression/key-count/time bounds. | Real controlled network probes for IPv4/IPv6, redirect, rebinding, oversized response, cancellation. |
| Stale/removed key acceptance | Source-bound cache expiry, fetched-at metadata, refresh semantics, explicit removed-key behavior, no stale resurrection. | Actual rotation/removal against the named discovery adapter. |
| Key exfiltration | Opaque handle; signer boundary; public-only serialization; redaction; no secret fields in inspection. | Real local and remote signer error pathways plus log/telemetry scan. |
| Forwarded-header spoofing | Explicit trusted-proxy policy and authoritative external origin; retain ingress and reconstructed facts. | Actual proxy route with trusted and untrusted hops. |
| Retry/redirect reuse | Req re-signs each final attempt and requires cross-origin policy; selected nonce/time parameters regenerate. Finch signs each explicit caller invocation; callers own its retry/redirect loop. Responses bind to the supplied request. | Actual redirect/retry flows, including cross-origin denial. |
| Parser/resource exhaustion | Bounded bytes, members, depth, signature/component/key counts, numeric magnitudes, deadlines, and streaming work. | Just-inside/outside bounds, fuzz corpus, timeout/cancel paths, measured resource receipts. |
| Error oracle/data leak | Stable bounded public reasons and redacted default inspection. Opt-in diagnostic redactors and a versioned telemetry contract remain proposed in ADR 0006. | Real negative paths with sensitive canaries absent from output. |
| Cross-profile replay | Domain-separate the trusted profile/security context in replay identity; no fallback. | Same nonce under generic, Web Bot Auth, and package-namespaced extension profiles; tag substitution rejection. |
| Corpus compromise | Immutable provenance, independent expected values, digest manifest, source review, and the Elixir consumer prohibited from regenerating expectations. | Tampered-case red proof in Elixir and manifest verification. |
| Supply-chain substitution | Exact development pins, locked dependencies, package content allowlist, advisory/license review, provenance/checksums, isolated notebook toolchain. CI actions use immutable commit SHAs; the PostgreSQL service uses the moving `postgres:18` tag, not a digest pin. | Fresh clone, package inspection, audit output, and consumer install on required platforms; the service tag does not establish immutable image identity. |

## Profile-specific hazards

Web Bot Auth discovery can turn a signed field into a network capability.
The selected draft permits multiple discovery types. Selection is configuration,
not content negotiation by an attacker. Directory signatures and requests use
their own profile rules; support for `req` in one does not imply support in the
other. Nested signatures must independently satisfy required coverage before
one whole-envelope replay claim.

## Generic JOSE threats

HTTP and JOSE use separate parsers and exact algorithm registries. Protected
headers and finalized ciphertext bytes remain exact. Decryption results withhold
plaintext until complete AEAD validation. Recipient integrity alone establishes
neither origin, identity, nor request association. Caller callbacks select keys
and application trust explicitly; generic JOSE cannot infer them from wire data.

## Failure behavior

Malformed or unsupported input returns a stable error before cryptographic work when safe. Verification continues only when needed to apply an explicit multi-signature policy; it never silently accepts the first convenient label. Required digest, discovery, clock, custody, replay, or related-request data that is unavailable fails closed for that profile.

Custody, discovery, JOSE callbacks, Web Bot Auth trust callbacks, and required replay
receive bounded deadlines and caller cancellation. Generic policy resolver, clock,
verification-function, and signer callbacks run synchronously in the calling process;
callers own their external-work deadlines or delegate to bounded custody/discovery
operations. A timeout is distinct from invalid cryptography and from policy rejection,
but none produces an authenticated principal. Replay errors are always nonretryable;
a timeout may have committed. Discovery classifies transient failures separately,
including retryable 5xx and nonretryable 4xx status failures. Callers own retry
scheduling and whether replaying the whole operation is safe. Errors retain no
attacker-controlled diagnostics.

## Residual boundaries

RequestSeal cannot establish that a caller's trust anchors, proxy configuration, authorization policy, payment decision, or external key-custody service are correct. It makes their inputs, provenance, and unevaluated state explicit so the caller cannot receive an accidental success signal. Actual assurance for a configured adapter comes from the real-substrate receipts in the verification design, not from the existence of the interface.
