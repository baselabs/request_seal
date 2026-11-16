# RequestSeal threat model

RequestSeal processes attacker-controlled wire data at an authentication boundary. Its primary security goal is to report exactly what was cryptographically established, by which trusted association, under which profile, without granting caller authorization or payment authority.

RequestSeal and its [TypeScript counterpart](architecture.md#typescript-counterpart-and-conformance) share the independently sourced conformance corpus and its digest and cardinality checks.

## Assets and trust boundaries

Assets are private signing authority, private recipient keys, verified message bytes, content-integrity state, principal attribution, replay uniqueness, nested signature binding, and diagnostic confidentiality. Trust boundaries exist between wire input and the lossless model; model and profile; profile and key/discovery; verification and replay store; RequestSeal and each framework adapter; independent corpus data and the Elixir consumer; and authenticated principal and caller authorization.

The caller controls accepted profiles, trusted origins/proxies, trust anchors, discovery endpoints, key handles, clocks, replay adapter, resource limits, and authorization. An input message controls none of those merely by naming a key, URL, label, algorithm, tag, or identity.

## Security invariants

1. Verified means exact selected bytes validated under an explicitly selected source-bound profile.
2. A signature authenticates only its covered components. A signed digest field authenticates body content only after digest recomputation succeeds.
3. Key possession is not identity. Identity requires a trusted, profile-valid key association with provenance.
4. Authentication is not authorization. RequestSeal never permits an application action or payment.
5. Replay success requires one atomic claim, under the caller's namespace, over covered values of exactly one verified signature; uncovered values such as labels never enter a claim.
6. Private keys stay behind custody handles. No error, telemetry, inspection, or serialization path exports them.
7. Failed or incomplete verification never yields a partially trusted principal object that a caller can mistake for success.
8. Profile labels do not weaken rules. There is no generic or legacy fallback after a named-profile failure.

## Threats and controls

| Threat | Control | Required proof |
| --- | --- | --- |
| Canonicalization confusion | Preserve raw target, ordered field occurrences, trailers, parameter order, and ordered JSON occurrences; derive through one source-bound rule set. | Published vectors, mutation cases, and real adapter preservation. |
| Algorithm/key confusion | Exact algorithm identifiers; profile allowlist; key-type/use/operation checks; separate HTTP and JOSE mappings. | Every active IANA algorithm plus cross-algorithm and wrong-key tests. |
| Component omission | Profiles require coverage explicitly; results expose covered components; digest recomputation is independent. | Removal/substitution of every required component and body mutation. |
| Replay race or poisoning | Validate signature/profile/linked objects before invoking the caller commitment function or atomic store. Bind the selected verified nonce, challenge, or transaction identifier to caller-defined scope; reject ambiguous required inputs and required callback/store failures. | Real concurrent backend race; same identifier through direct and every adapter constructor; caller-scope checks; callback error/cancellation; unauthenticated poison attempt. |
| Discovery SSRF | Caller-controlled allowlist; HTTPS; no automatic redirects; DNS/IP revalidation; private/link-local/loopback denial; response/decompression/key-count/time bounds. | Real controlled network probes for IPv4/IPv6, redirect, rebinding, oversized response, cancellation. |
| Stale/removed key acceptance | Source-bound cache expiry, fetched-at metadata, refresh semantics, explicit removed-key behavior, no stale resurrection. | Actual rotation/removal against the named discovery adapter. |
| Key exfiltration | Opaque handle; signing, key-wrapping, and key-unwrapping custody boundaries; public-only serialization; redaction; no secret fields in inspection. | Real local and remote signer error pathways plus log/telemetry scan. |
| Forwarded-header spoofing | Explicit trusted-proxy policy and authoritative external origin; retain ingress and reconstructed facts. | Actual proxy route with trusted and untrusted hops. |
| Cross-origin relay | `@authority` coverage binds a signature to its origin, so the verifier's origin must come from its own configuration: a declared origin, or a connection origin only where the application answers for its own authorities alone (RFC 9421 Section 7.4.3). `origin: :connection` takes the authority from the sender's Host line. | A request signed for another authority sent to a server answering for any host. |
| Retry/redirect reuse | Req re-signs each final attempt and requires cross-origin policy; selected nonce/time parameters regenerate. Finch signs each explicit caller invocation; callers own its retry/redirect loop. Responses bind to the supplied request. | Actual redirect/retry flows, including cross-origin denial. |
| Parser/resource exhaustion | Bounded bytes, members, depth, signature/component/key counts, numeric magnitudes, deadlines, retained-body chunk counts and producer work. Dirty native work can overrun a deadline, and trusted callbacks must propagate cancellation to their own work. | Just-inside/outside bounds, fuzz corpus, timeout/cancel paths, measured resource receipts. |
| Error oracle/data leak | Stable bounded public reasons and redacted default inspection. The versioned telemetry contract carries only low-cardinality outcome/reason/layer atoms. | Real negative paths with sensitive canaries absent from output, event metadata, and event names. |
| Cross-profile replay | Commitment facts carry the selected profile stamp; the caller's namespace and commitment separate profiles. No fallback. | Same nonce under generic, Web Bot Auth, and package-namespaced extension profiles; tag substitution rejection. |
| Corpus compromise | Immutable provenance, independent expected values, digest manifest, source review, and the Elixir consumer prohibited from regenerating expectations. | Tampered-case red proof in Elixir and manifest verification. |
| Supply-chain substitution | Exact development pins, locked dependencies, package content allowlist, advisory/license review, provenance/checksums, isolated notebook toolchain. CI actions use immutable commit SHAs; the PostgreSQL service uses the moving `postgres:18` tag, not a digest pin. | Fresh clone, package inspection, audit output, and consumer install on required platforms; the service tag does not establish immutable image identity. |

## Profile-specific hazards

Web Bot Auth discovery can turn a signed field into a network capability.
The selected draft permits multiple discovery types. Selection is configuration,
not content negotiation by an attacker. Directory signatures and requests use
their own profile rules; support for `req` in one does not imply support in the
other. Nested signatures must independently satisfy required coverage. Required replay
accepts exactly one selected signature and claims over its covered values only:
labels are uncovered (RFC 9421 Section 7.2.5), and a claim over a set of
signatures would let a relabeled, stripped, or recombined capture claim afresh.

## Generic JOSE threats

HTTP and JOSE use separate parsers and exact algorithm registries. Protected
headers and finalized ciphertext bytes remain exact. Decryption results withhold
plaintext until complete AEAD validation. Recipient integrity alone establishes
neither origin, identity, nor request association. Caller callbacks select keys
and application trust explicitly; generic JOSE cannot infer them from wire data.

## Failure behavior

Malformed or unsupported input returns a stable error before cryptographic work when safe. Generic verification requires an explicitly selected signature label. Required digest, discovery, clock, custody, replay, or related-request data that is unavailable fails closed for that profile.

Custody, discovery, JOSE callbacks, Web Bot Auth trust callbacks, and required replay
receive bounded deadlines and caller cancellation. Generic policy resolver, clock, and
verification-function callbacks, and function signers in the explicit three-key
`sign/4` form, run synchronously in the calling process (`t:RequestSeal.signing_spec/0`
signers run in custody's monitored workers under `:signing_timeout`);
callers own their external-work deadlines or delegate to bounded custody/discovery
operations. A timeout is distinct from invalid cryptography and from policy rejection,
but none produces an authenticated principal. Replay errors are always nonretryable;
a timeout may have committed. Discovery classifies transient failures separately,
including retryable 5xx and nonretryable 4xx status failures. Callers own retry
scheduling and whether replaying the whole operation is safe. Errors retain no
attacker-controlled diagnostics.

## Residual boundaries

RequestSeal cannot establish that a caller's trust anchors, proxy configuration, authorization policy, payment decision, or external key-custody service are correct. It makes their inputs, provenance, and unevaluated state explicit so the caller cannot receive an accidental success signal. Actual assurance for a configured adapter comes from real-substrate evidence (see the [testing guide](../guides/testing.md)), not from the existence of the interface.

## Bounded parsing

Compact and nested parsing stop at the first excess segment; tests enforce a
10,000-reduction separator-storm budget at the complete configured byte ceiling.
Discovery trailing whitespace permits only SP, HTAB, LF, and CR under [RFC 8259 Section 2](https://www.rfc-editor.org/rfc/rfc8259.html#section-2).

## Decryption timing

RequestSeal makes no constant-time claim across machines, loads, keys, ciphertext lengths, or repeated remote observations.

RSA-OAEP padding failures and GCM authentication failures return the identical complete error:
`%RequestSeal.JOSE.Error{reason: :decryption_failed, layer: :crypto, correlation: nil, retryable: false}`.
Run `MIX_ENV=test mix run bench/ceilings.exs` for parser resource measurements and OAEP timing distributions.
