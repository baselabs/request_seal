<!-- Status: current · Kind: design · Updated: 2026-10-08 · Governed by: architecture and ADRs 0002–0007 · Review when: a trust boundary, profile, adapter, data shape, or external effect changes -->

# RequestSeal threat model


RequestSeal processes attacker-controlled wire data at an authentication boundary. Its primary security goal is to report exactly what was cryptographically established, by which trusted association, under which profile, without granting caller authorization or payment authority.

RequestSeal is Elixir only. The TypeScript counterpart is deferred, not planned for the current release; the cross-language corpus format remains a design for later use.

## Assets and trust boundaries

Assets are private signing authority, private recipient keys, verified message bytes, content-integrity state, principal attribution, replay uniqueness, nested signature binding, and diagnostic confidentiality. Trust boundaries exist between wire input and the lossless model; model and profile; profile and key/discovery; verification and replay store; RequestSeal and each framework adapter; independent corpus data and the Elixir consumer; and authenticated principal and caller authorization.

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
| Key exfiltration | Opaque handle; signing and key-unwrapping custody boundaries; public-only serialization; redaction; no secret fields in inspection. | Real local and remote signer error pathways plus log/telemetry scan. |
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

## Measured input ceilings

OBSERVED on October 8, 2026 by `MIX_ENV=test mix run bench/ceilings.exs`:
Darwin arm64, 64-bit words, Erlang/OTP 29.1.1 (ERTS 17.1), Elixir 1.20.4
(compiled for OTP 29). CPU model not recorded; the machine
identity recorded by `uname -sm` is Darwin arm64. The runtime OTP patch version
was read from its `OTP_VERSION` file.

Each adversarial candidate has 10 warmups and 100 measured samples, with garbage
collection before each measurement. Time uses integer microseconds;
p50/p99 use nearest ranks. Reductions belong to the current parser process.
The table independently selects the largest observed time p99 and largest
reduction maximum per parser; the candidates can differ. Each maximum column
records the selected candidate's largest individual sample. These are observed
resource measurements for this run, rather than universal latency bounds.

| Parser | Time candidate / input ceilings | Time p50 / p99 / max (µs) | Reduction candidate | Reductions p50 / p99 / max |
| --- | --- | ---: | --- | ---: |
| Structured Fields | dictionary / bytes:65536,members:1024 | 4896 / 11065 / 22136 | dictionary | 360088 / 363107 / 363290 |
| Signature base | base / bytes:1048576,components:256 | 20107 / 34829 / 43177 | base | 3928094 / 4077568 / 4077579 |
| Compact JWS | compact / compact_bytes:1048576,header_bytes:16384,depth:4 | 2620 / 6138 / 10671 | compact | 2397568 / 2397632 / 2397632 |
| Compact JWE | compact / compact_bytes:1048576,header_bytes:16384,depth:4 | 2649 / 7787 / 9971 | compact | 2400029 / 2400090 / 2400091 |
| JOSE protected JSON | bytes_depth / bytes:16384,depth:4 | 131 / 714 / 1154 | bytes_depth | 33023 / 33089 / 33090 |
| JWKS body | json_shape / bytes:65536,keys:32,members:256,array:256,depth:32 | 723 / 1224 / 1269 | body_keys | 148493 / 148512 / 148513 |
| Key directory body | body_keys / bytes:65536,keys:32 | 337 / 1218 / 1431 | body_keys | 148741 / 148908 / 148909 |

Structured Fields also measures the byte, parameter, inner-item, value-byte, and
node ceilings. Its fixed grammar depth accepts container → inner list → item
and rejects a further inner list. Signature-base inputs include the full
1,048,576-byte output and 256 components, plus 256 query components. Compact JOSE
measurements call the production segment parser, protected-header parser, and
Base64url decoders; key resolution, signature verification, and decryption are
outside those parser measurements. Before measuring, real generated envelopes
are verified/decrypted successfully. Headers reach 16,384 bytes and depth four.
Separator and whitespace storms reach the full compact byte ceiling. Discovery
calls the same bounded JSON and key-import functions used by fetch, through its
internal body entry point, with 32 actual generated public keys. Its shape
candidate reaches 256 object members, 256 array entries, and depth 32.
Network transport and directory possession proof are outside the body measurement.

OBSERVED: one-megabyte separator rejection used 61 reductions for JWS and
71 for JWE in this run. Compact and nested parsing stop at the first excess
segment. Fixed-seed properties and regular regressions enforce a 10,000-reduction
budget for separator storms, including the complete configured byte ceiling.
Discovery trailing bytes follow [RFC 8259 Section 2](https://www.rfc-editor.org/rfc/rfc8259.html#section-2):
SP, HTAB, LF, and CR; vertical tab, form feed, and Unicode spaces reject.

## RSA-OAEP decryption timing

OBSERVED in the same benchmark run: one locally generated 2,048-bit RSA key,
A256GCM, 30 warmups per outcome, and 1,000 samples each for valid ciphertext,
corrupted encoded-message leading zero (byte 0), corrupted masked seed (byte 1),
corrupted masked data block (byte 200), and corrupted GCM tag, for both RSA-OAEP
and RSA-OAEP-256. The timer measures the complete `JWE.decrypt/2` call, including
its sensitive worker. Sample order rotates to reduce order bias. The script
recovers the real OAEP encoded message with raw private RSA, asserts its leading
zero, corrupts each selected byte, and applies raw public RSA. Actual unwrap
rejection is asserted before timing. Tag corruption changes a decoded tag byte
and re-encodes it canonically; other token bytes remain identical.

| Algorithm | Outcome | Samples | Time p50 / p99 (µs) | Min / max (µs) |
| --- | --- | ---: | ---: | ---: |
| RSA-OAEP | valid | 1,000 | 611 / 1830 | 585 / 2800 |
| RSA-OAEP | leading_zero | 1,000 | 612 / 1743 | 585 / 5251 |
| RSA-OAEP | masked_seed | 1,000 | 611 / 1948 | 587 / 3349 |
| RSA-OAEP | padding | 1,000 | 611 / 1866 | 587 / 4131 |
| RSA-OAEP | tag | 1,000 | 612 / 1961 | 585 / 9605 |
| RSA-OAEP-256 | valid | 1,000 | 618 / 2659 | 585 / 16538 |
| RSA-OAEP-256 | leading_zero | 1,000 | 619 / 2426 | 583 / 4855 |
| RSA-OAEP-256 | masked_seed | 1,000 | 619 / 2911 | 585 / 7508 |
| RSA-OAEP-256 | padding | 1,000 | 617 / 2803 | 581 / 8893 |
| RSA-OAEP-256 | tag | 1,000 | 618 / 2720 | 583 / 11821 |

A paired bootstrap with 1,000 resamples reports the 99% interval for each
corruption-minus-comparison mean. The two-sample Kolmogorov–Smirnov distance uses
the approximate 99% critical distance 0.0729; rank probability reports the
empirical probability that the corruption path is slower (ties count as one-half).
The combined decision flags separation if either unadjusted criterion triggers;
it has no joint 99% confidence or multiple-comparison error control.

| Algorithm | Corruption versus | Rank probability | KS distance | Mean delta 99% interval (µs) |
| --- | --- | ---: | ---: | ---: |
| RSA-OAEP | leading_zero vs. valid | 0.509 | 0.034 | [-15.16,23.649] |
| RSA-OAEP | leading_zero vs. tag | 0.5116 | 0.039 | [-41.939,23.825] |
| RSA-OAEP | masked_seed vs. valid | 0.5066 | 0.054 | [-8.533,29.728] |
| RSA-OAEP | masked_seed vs. tag | 0.5089 | 0.039 | [-31.286,28.25] |
| RSA-OAEP | padding vs. valid | 0.4939 | 0.047 | [-21.847,20.286] |
| RSA-OAEP | padding vs. tag | 0.4966 | 0.03 | [-42.929,13.476] |
| RSA-OAEP-256 | leading_zero vs. valid | 0.5019 | 0.025 | [-118.583,1.585] |
| RSA-OAEP-256 | leading_zero vs. tag | 0.5112 | 0.031 | [-78.756,9.779] |
| RSA-OAEP-256 | masked_seed vs. valid | 0.4967 | 0.022 | [-93.473,17.276] |
| RSA-OAEP-256 | masked_seed vs. tag | 0.506 | 0.026 | [-74.027,37.994] |
| RSA-OAEP-256 | padding vs. valid | 0.4904 | 0.028 | [-103.127,28.032] |
| RSA-OAEP-256 | padding vs. tag | 0.4993 | 0.023 | [-70.725,31.83] |

OBSERVED: no timing separation was detected for leading-zero, masked-seed, or
masked-data-block corruption versus valid ciphertext or tag failure in this run
at this microsecond resolution and sample count. All 12 mean intervals include
zero; all KS distances are below 0.0729. Timing figures vary per run; the timing
and caller-result conclusions were rechecked in this run. This measurement does
not establish constant-time behavior on other machines, loads, keys, ciphertext
lengths, or repeated remote observations.

OBSERVED: valid ciphertext returns `{:ok, Result}`. All four corrupted ciphertext
cases return the identical complete error:
`%RequestSeal.JOSE.Error{reason: :decryption_failed, layer: :crypto, correlation: nil, retryable: false}`.
Computed flags are `errors_equal=true`, `failure_results_equal=true`, and
`all_results_equal=false` for both algorithms; valid ciphertext succeeds.
The regular OAEP regression uses real RSA and GCM and compares complete error
structs for leading-zero, masked-seed, and multiple masked-data-block corruptions.
