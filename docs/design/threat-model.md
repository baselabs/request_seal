<!-- Status: current · Kind: design · Updated: 2026-10-16 · Governed by: public architecture · Review when: a trust boundary, profile, adapter, data shape, or external effect changes -->

# RequestSeal threat model


RequestSeal processes attacker-controlled wire data at an authentication boundary. Its primary security goal is to report exactly what was cryptographically established, by which trusted association, under which profile, without granting caller authorization or payment authority.

The TypeScript counterpart is the separate npm package `@request-seal/core`. Both implementations share the independently sourced conformance corpus and its digest and cardinality checks.

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
| Error oracle/data leak | Stable bounded public reasons and redacted default inspection. The versioned telemetry contract (from 0.5.0) carries only low-cardinality outcome/reason/layer atoms; opt-in diagnostic redactors remain proposed. | Real negative paths with sensitive canaries absent from output, event metadata, and event names. |
| Cross-profile replay | Commitment facts carry the selected profile stamp; the caller's namespace and commitment separate profiles. No fallback. | Same nonce under generic, Web Bot Auth, and package-namespaced extension profiles; tag substitution rejection. |
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

## Measured input ceilings

OBSERVED on October 16, 2026 by `MIX_ENV=test mix run bench/ceilings.exs`:
Apple M4 (Darwin arm64), 64-bit words, Erlang/OTP 29.1.1 (ERTS 17.1), Elixir
1.20.4 (compiled for OTP 29). The runtime OTP patch version was read from its
`OTP_VERSION` file. This run follows the 0.5.0 hot-path changes (binary-part
OWS trimming, single-pass builder counting, validate-once verification
plumbing); the signature-base candidate measures ~2.5× faster at p50 than the
October 8 run on the same machine class.

Each adversarial candidate has 10 warmups and 100 measured samples, with garbage
collection before each measurement. Time uses integer microseconds;
p50/p99 use nearest ranks. Reductions belong to the current parser process.
The table independently selects the largest observed time p99 and largest
reduction maximum per parser; the candidates can differ. Each maximum column
records the selected candidate's largest individual sample. These are observed
resource measurements for this run, rather than universal latency bounds.

| Parser | Time candidate / input ceilings | Time p50 / p99 / max (µs) | Reduction candidate | Reductions p50 / p99 / max |
| --- | --- | ---: | --- | ---: |
| Structured Fields | dictionary / bytes:65536, members:1024 | 4 696 / 7 193 / 7 946 | dictionary | 360 110 / 363 061 / 363 291 |
| Signature base | base / bytes:1048576, components:256 | 8 799 / 10 651 / 10 922 | base | 3 332 590 / 3 333 645 / 3 333 660 |
| Compact JWS | whitespace_storm / compact_bytes:1048576, segments:under-limit | 2 239 / 4 333 / 4 397 | compact | 2 397 577 / 2 397 641 / 2 397 642 |
| Compact JWE | compact / compact_bytes:1048576, header_bytes:16384, depth:4 | 2 944 / 8 899 / 9 307 | compact | 2 400 050 / 2 400 112 / 2 400 114 |
| JOSE protected JSON | bytes_depth / bytes:16384, depth:4 | 55 / 123 / 135 | bytes_depth | 33 032 / 33 098 / 33 099 |
| JWKS body | json_shape / bytes:65536, keys:32, members:256, array:256, depth:32 | 844 / 1 565 / 1 799 | body_keys | 148 488 / 148 513 / 148 513 |
| Key directory body | body_keys / bytes:65536, keys:32 | 335 / 1 227 / 1 347 | body_keys | 148 739 / 148 908 / 148 909 |

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
| RSA-OAEP | valid | 1000 | 624 / 1 923 | 588 / 3 000 |
| RSA-OAEP | leading_zero | 1000 | 623 / 2 046 | 585 / 4 316 |
| RSA-OAEP | masked_seed | 1000 | 623 / 2 161 | 583 / 3 292 |
| RSA-OAEP | padding | 1000 | 624 / 2 052 | 587 / 12 597 |
| RSA-OAEP | tag | 1000 | 622 / 2 067 | 580 / 2 551 |
| RSA-OAEP-256 | valid | 1000 | 625 / 1 755 | 587 / 4 670 |
| RSA-OAEP-256 | leading_zero | 1000 | 624 / 1 939 | 587 / 4 371 |
| RSA-OAEP-256 | masked_seed | 1000 | 625 / 2 013 | 587 / 10 568 |
| RSA-OAEP-256 | padding | 1000 | 625 / 1 490 | 587 / 2 795 |
| RSA-OAEP-256 | tag | 1000 | 626 / 2 000 | 585 / 4 944 |

A paired bootstrap with 1,000 resamples reports the 99% interval for each
corruption-minus-comparison mean. The two-sample Kolmogorov–Smirnov distance uses
the approximate 99% critical distance 0.0729; rank probability reports the
empirical probability that the corruption path is slower (ties count as one-half).
The combined decision flags separation if either unadjusted criterion triggers;
it has no joint 99% confidence or multiple-comparison error control.

| Algorithm | Corruption versus | Rank probability | KS distance | Mean delta 99% interval (µs) |
| --- | --- | ---: | ---: | ---: |
| RSA-OAEP | leading_zero vs. valid | 0.5079 | 0.027 | [-11.918,21.919] |
| RSA-OAEP | leading_zero vs. tag | 0.5081 | 0.03 | [-11.29,25.263] |
| RSA-OAEP | masked_seed vs. valid | 0.4988 | 0.023 | [-24.611,13.23] |
| RSA-OAEP | masked_seed vs. tag | 0.4992 | 0.025 | [-22.77,12.912] |
| RSA-OAEP | padding vs. valid | 0.5013 | 0.02 | [-20.989,47.896] |
| RSA-OAEP | padding vs. tag | 0.5015 | 0.021 | [-16.988,40.329] |
| RSA-OAEP-256 | leading_zero vs. valid | 0.4975 | 0.028 | [-13.925,18.377] |
| RSA-OAEP-256 | leading_zero vs. tag | 0.5042 | 0.033 | [-20.127,24.116] |
| RSA-OAEP-256 | masked_seed vs. valid | 0.502 | 0.022 | [-16.767,41.462] |
| RSA-OAEP-256 | masked_seed vs. tag | 0.5088 | 0.046 | [-13.359,36.373] |
| RSA-OAEP-256 | padding vs. valid | 0.5036 | 0.024 | [-26.491,11.981] |
| RSA-OAEP-256 | padding vs. tag | 0.5104 | 0.043 | [-22.441,10.166] |

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
