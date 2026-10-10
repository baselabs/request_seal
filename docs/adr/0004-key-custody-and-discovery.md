# ADR 0004: Keep key custody external and discovery controlled

- Status: Accepted
- Date: 2026-10-06
- Updated: 2026-10-09

## Context

RequestSeal must support local keys, HSM/KMS-style custody, JWK/JWKS, WBA directories, rotation, and revocation without requiring a network or key store. Sender-provided identifiers and URLs are attacker-controlled until a profile-valid trust association is established. [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) define JWK sets, thumbprints, and OKP keys.

## Decision

Represent private custody as an opaque caller-owned `KeyHandle`; only the selected signing or verification custodian interprets it. The core receives signature/verification results and bounded public metadata, never exportable private material. Asymmetric verification resolves a public key; HMAC verification resolves an opaque verification handle. Both include provenance and asserted associations, which profiles must validate before principal attribution. HMAC establishes shared-secret possession, not a unique signer or public verifiability.

Distinct-key policies use canonical public components for asymmetric keys and trusted nonsecret custodian/resolver key-equivalence identities for HMAC. All aliases/imports of one secret map to one identity within the declared trust scope; per-handle IDs cannot establish distinctness. Unknown cross-custodian equivalence rejects a key-distinct threshold. The custodian supplies HMAC key-equivalence identity as an opaque value; RequestSeal never derives it. It stays internal and follows the redaction contract. An explicitly selected principal/role policy may use its own independently established trust bindings.

TLS custody stays with the caller's transport. Internal CEKs/IVs never become public metadata.

Network discovery is an optional adapter invoked only by explicit profile/caller policy. It enforces HTTPS, no automatic redirects by default, DNS and post-connect address checks, private/link-local/loopback denial, bounded redirects when specifically allowed, response/decompression/key-count limits, deadlines, cancellation, cache freshness, and explicit removal/rotation semantics. A message cannot introduce a fetchable URL outside configured discovery types and trust roots.

## Strongest alternatives

1. **Accept raw private keys in `sign/3`.** It makes local development direct. It spreads secret-bearing values across structs, inspection, errors, and adapters, making non-exporting custody impossible.
2. **Require a general-purpose HTTP client/cache.** It offers turnkey discovery. It imposes network/process choices on every consumer and conflates fetching with trust. The implemented optional discovery adapter instead uses a bounded HTTP/1.1 GET over caller-started OTP TLS, with vetted addresses and explicit source policy. Its optional cache starts only when the caller requests it; neither transport nor cache is required by core signing or verification.
3. **Let the key resolver fetch arbitrary `keyid` URLs.** It is flexible and mirrors some generic libraries. It creates an SSRF and confused-deputy surface and treats location as identity.
4. **Require callers to resolve everything before RequestSeal.** It removes network code. It also strips provenance and profile-specific directory validation from the result, encouraging key possession to be mistaken for identity.

## Deciding evidence and deletion test

WBA protocol-00 requires explicit discovery types and HTTPS/200/no automatic redirects; RFC/JWK sources define key representation, not trust. Delete the custody boundary and every caller/custodian must expose or translate secrets differently. Delete discovery as a core-required subsystem and pure callers get simpler; therefore discovery stays an optional adapter rather than a required layer.

## Consequences

Local use has no network requirement. Local construction starts one unsupervised sensitive holder per handle, addressed only by PID and token. Sensitivity is set before key material arrives; the holder rejects system introspection and performs cryptography without returning private state. It monitors the creator and exits on creator death or explicit `Local.release/1`; later signing returns the existing `:key_not_found` reason. Loading the library starts no process. Remote signers and discovery integrations must implement deadlines, cancellation, redaction, and provenance. Principal attribution remains unavailable when a valid key lacks a trusted association.

## Acceptance

- Secret canaries never appear in public values, inspection, logs, telemetry, exceptions, or package artifacts.
- Actual local and authorized external signers exercise success, timeout, cancellation, and provider error paths.
- Real controlled discovery exercises redirects, DNS/IP changes, IPv4/IPv6 restricted ranges, oversized/decompressed responses, excessive keys, cache expiry, rotation, and removal.
- Asymmetric thumbprints are deterministic and key type/use/operations/algorithm compatibility is enforced.
- Actual HMAC verification retains secret custody; same-secret aliases/imports count once, distinct trusted identities count as configured, and unknown cross-custodian equivalence rejects key-distinct thresholds.
- A valid signature from an untrusted or unattributed key cannot populate an authenticated principal.

## Implemented resolver boundary — October 8, 2026

OBSERVED in `lib/request_seal/authentication.ex` (`resolve/3`) and
`lib/request_seal/discovery.ex` (`resolver/2`): generic resolution returns an
authoritative algorithm and public key or verification function, plus optional
internal key-equivalence identity. HMAC uses a verification function that can
invoke an opaque custody handle. Provenance and asserted principal associations
are not generic resolver-result members. `Discovery.Resolution` exposes source
provenance separately; Web Bot Auth applies caller trust before attribution.
This supersedes the Decision's claim that both generic key results include
provenance and asserted associations.

## RSA-OAEP recipient custody — October 8, 2026

Extend opaque local custody to key unwrapping under
[RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) and
[RFC 7518 Section 4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3).
`Local.new/3` and `Local.import/4` select `{:jwe, "RSA-OAEP"}` or
`{:jwe, "RSA-OAEP-256"}` with only `:unwrap` capability. Import accepts
unencrypted private PEM, PKCS #8 DER, or private JWK; RSA moduli are 2048–8192
bits, CRT components are validated, and PSS-only keys reject. JWK algorithm,
encryption use, and decryption/unwrapping operation restrictions apply.
Signing and unwrap capabilities remain separate, each bound to one algorithm.

`Custody.unwrap/3` shares the monitored runner, cancellation, bounded input,
and deadline contract. The holder performs the private RSA operation and
returns only unwrapped bytes. A JWE resolver may return
`{:ok, %{algorithm: wire_algorithm, key: handle}}`; its request receives the
remaining envelope deadline. The raw-key unwrap callback remains supported.
The CEK passes from the sensitive holder through the sensitive custody runner
and middle process to the sensitive JWE worker for authenticated content
decryption; all four processes see it. JWE's outer middle process and the decrypt
caller receive only the authenticated result. Every custody runner and middle
process sets sensitivity before work, including signing operations. Direct
`Custody.unwrap/3` callers receive unwrapped bytes and own their protection;
the bytes never become public metadata. Unwrap rejection uses
a fresh random CEK and still attempts GCM authentication; OAEP padding failure
and GCM tag failure return the same complete error. A handle bound to the other
permitted OAEP algorithm follows that same failure path; an empty OAEP plaintext
is a direct custody `:decryption_failed`. Released or unavailable handles also
yield the forged-message error in JWE, so operators check
`Custody.public_key(handle)` at startup. Resolver entries must match the selected
header algorithm in both callback and handle branches. Deadline expiration
remains a separate bounded failure.

A header naming the other permitted OAEP algorithm fails before any RSA operation
and can therefore be faster than a padding failure; the complete error is identical,
and the timing reveals only which variant the handle binds.

Acceptance requires actual OTP round trips, independent published OAEP vectors,
Node WebCrypto encryption to the handle's public key, wrong/released handle
rejection, suspended-holder timeout/cancellation, and private-key canary checks
on values, inspection, BEAM serialization, process introspection, and diagnostics.

## Supervised Ed25519 source ownership — October 9, 2026

Add an optional `RequestSeal.Custody.Local.Owner` child to the consumer's tree.
It reads explicitly tagged Ed25519 seed sources inside a sensitive process,
constructs existing Local holders, then retains only handles and bounded statuses.
Sources are environment values, direct files, or paths from environment variables;
encoding tags are Base64url, Base64, hex, and raw. There is no literal-seed source,
guess-decoding, global registration, or registration after startup. Files require
regular-file metadata and mode 0600 or stricter. A failed key does not stop the
Owner or issue a signing capability. Initialization costs are linear in configured
keys, with a 4,096-byte source limit and one holder per ready key.

The existing creator-monitor boundary now binds these holders to the supervised
Owner. Restart rereads every descriptor and retires old handles. Consumers fetch
per operation or fetch again and retry once on `:key_not_found`. Environment
variables remain intact for restart; direct files are the production preference
because environment seed values are inherited by OS child processes. Caller
configuration paths and their parent directories must remain trusted at startup.

The explicit HTTP signature form accepts an algorithm-matching handle and uses
the custody deadline boundary. It retains synchronous function signers and exact
wire construction. Public reason and message contracts belong in `RequestSeal.Error`
and the key-custody guide. This decision adds no application profile or authority.
