# 0004 — Keep key custody external and discovery controlled

The 1.x key-function alternatives recorded here are superseded by
[ADR 0027](0027-key-handles-replace-closures.md). In 2.0, key operations use
algorithm-bound handles; resolver callbacks still select keys.

## Context

RequestSeal must support local keys, HSM/KMS-style custody, JWK/JWKS, WBA directories, rotation, and revocation without requiring a network or key store. Sender-provided identifiers and URLs are attacker-controlled until a profile-valid trust association is established. [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) define JWK sets, thumbprints, and OKP keys.

## Decision

Opaque caller-owned handles keep private key material within the selected custodian.
Generic asymmetric verification resolves public keys; HMAC resolves a `:verify` custody handle and proves shared-secret possession without unique signer attribution.
TLS custody remains with the caller; CEKs and IVs never become public metadata.
Discovery requires explicit profile/caller policy, HTTPS, trusted sources, vetted addresses,
bounded redirects, response/decompression/key limits, deadlines, cancellation, and freshness.

## Consequences

Local use has no network requirement. Local construction starts one unsupervised sensitive holder per handle, addressed only by PID and token. Sensitivity is set before key material arrives; the holder rejects system introspection and performs cryptography without returning private state. It monitors the creator and exits on creator death or explicit `Local.release/1`; later signing returns the existing `:key_not_found` reason. Loading the library starts no process. Remote signers and discovery integrations must implement deadlines, cancellation, redaction, and provenance. Principal attribution remains unavailable when a valid key lacks a trusted association.

## Acceptance

- Secret canaries stay out of public values, diagnostics, telemetry, and artifacts.
- Real signers exercise success, timeout, cancellation, and provider failures.
- Controlled discovery exercises address restrictions, redirects, bounds, freshness, rotation, and removal.
- Asymmetric thumbprints and key type/use/operations/algorithm checks are deterministic.
- HMAC secrets stay in custody; a valid key without trusted attribution supplies no principal.

## Resolver boundary

Generic resolution returns exactly `{:ok, %{algorithm: algorithm, key: public_key_or_verify_function}}`
or `:error`; extra identity or provenance members reject.
`Discovery.Resolution` exposes provenance separately, and Web Bot Auth applies caller trust.
`Custody.identity/1` is a separate API with custodian-supplied symmetric identities.

## RSA-OAEP recipient custody

[RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) and [RFC 7518 Section 4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3) define the wire algorithms.
`Local.new/3` and `Local.import/4` bind RSA-OAEP or RSA-OAEP-256 handles to unwrap.
Import accepts unencrypted PEM, PKCS #8 DER, or private JWK with 2048–8192-bit RSA,
validated CRT components and JWK restrictions; PSS-only keys reject.
The indexed holder callback delivers keys directly into an owner-created sink
([ADR 0017](0017-indexed-unwrap-through-a-sink.md)); the custody runner receives a summary.
`Custody.unwrap/3` returns indexed results to callers, who own protection of returned bytes.
JWE releases only authenticated plaintext; failed OAEP unwrap uses a random CEK and attempts GCM.
Padding and tag failures return identical complete errors, while deadlines remain distinct.
Other permitted OAEP variants can reject before RSA and reveal the handle's algorithm through timing.
Released handles reject; callers can check `Custody.public_key/1` at startup.

## Supervised Ed25519 seed sources

`Custody.Local.Owner` is an optional caller-supervised child that reads seed descriptors
inside a sensitive process, retaining handles and bounded statuses.
Sources are tagged environment values, direct files, or environment-selected paths;
encodings are Base64url, Base64, hex, and raw. Literal seeds and guessed encodings reject.
Files require trusted paths, regular-file metadata, and mode 0600 or stricter.
Source reads are limited to 4,096 bytes; failed keys grant no capability.
Each ready key has one holder monitored by the child; restart rereads sources and retires handles.
Fetch per operation or retry a fetch once on `:key_not_found`.
Environment values persist for restart and reach OS children; direct files are preferred in production.
HTTP signing accepts algorithm-matching handles with custody deadlines and exact wire construction.
Errors follow `RequestSeal.Error` and the key-custody guide; no application authority is implied.

## Custody capabilities and proposals

Optional `wrap/4` supports AES Key Wrap ([ADR 0019](0019-aes-key-wrap-custody.md));
`release/2` supports `Custody.release/1`, and [ADR 0018](0018-ecdh-es-key-agreement.md)
defines ECDH-ES over P-256, P-384, and X25519.
JWE accepts algorithm-matching unwrap handles.
[ADR 0027](0027-key-handles-replace-closures.md) requires handle-only key resolution;
[ADR 0026](0026-custody-key-generation-and-derivation.md) defines generation inside
sensitive holders and atomic derivation with caller-owned cleanup capabilities.
`RequestSeal.verify/3` selects one label. [ADR 0043](0043-quorum-replay-commitment.md)
defines `RequestSeal.verify_quorum/3` for callers that require a joint verdict.
