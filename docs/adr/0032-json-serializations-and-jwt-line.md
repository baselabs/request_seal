<!-- Status: proposed · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0032 — Add JOSE serializations and formats in 2.2 and JWT in 2.3
Status: Proposed

## Context

The 1.x and 2.0 JOSE surface is compact serialization with a fixed set of key formats.
Interop targets also use the JSON serializations, detached content and further key
encodings, and many applications need JSON Web Tokens on top of JWS. Each is additive and
can follow 2.0 without a break.

## Decision

1. 2.2 adds flattened and general JSON serialization, additional authenticated data,
   detached content, the `Ed25519` algorithm name from RFC 9864, DER-encoded ECDSA
   signatures, SEC1 compressed points and COSE_Key import and export.
2. 2.3 adds `RequestSeal.JWT` over JWS, limited to RFC 7519, the RFC 8725 best practices, the RFC 7523 assertion profile and the `oauth-id-jag+jwt` identity assertion type.
3. Protocols that bind tokens to HTTP requests or TLS connections are outside this line.
   The generic embedded-key primitive in
   [ADR 0015](0015-jose-protected-members-and-embedded-keys.md) is available to
   applications that build such protocols.

## Alternatives

1. **Fold these into 2.0.** One release. 2.0 already carries every break, and these need
   their own designs and corpus surfaces.
2. **Leave JWT to other libraries.** Less surface. Applications would verify JWS here and
   parse claims elsewhere with different bounds.

## Consequences

Each line needs its own design, corpus surfaces and TypeScript parity before release. None
has a judged design yet; this record states scope only and stays Proposed until those
designs exist.
