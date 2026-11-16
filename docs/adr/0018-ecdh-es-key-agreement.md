# 0018 — Support ECDH-ES key agreement over P-256, P-384 and X25519

## Context

JWE recipients that publish elliptic-curve or X25519 keys expect ECDH-ES (RFC 7518 Section
4.6, RFC 8037 Section 3.2). Without it an application can encrypt only to RSA keys or
shared symmetric keys. Key agreement takes an ephemeral public key from an unauthenticated
header, so the checks on that key and the place where the private agreement runs decide
whether a forged header can extract key information.

## Decision

1. Support `ECDH-ES`, `ECDH-ES+A128KW` and `ECDH-ES+A256KW` over P-256, P-384 and X25519.
2. Derive keys with the RFC 7518 SHA-256 Concat KDF. The key-wrap variants use the same
   RFC 3394 implementation as A128KW and A256KW
   ([ADR 0019](0019-aes-key-wrap-custody.md)).
3. `RequestSeal.JOSE.KeyManagement.agree/4` takes a public recipient key and creates the
   ephemeral private key only inside a sensitive worker.
4. The recipient's private agreement runs only in custody: a handle bound to the
   algorithm receives `%{epk, apu, apv, algorithm_id, key_bits}` params. The ephemeral
   public key and party information are validated before key resolution; an all-zero
   X25519 shared secret is refused.
5. `RequestSeal.PublicKey` imports and exports X25519 keys. An X25519 key cannot sign or
   verify.
6. Conformance comes from independent vectors: RFC 7518 Appendix C, RFC 7520 Sections 5.4,
   5.5 and 5.7, RFC 7748, RFC 8037 and Wycheproof, in the `key_management.ecdh_kdf/v1` and
   `key_management.agree/v1` corpus surfaces. Independent JOSE implementations decrypt the
   library's output, and the library decrypts theirs.

## Consequences

The JWE encrypt and decrypt allowlists include these ECDH-ES forms (ADR 0019). JWE decryption in the reviewed 2.0 branch accepts only unwrap handles; it rejects the legacy unwrap closure for every algorithm (ADR 0027). @request-seal/core 0.5.0 has no ECDH-ES support. Its proposed 0.6 parity contract uses X25519 where available and returns crypto/unsupported_algorithm on a runtime without it.
