<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0019 — Wrap with AES Key Wrap and keep GCMKW and dir unwrap-only
Status: Accepted

## Context

Symmetric JWE recipients need a content-key wrap that custody can perform without exposing
the key-encryption key. AES-GCMKW (RFC 7518 Section 4.7) needs a unique 96-bit IV for
every wrap under one key, so a custodian would have to keep a durable invocation counter
or rely on random IVs with a usage bound. AES Key Wrap (RFC 3394, RFC 7518 Section 4.4)
is deterministic and needs no IV state.

## Decision

1. Custody wraps content keys only with A128KW and A256KW, through the optional
   `wrap/4` callback and `RequestSeal.Custody.wrap/3`. The content key is exactly 16 or 32
   bytes; the result is `%{encrypted_key: bytes, params: %{}}`. The handle must grant
   `:wrap`.
2. The RFC 3394 implementation runs all 6n rounds and compares the integrity check value
   in constant time.
3. A128GCMKW, A256GCMKW and `dir` stay unwrap-only: those handles cannot wrap, and JWE
   encryption does not offer them.
4. Three allowlists hold. Encryption: RSA-OAEP, RSA-OAEP-256, A128KW, A256KW, ECDH-ES,
   ECDH-ES+A128KW and ECDH-ES+A256KW. Primitive wrap: RSA-OAEP, RSA-OAEP-256, A128KW and
   A256KW. Decryption: those seven plus A128GCMKW, A256GCMKW and `dir`. An algorithm
   outside the list is `:algorithm_not_permitted` at layer `:input`.
5. `RequestSeal.JOSE.KeyManagement.unwrap/4` takes closed per-family params, and wrap
   telemetry carries only `outcome: :ok | :failed`. The `key_management.aes_kw/v1` corpus
   surface carries the RFC 3394 vectors.

## Alternatives

1. **Wrap with GCMKW using a custody invocation counter.** Keeps one symmetric family. Every
   custodian must persist a counter that survives restarts and replicas, and a reset
   repeats an IV.
2. **GCMKW with random IVs and a usage limit.** No durable state. The safe limit per key is
   a budget the custodian must still track.
3. **Drop GCMKW and `dir` entirely.** Smaller surface. Existing senders that use them could
   no longer be decrypted.

## Consequences

Senders that need a symmetric wrap use AES-KW. Decryption of GCMKW and `dir` tokens
continues. Custodians that implement `wrap/4` implement AES-KW only. The TypeScript
package moves its handle wrap from GCMKW to AES-KW in its next minor line.
