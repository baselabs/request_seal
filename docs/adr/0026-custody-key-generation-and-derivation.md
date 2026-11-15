<!-- Status: proposed · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0026 — Generate and derive keys inside custody
Status: Proposed

## Context

Applications that need a fresh signing, wrapping or agreement key, or a per-domain key
derived from a root, generate it outside custody and import it. The key then exists in
caller memory before custody holds it. A derived key also has to be usable only after it
is durably recorded, or a crash between derivation and use leaves an unrecorded key.

## Decision

1. Local.generate(algorithm, opts) returns {:ok, handle} or {:error, Custody.Error}. RSA signing and RSA-OAEP require :bits in [2048, 3072, 4096], plus optional :capabilities. ECDH-ES forms require :curve in ["P-256", "P-384", "X25519"], plus optional :capabilities. AES-KW and ECDSA, Ed25519 and HMAC signing algorithms accept only :capabilities; their key size or curve follows the algorithm. Misplaced or unknown options return :invalid_options. GCMKW, dir and {:derive, _} algorithm selections return :unsupported_algorithm.
2. Derivation uses HKDF-SHA256 with info
   `"request-seal/derive/v1" || lp(family) || lp(domain)`, where `lp` is a length prefix and
   the domain is 1 to 255 bytes. Families are `x25519-dhkem`, `p256-dhkem`, `p384-dhkem`,
   `ed25519-seed`, `hmac-sha256-key`, `aes128-key` and `aes256-key`.
3. Derivation uses derive/3 followed by commit/3 under the same operation deadline. Only an acknowledged atomic commit returns a usable child handle. A failed derive or an explicit commit refusal returns an ordinary error. A lost commit result triggers one release attempt under a fresh 1,000 ms context; confirmed destruction returns an ordinary error, while unconfirmed destruction returns {:cleanup_required, cleanup, error}. The redacted cleanup capability is caller-owned and may be retried through Custody.cleanup/2 until :ok.
4. Releasing a parent does not release its children. A custodian that implements
   `derive/3` also implements `commit/3` and `release/2`.

## Alternatives

1. **Generate outside custody and import.** No new callbacks. The key exists in caller
   memory first.
2. **Derive and use in one call.** One round trip. A crash can leave a used key that no
   record holds.
3. **Caller-chosen KDF info.** Flexible. Two applications could collide on one derived key
   across families.

## Consequences

Custodians that support derivation implement three callbacks together. The derivation
string is part of the wire contract and changes only with a new version tag. The corpus
carries derivation vectors so other implementations can match. This record stays Proposed
until the change lands on the main branch.
