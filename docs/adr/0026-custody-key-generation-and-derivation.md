# 0026 — Accepted: Generate and derive keys inside custody

## Context

Applications that need a fresh signing, wrapping or agreement key, or a per-domain key
derived from a root, generate it outside custody and import it. The key then exists in
caller memory before custody holds it. A derived key also has to be usable only after it
is durably recorded, or a crash between derivation and use leaves an unrecorded key.

## Decision

1. Local.generate(algorithm, opts) returns {:ok, handle} or {:error, Custody.Error}. RSA signing and RSA-OAEP require :bits in [2048, 3072, 4096], plus optional :capabilities. ECDH-ES forms require :curve in ["P-256", "P-384", "X25519"], plus optional :capabilities. AES-KW and ECDSA, Ed25519 and HMAC signing algorithms accept only :capabilities; their key size or curve follows the algorithm. Misplaced or unknown options return :invalid_options. GCMKW, dir and {:derive, _} algorithm selections return :unsupported_algorithm.
2. Derivation uses HKDF-SHA256 with info
   `"request-seal/derive/v1" || lp(family) || lp(domain)`, where `lp(x) = u16be(byte_size(x)) || x` and
   the domain is 1 to 255 bytes. Families are `x25519-dhkem`, `p256-dhkem`, `p384-dhkem`,
   `ed25519-seed`, `hmac-sha256-key`, `aes128-key` and `aes256-key`. Extract uses
   salt `"request-seal/derive/v1"`. The ECDH families then apply
   [RFC 9180 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3)
   DeriveKeyPair (KEM 0x0020, 0x0010, or 0x0011 respectively; P-384 uses SHA-384).
   The other outputs are a seed, HMAC key, or AES-KW KEK. This public framing
   composes [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-2);
   it is a RequestSeal contract, not an externally registered signing profile.
3. Derivation uses derive/3 followed by commit/3 under the same operation deadline. Only an acknowledged atomic commit returns a usable child handle. A failed derive or an explicit commit refusal returns an ordinary error. A lost commit result triggers one release attempt under a fresh 1,000 ms context; confirmed destruction returns an ordinary error, while unconfirmed destruction returns {:cleanup_required, cleanup, error}. The redacted cleanup capability is caller-owned and may be retried through Custody.cleanup/2 until :ok.
4. Releasing a parent does not release its children. A custodian that implements
   `derive/3` also implements `commit/3` and `release/2`.

## Consequences

Custodians that support derivation implement three callbacks together. The derivation
string is part of the wire contract and changes only with a new version tag. The corpus
carries derivation vectors so other implementations can match. The pinned RFC 9180
vectors contain P-256 and X25519; P-384 is labeled as an independent Section 7.1.3
derivation. Symmetric children are compared by operations, never by exporting
material. Acceptance accompanies the implementation's qualified landing on main.
