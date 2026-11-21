# 0027 — Accepted: Replace raw-key closures with key handles

## Context

In 1.x several entry points accept a closure that returns raw key bytes or performs a
private-key operation: JWS resolvers, the JWE unwrapper, the HTTP `signer` and
`verify_fun` policy types, and the accept-signature fulfillment path. Several 1.x closure paths already run inside deadline-bound workers; neither a closure nor a handle by itself cancels an external service’s work. Handles provide one explicit algorithm binding, capability set, context, redaction and release contract. Removing the closure alternatives makes the library’s private-key operations use that single audited custody contract; it does not prove that caller memory never contained a key. [ADR 0004](0004-key-custody-and-discovery.md) introduced handles,
but the closure forms remained beside them.

## Decision

1. Every private-key operation takes a `RequestSeal.KeyHandle`.
2. A JWS resolver answers with a `RequestSeal.PublicKey`, a `:verify` handle, or
   `:embedded` ([ADR 0015](0015-jose-protected-members-and-embedded-keys.md)).
3. JWE encryption takes a public RSA, EC or X25519 recipient key, or a `:wrap` handle. JWE
   decryption takes `key:` only ([ADR 0016](0016-bounded-jwe-open-coordinator.md)).
4. The `signer` and `verify_fun` policy types are removed.
5. Accept-signature fulfillment takes a list of handles with distinct algorithms; when no
   handle fits, it returns `:negotiation_unfulfillable`.
6. The strict JSON object decoder lands in the same slice
   ([ADR 0028](0028-strict-json-object-decoding.md)).

## Consequences

Every 1.x closure call site changes in 2.0, and the upgrade guide must show the handle form for
each. Applications with keys in an external service implement the custody behaviour
instead of a closure. This decision is accepted for the 2.0 key-handle API.
