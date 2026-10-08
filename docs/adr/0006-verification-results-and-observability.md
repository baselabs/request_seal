# ADR 0006: Return layered verification facts and bounded safe diagnostics

- Status: Accepted
- Date: 2026-10-06

## Context

A Boolean `valid?` collapses cryptographic verification, profile conformance, body integrity, freshness, replay, key provenance, identity, and authorization. This encourages callers to grant authority after a mathematically valid signature. Detailed errors can leak bodies, signature bases, tokens, keys, sensitive URLs, or attacker-controlled high-cardinality values.

## Decision

Return a structured verification value only after the selected policy's required layers succeed. It includes per-label cryptographic facts, covered components, profile/revision/rule outcomes, digest status, freshness inputs, replay receipt, key provenance, and authenticated principal or explicit unattributed state. It always records authorization as `:not_evaluated`. Multiple-signature results retain the configured counting unit, required slots, deduplicated qualifying keys/principals/roles, per-signature coverage, and provenance. HMAC results explicitly record shared-secret possession and cannot imply unique signer attribution or public verifiability. HMAC key-equivalence identities are opaque custodian-supplied values that RequestSeal never derives. Trusted key-equivalence identities remain internal and redacted; ambiguous symmetric-key distinctness fails the required policy. The exact all/any/threshold and explicit composite-coverage contracts are defined in the architecture; labels never count toward a threshold and partial signatures never implicitly pool coverage.

Errors expose a stable, bounded reason code, layer, retryability, and correlation token. Default inspection, exceptions, logs, and telemetry exclude raw fields, bodies, signature bases/bytes, private or bearer material, identity tokens, full sensitive URLs, arbitrary key IDs, and unbounded peer text. Opt-in diagnostics use explicit redactors and remain bounded. Telemetry event names and metadata keys are versioned public contracts; metadata uses low-cardinality classifications.

## Strongest alternatives

1. **Boolean plus exception text.** It is easy to consume but erases why a request is or is not authenticated and turns messages into an unstable/leaky API.
2. **Return every partial layer on failure.** It is excellent for debugging. Callers can accidentally use an authenticated-looking subvalue from a profile-invalid envelope.
3. **Opaque success token only.** It prevents misuse but hides coverage/provenance needed for caller policy and auditing.
4. **Application-specific actor result.** It gives convenient authorization integration. It couples RequestSeal to caller identity/permission models and falsely equates authentication with authority.

## Deciding evidence and deletion test

RFC 9421 states that signatures cover selected components, while application profiles set acceptance; RFC 9530 requires independent content-digest semantics. Delete the layered result and each caller must reconstruct coverage, provenance, and trust distinctions from errors/options. Keep it. Delete a generic authorization layer and every caller gets a clearer boundary; authorization remains outside.

## Consequences

The result type is richer and compatibility-sensitive. Callers can make explicit decisions without parsing strings. Safe defaults reduce diagnostic detail, so authorized troubleshooting uses controlled opt-in views rather than globally verbose logging.

## Acceptance

- Cryptographically valid/profile-invalid, valid/unattributed, valid/body-unverified, stale, replayed, and store-failed cases are distinct.
- No result represents caller authorization or payment approval.
- Duplicate labels/key aliases, principal key rotation, role overlap, mixed trust, and partial-coverage unions obey the explicit threshold unit and per-signer requirements; results preserve the exact qualifying set.
- Sensitive canaries are absent from real error, inspect, log, exception, and telemetry paths.
- Every public reason is documented, bounded, searchable, and has stable retryability semantics.
- Cardinality and byte limits are measured under hostile input.
