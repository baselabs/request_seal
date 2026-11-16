# 0006 — Return layered verification facts and bounded safe diagnostics

## Context

A Boolean `valid?` collapses cryptographic verification, profile conformance, body integrity, freshness, replay, key provenance, identity, and authorization. This encourages callers to grant authority after a mathematically valid signature. Detailed errors can leak bodies, signature bases, tokens, keys, sensitive URLs, or attacker-controlled high-cardinality values.

## Decision

Return layered verification facts only after every required policy check succeeds.
Authorization is always `:not_evaluated`; no partial principal escapes on failure.
Errors and telemetry use bounded classifications without sensitive or attacker-controlled text.

## Consequences

The result type is richer and compatibility-sensitive. Callers can make explicit decisions without parsing strings. Safe defaults reduce diagnostic detail, so authorized troubleshooting uses controlled opt-in views rather than globally verbose logging.

## Acceptance

- Policy, attribution, content, freshness, replay, and storage outcomes stay distinct.
- Verification grants no authorization or payment approval.
- Sensitive canaries remain absent from values, inspection, errors, logs, and telemetry.
- Public reasons have bounded stable semantics, including cardinality and byte limits.

## Result boundary

Single-label results record algorithm, ordered coverage and parameters, content,
freshness, replay, and profile. Generic results are unattributed; Web Bot Auth
records caller-trusted association and provenance in its principal.
Generic resolution adds neither discovery provenance nor HMAC identity facts.
Default inspection omits principals and signature metadata.
`RequestSeal.Error` values are nonretryable and retain a random correlation token,
without callback text. Error reasons and layers are documented public contracts.
HMAC identity remains an opaque custodian-supplied value outside generic results.

## Telemetry boundary

`RequestSeal.Telemetry` defines six events: verify stop, Web Bot Auth verify stop,
replay claim, custody sign stop, custody wrap, and custody unwrap, with bounded measurements
and low-cardinality metadata. [ADR 0016](0016-bounded-jwe-open-coordinator.md) proposes JOSE coordination events.
