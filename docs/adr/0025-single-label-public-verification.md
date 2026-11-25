# 0025 — Verify one selected signature label in the public package

Status: Superseded for quorum verification by [ADR 0043](0043-quorum-replay-commitment.md).
`RequestSeal.verify/3` still selects one label. Use `RequestSeal.verify_quorum/3`
with an explicit `RequestSeal.Quorum` policy for a multi-signature verdict.

## Context

Earlier records ([ADR 0005](0005-atomic-replay-envelope.md), [ADR 0006](0006-verification-results-and-observability.md),
[ADR 0011](0011-public-contract-provenance.md)) described multi-signature quorum
verification with a distinct-key threshold. A quorum has to answer which keys count as
distinct, how partial failures and deadlines combine, and how replay applies to several
signatures. Those answers depend on deployment trust rules that a standards library cannot
state for every user.

## Decision

1. Public verification selects one signature label and verifies it. Replay claims exactly
   that selected signature.
2. Quorum verification, its policy, its telemetry event, the `:invalid_quorum` reason, the
   `:quorum` layer and the retryable deadline error are not part of the public package.
   Every RequestSeal.Error is nonretryable. Other public error types keep their documented retryability; RequestSeal.JOSE.Error marks :deadline_exceeded as retryable.
3. Ash authorization scope stays public.
4. Several signatures in one message remain verifiable; only their combination into a quorum
   is removed. `RequestSeal.verify/3` always verifies one label. Web Bot Auth verifies every
   selected signature, including nested ones, when replay is `:not_required`; with required
   replay, more than one selected signature rejects as `:unexpected_signature` at `:policy`
   after the signatures pass and before any claim ([ADR 0005](0005-atomic-replay-envelope.md)).

## Consequences

An application that requires several signatures composes independent single-label verifications under its own trust and replay policy. The first stable release shipped without quorum; this decision supersedes the earlier records’ quorum and threshold contracts.
