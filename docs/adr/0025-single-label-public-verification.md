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

## Original decision for 1.0

1. Public verification selected one signature label and verified it. Replay claimed exactly
   that selected signature.
2. The 1.0 package omitted quorum verification, its policy, telemetry event,
   error reason and layer. All `RequestSeal.Error` values in 1.0 were nonretryable.
3. Ash authorization scope stayed public.
4. `RequestSeal.verify/3` could verify each label separately. Web Bot Auth verified every
   selected signature, including nested ones, with `replay: :not_required`. With required replay,
   it rejected multiple selected signatures as `:unexpected_signature` at `:policy`
   after signature verification and before the claim ([ADR 0005](0005-atomic-replay-envelope.md)).

## Consequences for 1.0

Applications that required several signatures composed independent single-label
verifications under their own trust and replay policies.
