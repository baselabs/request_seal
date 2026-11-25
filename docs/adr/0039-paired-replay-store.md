# 0039 — Require both replay stores during migration

Status: Accepted.

## Context

[RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2)
describes detecting replay with a nonce. Moving storage must preserve the
refusal of nonces already recorded anywhere in the verification boundary.

## Decision

Claim the destination first and consult the retiring store only when the
destination inserted the claim. Supply the same absolute deadline to both
operations. Run the pair under a cancellable worker that covers adapter calls
and synchronous telemetry, including direct pair calls. Validate the context
before invoking either store. Leave completed writes in place on every
failure. Sweep each store with the same clock and deadline.
ETS checks the requesting process and local lifetime owners before accepting a
queued claim for insertion. External commits can remain indeterminate after
cancellation if a peer has already accepted the write.

The destination must preserve and share each claim across every verifier that
may receive it throughout retention, including across restarts and routing
changes. An ETS destination is refused with a retiring adapter other than ETS.
Two ETS stores are suitable only within one verifier with continuous state.

Deploy the pair to all writers before switching any writer to destination only.
Keep the retiring store in use until its last possible retiring-only claim has
aged out, accounting for the maximum retention and clock differences.

## Alternatives

Copying retained rows during live writes leaves a gap for concurrent inserts.
Writing a single store on failure can let traffic bypass the replay history.
Deleting the first write on a second-store error races retries and cannot
resolve an indeterminate remote commit.

## Consequences

A failed attempt can spend its nonce at the destination. Operators own both
stores, their retention, and the rollout window. A pair preserves the replay
boundary the retiring store already provides.

The corpus exercises a fresh claim, both duplicate positions and resulting
store states, and repeated store reference refusal.
