# 0029 — Proposed: Adopt ash_onetime 2 custody and an install-bound replay store

## Context

The ash_onetime integration ([ADR 0005](0005-atomic-replay-envelope.md),
[ADR 0008](0008-toolchain-and-compatibility.md)) uses ash_onetime for replay
storage. The ash_onetime 2.0 line adds a key-custody behaviour and binds storage to an
install, so one host can run several installs without sharing replay state.

## Decision

1. `RequestSeal.AshOnetime.Custody` implements `AshOnetime.KeyCustody` over RequestSeal
   custody handles.
2. `RequestSeal.Replay.AshOnetime.store` takes exactly `:install` (required, which is
   breaking), `:partition` and `:prefix`.
3. Every `RequestSeal.Replay.Error` stays nonretryable. The host application creates and
   holds the install; the library never creates one.

## Consequences

This slice waits on the ash_onetime 2.0 release, and so does the public 2.0 release
([ADR 0023](0023-public-version-line-and-2-0-boundary.md)). The ash_onetime range in
`mix.exs` moves to the 2.x line. This record stays Proposed until the change lands on the
main branch.
