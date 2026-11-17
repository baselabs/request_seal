# 0033 — Bound JWE teardown with a guard and heir notices

Status: Accepted.

## Context

JWE open combines untrusted input, caller-owned custody and callbacks that can
block or exit with arbitrarily large reasons. Cancellation cannot depend on the
coordinator finishing a pass, nor can callback reasons enter a library queue.
The admission, resolution, unwrap and content outcomes of
[ADR 0016](0016-bounded-jwe-open-coordinator.md) remain the public contract.

## Decision

A raw-monitored guard creates the caller notice, an ETS ended set and a protected
registry whose heir is the guard. The coordinator owns that registry while it
runs and registers every library-owned child. Each callback child receives a
private notice table before its library link is removed. Its exit transfers the
empty table to the guard; the guard records the end, deletes the notice and only
then forwards completion. Library processes exit with closed atoms. The guard
checks ownership before every dequeue, kills the coordinator once, then sweeps
the inherited registry once. Coordinator ownership changing is the end marker;
queued transfer and EXIT messages cannot reopen causes. A reply outcome row
precedes the reply send and determines the guard's final reason.

R ends admission and resolution. U is the accepted resolution barrier plus the
unwrap budget. D ends content work. F = D + 100 ms independently ends a stalled
coordinator. An early resolution barrier retains its original U even if its end
notices arrive after R. Every range shares that U; group intake counts members
directly and expiry visits each remaining group once. Revoking a route prevents
new deliveries; the main worker receive discards queued outcomes for removed
positions without a separate mailbox scan per route.
Callback children check caller-notice ownership and their deadline
immediately before entering caller code. After the registry flips, teardown ends
by anchor + B(n), where B(n) = 20 ms + 15 microseconds × n. The anchor is the
first caller-death observation, F, or min(now, D) for an otherwise uncaused end.
The caller stamps wait-end by F + B(n), before cleanup and telemetry handlers.
The accepted cardinality is published once in a second atomics cell; before
acceptance n = 0. The guard reads it once at the owner flip. Between a cause and
that flip it uses B(10,000). Absolute timers and receive waits round upward to
milliseconds from internal monotonic microseconds. The caller reserves one
millisecond of receive rounding inside F + B(n), so its wait-end stamp remains
inside that upper bound.

The caller walks input without bulk copying and sends one bounded item per
message, checking D and the stop flag first. Preflight checks each bounded unit
and each row handoff, cooperates by D + K_pf (5 ms), and exits. Policies excluding
single-open `protected.expected` have a 4,096-word bound including function
environments. Each expectation has a 4,096-word bound and 16,384 binary-byte
sum; each permitted UTF-8 name has a 16,384-byte bound before scanning. These
violations are `:invalid_policy`. Resolvers validate and digest their answer
before forwarding it, with the same word and binary-byte bounds for handles;
oversized answers are `:key_resolver_failed`. Sink delivery normalizes in its
sender. RequestSeal owns UTF-8 traversal on every library path.

Validation catches only explicit input failures. Unexpected library exceptions
and exits become `:internal_failure`, including a preflight exit without a final
report during the D drain. A successful validation report ends outer validation
verdicts; completion also requires the row handoff. Caller notice ownership is
retained through exception cleanup, and a guard past F keeps and deletes its
notice instead of transferring it to a caller that may already have returned.
A caller whose notice wait times out kills and joins the guard before draining
late transfers and deleting their tables. Error-class exceptions in every plain
library entry exit with a closed atom, keeping exception arguments out of logs.
A worker's unexpected exit settles its unfinished positions as internal failures.
The caller prepares every telemetry measurement before publishing any outcome;
telemetry's handler isolation preserves the completed result if a handler raises.

## Reasons

Teardown work is linear per child. B(n) represents that work directly while
retaining the 10,000-item admission cap; reducing the item cap would change the
supported batch size. A constant reaction is separated from the bounded sweep.
ETS and an off-heap guard mailbox keep reaction state independent of n. End
notices avoid copying caller-sized exit reasons. The inherited registry remains
complete even when the coordinator stops between process creation and handoff.

The committed reduction oracles and 69 distinct reversing mutations check constant reaction,
linear complete teardown, queue bounds, guard heap and caller wait-end. A
reaction sample pauses the guard at its receive and joins caller death before
resuming it; the receive entry after the kill ends the measured interval before
another dequeue or the registry sweep. Topology samples install only the kill
and finish reduction dumps after placement, so setup does not trace every queued
end notice.
Placement collectors match each new event once. A second trigger during a sweep
requires both a verified registry owner flip and a guard still paused in the sweep.
A release gate measures the absolute bound and derives K_pf from byte units,
report send and preflight exit. Constants come from Bounds; no baseline ratio replaces them.
Final report measurements send the production row, count and control envelopes
from a sensitive process with an off-heap mailbox to an off-heap observer.
The report records the observer's actual queue flag. The consumer independently
recomputes the longest unit + maximum report send + maximum preflight exit.
Timed topology samples keep the observer mailbox off heap and omit caller input
send traces, whose copies would make the observer retain the entire batch.
Coordinator control traces and a monitor for every observed birth remain active.
The observer consumes each event once without selective scans for end notices.

Samples require Linux load average at most available host logical CPUs
(falling back to the main node's online schedulers when availability is unknown) and aggregate CPU
steal at most 5% across the sample window. Raw counters, load, CPU model, logical
CPU count, online schedulers, OTP release and headroom accompany measurements.
The Python runner independently brackets the run with Linux CPU and load
readings, rejects regressing or out-of-bracket per-attempt counters, and checks
load against both the recorded admission capacity and its own CPU count.
Counter windows span at least 20 ms, outside the timed units, to admit short
units only with a measurable CPU accounting denominator. A zero elapsed window
is rejected and consumes a host-condition attempt on both sides.
Load and steal share 30 host-condition attempts; invalid placements have 20
attempts. Exhausting either budget fails and reports the observed attempts.
These are verification obligations, not one-run performance claims.

## Consequences

At most n + 35 library-owned processes coexist; at most 2n + 35 are created over
a call. Resolver and custody phases do not overlap. At most n + 3 ETS tables
coexist, with one two-cell atomics array. Single open creates six processes and
five tables over its lifetime. Large keyrings and custodian state belong behind
references. A callback's arbitrary unlinked descendants and external effects
remain outside library cancellation. Native cryptographic work and scheduler
availability are covered by the release gate's reference measurements.
