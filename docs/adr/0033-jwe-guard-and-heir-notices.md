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
private ordered-set notice table before its library link is removed. Deleting an
empty ordered set avoids the hash-set segment scan charge per child. Its exit
transfers the empty table to the guard. Before the registry sweep, the guard
records the end, deletes the notice and only then forwards completion. After
that sole sweep, it deletes each notice and joins it against the immutable
registry with scalar awaiting and coordinator-exit counters, without copying
the state map or growing the ended set per child. A custody slot proves that P3
already joined every resolver notice, so the sweep skips ended-set reads for
resolver slots while retaining every registry row. Ended-set checks read only the
stored pid; registry joins still require the caller-code role. Library processes
exit with closed atoms. The guard
checks ownership before every dequeue, kills the coordinator once, then sweeps
the inherited registry once. Coordinator ownership changing is the end marker;
queued transfer and EXIT messages cannot reopen causes. A reply outcome row
precedes the reply send and determines the guard's final reason.

R ends admission and resolution. U is the accepted resolution barrier plus the
unwrap budget. D ends content work. F = D + 100 ms independently ends a stalled
coordinator. An early resolution barrier retains its original U even if its end
notices arrive after R. R expiry is independent of an existing barrier and
preserves its original U. Every range shares that U; group intake counts members
directly. R and D rebuild positional state once per expiry; U likewise rebuilds
group state once, issuing all unfinished-group kills before summary traffic.
U notifies each live range once with the shared deadline, instead of sending a
timeout summary for every group. Per-group durations and item counts remain
intact. A terminal result updates only its position and settled count; admission
and resolution counters do not change when content work finishes.
At U, each worker revokes all remaining routes, authenticates each undelivered
prepared position once under its fallback, and rebuilds positional state once.
This includes positions whose member message is still queued, so late members
cannot start another expiry pass. An accepted delivery remains settled. Revoking
a route prevents new deliveries; the main worker receive discards queued outcomes for removed
positions without a separate mailbox scan per route. A range returns normally
as soon as no positions remain, including after U authentication; it does not
wait for the coordinator's reply, notice drain or reason-bearing link signal.
Normal range completion follows its last result send, preserving sender order
at the coordinator. Worker-end handling does not kill resolvers for settled
positions. A normal range has sent its contributions or expired them at U/D,
so its end never scans the custody-group map for missing contributions. An
unexpected range exit still notifies every unfinished group it contributed to.
U expiry releases revoked route and group maps and the old position map before
fallback authentication. The reply passes read their fixed tag and address once,
while retaining every ordered positional and group message. Other unfinished
ranges still end through D or the coordinator link during cancellation.
Callback children check caller-notice ownership and their deadline
immediately before entering caller code. After the registry flips, teardown ends
by anchor + B(n), where B(n) = 20 ms + 15 microseconds × n. The anchor is the
first caller-death observation, F, or min(now, D) for an otherwise uncaused end.
The caller stamps wait-end by F + B(n), before cleanup and telemetry handlers.
The accepted cardinality is published once in a second atomics cell; before
acceptance n = 0. The guard reads it once at the owner flip. Between a cause and
that flip it uses B(10,000). Absolute timers and receive waits round upward to
milliseconds from internal monotonic microseconds. Every caller wait phase
(notice intake, bootstrap, cancellation and result intake) wakes 10 ms inside
F + B(n). Upward rounding consumes less than 1 ms, leaving over 9 ms for timer
delivery, scheduling and the wait-end stamp under the release gate's reference
conditions. The public bound, accepted cardinality and K_pf remain unchanged.
The caller arms each wakeup as an absolute timer and cancels it when that phase
ends. Cancellation rechecks the accepted cardinality when waking, as result
intake does. The coordinator also arms R, U and D wakeups, and the guard arms
its stop deadline: descheduling between a clock read and a receive cannot start a fresh
relative wait beyond the absolute deadline.
The guard arms the temporary cancellation limit once as well, so it need not
convert the remaining timeout again for every child notice.

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
Serialization detection validates eight whitespace bytes, then compares the
binary with its eight-byte tail using OTP's native common-prefix search when
the next word repeats. A common prefix of length k proves that the first k + 8
bytes repeat that validated word, including a partial final repetition. The
classifier skips those bytes without copying them. Nonperiodic input advances
one word; a partial word uses byte steps. Each byte lane accepts only space,
tab, LF and CR. JSON openings are refused before attempting compact form. This
avoids compiling a 252-pattern automaton or allocating wide integers. JSON
trailing whitespace uses the same classifier. At most five scoped dot searches
then establish exactly four separators; the first search starts after the
already-classified whitespace.
There is no per-token regular expression compilation or backtracking. Allocation
is bounded independently of the number of dots. Leading whitespace remains part
of the original protected bytes, and parts reference the original token. Byte
classification yields through ordinary reductions; the Codec function consumes
each native dot-search result,
retaining its continuation while OTP yields. Placement suspends first, then
checks that stack for the actual Codec unit; it never depends on the native
continuation's current function name. The checkpoint unit remains one
whole token, including its separator scan and accounting.

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

The committed reduction oracles and 73 distinct reversing mutations check constant reaction,
linear complete teardown, queue bounds, guard heap and caller wait-end. A
mutation selects its test by the manifest's exact test name, with an independent
check that the name exists exactly once in its file. Moving test lines cannot
change the selection. The past-F oracle first joins the guard, then rejects any
caller-notice transfer before asserting its deadline exit: a forbidden transfer
allows the already-expired coordinator and the guard's F check to race.
A reaction sample pauses the guard at its receive and joins caller death before
resuming it; the receive entry after the kill ends the measured interval before
another dequeue or the registry sweep. Topology samples install only the kill
and finish reduction dumps after placement, so setup does not trace every queued
end notice.
Placement collectors match each new event once. Sweep placement drains earlier
traces while the guard is suspended, then selects its first new sweep event
before processing unrelated traffic. The return collector checks its absolute
deadline before each dequeue, including under continuous
receive-timeout traces from a caller-bound mutation. It checks the caller result
before a trace barrier, then stops the producer before cleanup drains the queue.
A second trigger during a sweep requires both a verified registry owner flip
and a guard still paused in the sweep.
OTP fold helpers may have different arities; a helper frame must retain the
enclosing guard check. Byte-scan placements likewise require the codec
unit on the suspended process's stack.
A release gate measures the absolute bound and derives K_pf from byte units,
report send and preflight exit. Constants come from Bounds; no baseline ratio replaces them.
Final report measurements send the production row, count and control envelopes
from a sensitive process with an off-heap mailbox to an off-heap observer.
The report records the observer's actual queue flag. The consumer independently
recomputes the longest unit + maximum report send + maximum preflight exit.
Token units cover both compact input and a JSON candidate with mixed whitespace;
each sample retains the slower scan.
Timed topology samples keep the observer mailbox off heap and omit caller input
send traces and inherited receive traces. Coordinator sends establish placement,
then stop before the trigger. Lifecycle and required call traces remain active;
an isolated trace session filters receives to monitor deliveries and the single
handoff marker. Untimed message and ownership oracles retain their full traces.
Every observed birth receives a monitor owned by a dedicated high-priority,
off-heap receiver and must have both a processed DOWN and an end timestamp.
The receiver stamps the DOWN immediately, before forwarding it or inspecting
its own queue length. It performs no birth or lifecycle analysis. Ordinary
roles use the VM's monotonic exit trace timestamp.
[Sensitive roles](https://www.erlang.org/doc/apps/erts/erlang.html#process_flag/2)
suppress exit traces, so their end upper bound is the dedicated receiver's
DOWN receipt stamp. A receive trace in the scenario observer would instead
include the time until that busy process processes its monitor signal; it
cannot establish a sensitive process's exact exit time. The dedicated stamp
remains an upper bound, including that receiver's own scheduling, signal and
queue work. The gate retains the receiver queue length, independent observer
dequeue lag and complete birth and receipt counts for every role. The Python
consumer requires exact equality of those inventories. The timestamp is
converted from native units to the same microseconds as Bounds. The preflight
exit unit and cooperative exits use that same conservative upper bound. A trace
barrier also joins the isolated tracer's forwarded events before inspection.
Collection has a separate 10 s hang cap; it never uses B as its dequeue deadline.
After collecting, the gate judges the maximum end timestamp minus the original
anchor against the unchanged B. It retains every sample, placement, missing or
live role, late role and assertion failure before writing its final verdict.
Every sample also retains closed exit reasons, first and last end stamps per
role and reason, every library-only end, and arity-only coordinator U, reply
and finish call stamps. Caller-code reasons outside the known lifecycle atoms
are labeled without retaining their payload. These observations distinguish
normal worker completion from a shared coordinator exit without tracing
sensitive worker data. Custody callbacks run in the Unwrap child itself; this
path has no nested custody runner or guardian.
Range workers retain decoded protected headers only until sending their resolver
requests. They rebuild a successful Result's header from the same authenticated
protected segment, without reserializing it. Once a group contributes, its worker
positions drop handles, encrypted keys and key-management parameters; they retain
the original protected segment, algorithm and encryption, IV, ciphertext, tag,
width validity, per-position fallback CEK and delivery/group routing until settlement.
Every undelivered position still performs fallback AEAD.
Guard kill, owner-flip deadline calculation and finish calls, and coordinator
range-end and post-kill-pass calls, retain arities and timestamps only. Before
each timed placement, library-role snapshots retain queue lengths, memory and
reductions. The guard's single registry-fold return stamps the end of its kill
pass and retains only the scalar awaiting count. Caller exit-entry timestamps
distinguish exit-request delay from guard reaction. The caller-death interval
begins immediately before the kill request, conservatively before its notice
transfer; it includes no VM-wide
reduction-statistics barrier. Reduction oracles retain their separate barriers.
Custody placement sends its handshake only to the observer. An unused message
per custody group in the caller mailbox would force its selective receive to
rescan those messages for each positional and group result, creating quadratic
fixture work that competes with the library's teardown. No callback, sample,
input, role, cryptographic operation or deadline is removed by that correction.
A capped, incomplete lifecycle fails even if its observed timestamps fit B.
The linear-teardown reduction oracle reports an unfinished guard at the hang
cap as a teardown failure before asking for its finish reduction endpoint.
An incomplete coordinator pass likewise fails its linear-work assertion at its
existing hang cap. Placement collectors check one absolute deadline before
every dequeue, so queued traces cannot extend a cap. A capped trigger does not
enter a trace barrier while the incomplete producer is still running.
The caller stamps its own return immediately after the public call. The public
bound applies to wait-end by F + B, before cleanup and telemetry handlers; the
handler-free blocked-resolver peer checks both that marker and its return stamp.
Return collection has its own hang cap and cannot lose a result because an end
collection consumed a previously passed deadline.
Verify and the gate share the blocked-resolver driver, including the 30/20/5 s
policy, trace patterns, near-cap inputs and original U + B(10,000) end bound.
The driver holds the coordinator across R through U, queues its bounded wake,
then resumes it. This restores the due timer event of ordinary descheduling:
[debug suspension](https://www.erlang.org/doc/apps/erts/erlang.html#suspend_process/2)
pauses receive timeouts since OTP 28 and PID-addressed BIF timers since OTP 29,
including absolute timers. Without that event, the fixture can wait for a
worker's D exit to wake the coordinator instead of exercising its U transition.
Deadline placements consume events while waiting and poll the last two
milliseconds. An upward-rounded receive timeout and its timer tick must not
place a requested D - 1 ms resume after D. The K_pf derivation retains every
byte-unit, report and exit sample, including the first sample and residual
cooperative work. Unit setup records module-load state and loading time for
Codec and Worker before taking any byte-unit time.
Production enters Codec for policy and checkpoints before splitting a token,
and enters Worker.run before authentication, so loading those entry modules
is not part of either measured unit. Other helper loading remains in its
unit. Setup invokes no measured operation. Each scan sample retains both
compact and JSON timings as well as their maximum.
The token, JSON candidate and AEAD ciphertext are built before timing. All
five samples still include their own first data access, allocation, heap
growth and garbage collection within the unit; no sample is warmed or dropped.

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
The second-trigger reversing mutation reopens causes in the reached join loop;
the ended-state check clause remains necessary for the coordinator EXIT path.
Load and steal share 30 host-condition attempts; invalid placements have 20
attempts. Exhausting either budget fails and reports the observed attempts.
These are verification obligations, not one-run performance claims.

Whole-VM custody lifecycle assertions run in isolated peers and retain exact
process-set equality. HTTP caller-death checks trace every descendant of the
call while independently checking sockets and late wire requests. TLS test
publishers supervise the acceptor and each connection handler together; test
Agents and relays have test-supervisor lifetimes. Tracer and worker shutdowns
join process death, and failed JWE runtime placement destroys its trace session
and joins its processes through the same cleanup as a completed placement.

## Consequences

At most n + 35 library-owned processes coexist; at most 2n + 35 are created over
a call. Resolver and custody phases do not overlap. At most n + 3 ETS tables
coexist, with one two-cell atomics array. Single open creates six processes and
five tables over its lifetime. Large keyrings and custodian state belong behind
references. A callback's arbitrary unlinked descendants and external effects
remain outside library cancellation. Native cryptographic work and scheduler
availability are covered by the release gate's reference measurements.
