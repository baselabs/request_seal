# 0031 — Gate 2.0 on paired performance measurements

Status: Accepted

## Context

The 2.0 JWE coordinator adds processes and a barrier, and batch decryption groups custody
calls. Either could be slower than 1.0.0 for a single token or a page of tokens. Benchmarks
on shared infrastructure vary with hardware and active load.

## Decision

1. Freeze two workloads using [compact JWE](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.1)
   and [AES-GCM key wrapping](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7).
   Each side generates tokens with the same recipe. A page contains 100 1,299-byte tokens
   over 579-byte JSON with nullable fields. The published 1.0.0 baseline collects decoded
   objects in order through an unwrap closure and ordered `Task.async_stream`. The candidate
   calls `decrypt_many/2` with `content: :object` through a custody handle. The 299-byte
   single token opens to a 32-byte plaintext without decoding, through an unwrap closure on
   1.0.0 and a GCMKW local custody handle on the candidate.
2. Run 24 rounds on fresh GitHub-hosted `ubuntu-24.04` VMs. Each VM runs the published
   baseline (A) and the candidate (B) as separate processes in A/B/A/B/A/B order. Each sample
   set uses 30 warmups, then the median of 15 pages or 2,000 single opens. A round's ratio for
   each workload is the median of its B sample sets divided by the median of its A sample sets.
3. Observe each sample set from immediately before its first page warmup through
   its final single-open sample. Admit the round only when all its sample sets
   satisfy the CPU limits. Subtract the measured BEAM process tree's user and
   system CPU time from the aggregate delta of user, nice, system, IRQ and softirq.
   Credit the CPU deltas of processes visible at both boundaries and the BEAM's waited
   child CPU delta after discounting pre-window CPU of descendants visible only at the
   start. Express steal and foreign CPU as percentages of total elapsed host CPU
   ticks `K`, counting guest time once in user and nice. For `C` logical CPUs,
   allow a resolution of `e = 100 × 4 × C / K` percentage points. The host and
   process counters each advance in whole USER_HZ ticks and can each lag by
   less than one tick per running CPU at each of the two boundaries. The
   per-workload self-check in hosted run 45240645239 reported 12.5%, −33.3%,
   11.1% and 16.7% foreign CPU over near-empty spans.
   Admit sample sets with steal at most `5 + e` and foreign CPU between `−e`
   and `10 + e`, inclusive. Retain raw host and process tree readings, signed
   foreign CPU, steal and `e`. A zero-tick span cannot be admitted. Any rejected
   sample set leaves its round unmeasured.
   One-minute load includes the measured workload itself and is retained for diagnostics.
   In round 10 of hosted run 45226491587, it rose from 3.28 to 4.17 on a four-vCPU
   runner with zero steal.
4. Across admitted rounds, the candidate median must be at most 4,200 microseconds for a page
   and 140 microseconds for a single open, each over at least five rounds. The median of the
   per-round paired ratios must be at most 1.00 for a page and 3.2 for a single open, each
   over at least 20 complete admitted rounds.
5. Publish only after the collector records a passing verdict for the dispatched commit.
   Any failed or unmeasured gate fails the run. The workflow keeps each round's evidence
   and the verdict. The qualification run exercises a reduced self-check of the measurements
   and evidence schema. Its collector prints foreign CPU, steal and resolution
   for every sample set without enforcing admission or the performance thresholds.
6. Custody holder capacity uses a separate harness, run once before release from a
   measurement branch that never lands. It compared (b), one serial holder per
   `RequestSeal.Custody.Local` handle with batch grouping in `decrypt_many/2`, against (a),
   one holder per online scheduler per handle chosen round robin. Each of 24 hosted
   ubuntu-24.04 VMs ran b/a/b/a/b/a in separate processes over 2-second windows, with
   single-token (S1) and page (P1) callers at 1, S and 4S, where S is the online scheduler
   count. Item 3's CPU limits applied to every window. The rule, fixed before the run,
   selects (a) only if the S1 throughput ratio a/b at 4S has a median of at least 1.5 and
   a 95% bootstrap lower bound above 1.2, the single-caller p50 latency ratios for S1 and
   P1 are at most 1.05, and the P1 throughput ratio at 4S is at least 1.0.
   Hosted run 45264120027 admitted all 24 rounds. It measured a median S1 throughput ratio of 0.999 at 4S (bootstrap
   lower bound 0.993), S1 and P1 single-caller latency ratios of 1.043 and 1.001, and a P1
   throughput ratio of 0.990 at 4S. It selected (b). The shipped holder stays one serial
   holder per handle; extra holders would multiply resident key copies without measured
   capacity gain.

## Alternatives

1. **Publish numbers without gates.** A regression may ship with the release.
2. **Gate on absolute numbers alone.** Hardware variation can dominate the comparison.

## Consequences

Qualification runs correctness tests, reversing mutations and the reduced
performance self-check on each candidate. The near-cap teardown gate measures
performance against the library's bounds. It consumed 23 of the 24 wall-clock
minutes in qualification run 45512607434, so publication runs it on the exact
dispatched release commit.
A teardown regression on `main` blocks every release until a fix lands. The
failed `teardown` job names the near-cap measurement and retains its report
as `jwe-teardown`.

Before stamping a release version, an approved release maintainer can run
the measurement in hosted CI while `main` is a development snapshot. In
GitHub Actions, open **Publish**, select **Run workflow**, and dispatch
`main` after confirming its `@version` in `mix.exs` is a development
snapshot. Keep that version in place through dispatch. Open the run's
`teardown` job and download `jwe-teardown`. That job runs
`python3 scripts/jwe_teardown_gate.py --output "$RUNNER_TEMP/jwe-teardown.json"`.
The workflow has no separate teardown-only dispatch. Its release identity
check refuses development snapshots before upload, and the release
dispatch repeats the gate on the release commit.

Host conditions can leave a release unmeasured. Each dispatch uses its
fixed round inventory and runs it once.
