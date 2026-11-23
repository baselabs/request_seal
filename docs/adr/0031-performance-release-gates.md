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
2. Run 20 rounds on fresh GitHub-hosted `ubuntu-24.04` VMs. Each VM runs the published
   baseline (A) and the candidate (B) as separate processes in A/B/A/B/A/B order. Each sample
   set uses 30 warmups, then the median of 15 pages or 2,000 single opens. A round's ratio for
   each workload is the median of its B sample sets divided by the median of its A sample sets.
3. Admit a round only when every sample window has one-minute load at most the host's logical
   CPU count and CPU steal at most 5%. Keep rejected observations as unmeasured rounds.
4. Across admitted rounds, the candidate median must be at most 4,200 microseconds for a page
   and 140 microseconds for a single open, each over at least five rounds. The median of the
   per-round paired ratios must be at most 1.00 for a page and 3.2 for a single open, each
   over at least 20 complete admitted rounds.
5. Publish only after the collector records a passing verdict for the dispatched commit.
   Any failed or unmeasured gate fails the run. The workflow keeps each round's evidence
   and the verdict. The qualification run exercises a reduced self-check of the measurements
   and evidence schema.
6. Custody holder capacity uses a separate harness.

## Alternatives

1. **Publish numbers without gates.** A regression may ship with the release.
2. **Gate on absolute numbers alone.** Hardware variation can dominate the comparison.

## Consequences

Code landing requires the harness self-check. Publication requires the full measurement
verdict. Host conditions can leave a release unmeasured. Each dispatch uses its fixed
round inventory and runs it once.
