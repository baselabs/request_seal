<!-- Status: proposed · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0031 — Gate 2.0 on paired performance measurements
Status: Proposed

## Context

The 2.0 JWE coordinator adds processes and a barrier, and batch decryption groups custody
calls. Either could be slower than 1.0.0 for a single token or a page of tokens. Benchmarks
on a shared machine vary more than the differences being measured.

## Decision

1. Two frozen workloads: a page of tokens over a 579-byte JSON payload with 1,299-byte
   tokens, and a single 299-byte token with a 32-byte plaintext.
2. The page gate is at most 4,200 microseconds median at load at most 51, over at least 5
   rounds, with a paired ratio of at most 1.00 against 1.0.0.
3. The single gate is at most 140 microseconds at load at most 30, with a paired ratio of at
   most 3.2.
4. Measurements use at least 20 alternating paired rounds on separate virtual machines.
5. The benchmark exits nonzero if any gate fails or is unmeasured.
6. Custody holder capacity is decided on a separate harness, not by these gates.

## Alternatives

1. **No gate; publish numbers.** No release dependency. A regression ships unnoticed.
2. **Gate on absolute numbers only.** Simpler harness. Hardware differences dominate
   without a paired baseline.

## Consequences

Code landing does not wait on the gates. The gate's verdict waits on a quiet, isolated
benchmark host, and the 2.0 release waits on that verdict. The coordinator's design is
under revision, so the thresholds and workloads can change before this record is accepted.
