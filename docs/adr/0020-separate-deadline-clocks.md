# 0020 — Keep HTTP freshness, operation deadlines and body retention on separate clocks

## Context

Several bounds share the word "deadline" and were easy to read as one: signature freshness
in an HTTP verification policy, the deadline a custody or JOSE operation runs under, and
the time an adapter spends retaining a request body. They measure different things on
different clocks. A record that merges them invites a configuration that tightens one
while believing it tightens another.

## Decision

1. HTTP signature freshness (`created`, `expires`, maximum age and skew) is verification
   policy on the wall clock. It applies only when the policy sets it.
2. Custody operations carry an absolute monotonic deadline in RequestSeal.Custody.Context. Timeout options are 1 to 300,000 ms, with 5,000 ms defaults where documented. Custody expiry returns :deadline_exceeded. JWE decryption uses the explicit phase outcomes in ADR 0016: admission expiry is :deadline_exceeded at :input, resolution expiry is :key_resolver_failed at :key, unwrap expiry follows the :decryption_failed path, and unfinished content authentication is :deadline_exceeded at :crypto. Caller death is cancellation.
3. The Finch and Req adapters retain a request body for at most 16,384 chunks or 5,000 ms.
   That fixed bound applies only to request-body retention; Req response collection stops
   at 16,384 chunks or `:max_stream_bytes`.
4. The 2.0 JWE coordinator splits its operation deadline into resolve, unwrap and
   authentication clocks with required budgets
   ([ADR 0016](0016-bounded-jwe-open-coordinator.md)).
5. Documentation names which clock a bound uses and never describes one as another.

## Consequences

Operators tune freshness in the verification policy and work bounds per call. A slow
custodian cannot make a stale signature valid, and a short freshness window does not
shorten custody work. The README and guides state the 5,000 ms retention bound as a
request-body bound only.
