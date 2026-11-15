<!-- Status: proposed · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0016 — Open JWE through one bounded coordinator
Status: Proposed

## Context

In 1.x, `RequestSeal.JOSE.JWE.decrypt/2` opens one token per call through a middle process,
and a resolver may return a raw-key closure. An application that opens a page of tokens
runs its own task per token; each pays a custody round trip and holds a content key in a
process the library does not control. One deadline covers resolution, unwrap and content
authentication, so a slow resolver spends the authentication budget, and the outcome at
expiry depends on which step was running.

## Decision

1. `JWE.decrypt/2` and `JWE.decrypt_many/2` share one lifecycle. No plaintext leaves before full authentication, and a batch releases none before its final list. Indexed custody delivery follows [ADR 0017](0017-indexed-unwrap-through-a-sink.md).
2. The decrypt policy has exactly `:algorithms`, `:encryption`, `:max_plaintext`,
   `:timeout`, `:resolve_timeout`, `:unwrap_timeout`, `:key_resolver` and `:protected`
   ([ADR 0015](0015-jose-protected-members-and-embedded-keys.md)), plus the optional
   `:content` ([ADR 0028](0028-strict-json-object-decoding.md)). Budgets are required
   integers from 1 to 300,000 ms with `resolve_timeout + unwrap_timeout < timeout`.
3. From call start t0 there are three clocks. R = t0 + `resolve_timeout` ends admission and
   resolution. U = the end of resolution + `unwrap_timeout` ends custody unwrap.
   D = t0 + `timeout` ends content authentication. Admission unfinished at R returns
   `:deadline_exceeded` at `:input`; a resolver unfinished at R returns
   `:key_resolver_failed` at `:key`; an unwrap unfinished at U still authenticates under a
   prepared random content key and returns `:decryption_failed` at `:crypto`; content
   authentication unfinished at D returns `:deadline_exceeded` at `:crypto`. The caller
   waits at most a fixed 100 ms after D for finalization.
4. A fallback content key is drawn before key management on every path. Refusals, failed unwraps and unwrap expiry still authenticate under the fallback and return `:decryption_failed` at `:crypto`. Successful plaintext requires an accepted, width-valid key delivery and full authentication. The content-authentication event carries only `outcome: :ok | :failed`.
5. The resolver returns `:error` or exactly `{:ok, %{algorithm: same_alg, key: handle}}`,
   where the handle binds `{:jwe, alg}` and grants `:unwrap`. A closure entry is refused
   ([ADR 0027](0027-key-handles-replace-closures.md)).
6. `decrypt_many/2` takes items of exactly `:token` and `:expected`. Its policy adds
   `:max_tokens` (1 to 10,000), `:max_total_input` and `:max_total_plaintext` (1 to
   67,108,864 bytes each), and `:protected` holds only `:permitted`. All aggregate limits
   apply before key work. An unwrap failure or timeout preserves accepted per-index results.
7. `decrypt_many/2` returns `{:ok, results}` in input order, including `{:ok, []}`, each
   result being what `decrypt/2` would return for that item. The only outer errors are
   `:invalid_policy`, `:invalid_serialization`, `:limit` and `:deadline_exceeded` when
   finalization misses D + 100 ms.
8. Caller death cancels the operation without returning partial plaintext.

## Alternatives

1. **Keep per-token decrypt and let callers parallelize.** No new function. Every token pays
   its own custody call, and content keys live in the caller's tasks.
2. **One timeout split internally by fixed proportions.** Fewer options. The split hides
   which phase failed and cannot be sized to the caller's `:max_plaintext`.
3. **Stream plaintext per item as it authenticates.** Lower latency for early items. It
   releases plaintext before the batch's terminal decision and complicates cancellation.
4. **Default budgets.** Shorter calls. No default fits every plaintext bound and custody
   latency.

## Consequences

This record states the external contract. The internal process structure is recorded here once its design passes review.

Budgets become required in 2.0, and closure resolvers stop working for decrypt. Batch
telemetry carries only `count`, `groups`, `failed` and `deadline_exceeded`; custody unwrap
carries only `duration` and `items`. The `jwe.decrypt_many` corpus surface carries the
cross-language cases. Performance gates for the single and page workloads are in
[ADR 0031](0031-performance-release-gates.md). The coordinator's design is under revision;
the numbers above can change before this record is accepted, and it stays Proposed until
the change lands on the main branch.
