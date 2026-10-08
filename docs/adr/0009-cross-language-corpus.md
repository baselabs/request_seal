# ADR 0009: Make an independent corpus the Elixir–TypeScript semantic contract

- Status: Accepted
- Date: 2026-10-06

## Context

Elixir and TypeScript must implement the same wire/profile semantics natively. Sharing runtime code would violate that goal; separate hand-authored fixtures can agree only accidentally and drift in canonicalization, number ranges, JSON duplicates, base encodings, ECDSA representation, and rejection behavior.

## Decision

Own one language-neutral, immutable corpus with provenance. Each case contains source identity, exact input occurrences/bytes, selected profile/revision, policy, expected signature base or digest, expected output bytes or stable rejection rule ID, and evidence class. Binary values use an explicit self-identifying encoding; JSON numbers/strings and duplicate member occurrences are represented without passing through a lossy host map.

Expected values come from primary published vectors, definitive provider bytes, or independently reviewed derivations. Neither implementation may regenerate expected values during a conformance run. Both native packages consume the same files, verify a manifest digest, and run reciprocal signing/verification in separate processes. Language-specific APIs remain idiomatic around the shared semantics.

## Strongest alternatives

1. **Generate TypeScript fixtures from Elixir.** It centralizes truth. Any Elixir defect becomes expected output and reciprocal tests become self-confirming.
2. **Share a Go/WASM core.** It eliminates semantic duplication. It is not a native implementation and adds a runtime/toolchain boundary.
3. **Maintain parallel fixture sets.** Each language is autonomous. There is no exact parity oracle and source updates can land on one side only.
4. **Use only official positive vectors.** They are independent and authoritative for covered cases. They do not cover profiles, rejection taxonomy, adapters, source ambiguities, or cross-language edge representations.

## Deciding evidence and deletion test

Delete the shared corpus and every implementation must relearn source provenance, expected bytes, and parity cases; keep it. Delete code-generation coupling and implementations remain independently checkable; do not generate one from the other. The corpus manifest and consumer inventory each include a known-positive entry so empty or truncated discovery cannot pass.

## Consequences

Corpus changes are compatibility-sensitive reviews. A source correction may change both implementations, but the change is visible as data with provenance rather than hidden in one codebase. TypeScript can choose native types and error classes while mapping to stable semantic rule IDs.

## Acceptance

- Every corpus file is consumed once by both implementations, with inventory/result cardinalities tied out.
- Intentional expected-byte and rejection-rule tampering fails each consumer.
- Reciprocal tests use separate native processes and fresh outputs.
- Published/provider cases retain source revision and immutable bytes; unresolved source ambiguities have no invented golden output.
- Unicode, numeric bounds, duplicate names, Structured Fields ordering, base64/base64url, raw targets, trailers, and ECDSA encodings have positive and negative cases.


## Amendment

October 8, 2026: the TypeScript counterpart is deferred; RequestSeal is Elixir only. The cross-language corpus format remains a design for later use.
