# 0022 — Hold the TypeScript package to pinned corpus, vocabulary and reciprocity

## Context

[ADR 0002](0002-lossless-http-and-structured-fields.md) and [ADR 0009](0009-cross-language-corpus.md) make the
TypeScript package `@request-seal/core` a peer of the Elixir library, judged by the shared
corpus. Agreement on vectors alone does not prove that the two implementations accept each
other's live output, or that they report the same error vocabulary.

## Decision

1. The TypeScript package pins the corpus by release tag, source commit and index SHA-256
   together, and verifies that pin before trusting the inventory.
2. It pins the Elixir error vocabulary to one source commit. Its CI re-extracts the
   vocabulary at that commit and fails on any difference.
3. A reciprocity suite runs rounds in both directions against the published Hex package:
   each side signs, encrypts or wraps, and the other verifies or decrypts.
4. The corpus pin and the vocabulary pin are separate and move separately. Today both name
   the commit behind `v1.0.0`; a repin to a new Elixir line updates both.

## Consequences

The TypeScript package moves to a new Elixir line only by a deliberate repin, and its next
minor line repins to the 2.0 corpus. A vocabulary or reciprocity drift fails TypeScript CI
rather than reaching users. The reciprocity suite depends on the published Hex package, so
it cannot cover an Elixir change before that change is released.
