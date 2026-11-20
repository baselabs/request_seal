# 0009 — Make an independent corpus the Elixir–TypeScript semantic contract

## Context

Elixir and TypeScript must implement the same wire/profile semantics natively. Sharing runtime code would violate that goal; separate hand-authored fixtures can agree only accidentally and drift in canonicalization, number ranges, JSON duplicates, base encodings, ECDSA representation, and rejection behavior.

## Decision

Own one language-neutral, immutable corpus with provenance. Each case contains source identity, exact input occurrences/bytes, selected profile/revision, policy, expected signature base or digest, expected output bytes or stable rejection rule ID, and evidence class. Binary values use an explicit self-identifying encoding; JSON numbers/strings and duplicate member occurrences are represented without passing through a lossy host map.

Expected values come from primary published vectors, definitive provider bytes, or independently reviewed derivations. Neither implementation may regenerate expected values during a conformance run. Both native packages consume the same files, verify a manifest digest, and run reciprocal signing/verification in separate processes. Language-specific APIs remain idiomatic around the shared semantics.

## Consequences

Corpus changes are compatibility-sensitive reviews. A source correction may change both implementations, but the change is visible as data with provenance rather than hidden in one codebase. TypeScript can choose native types and error classes while mapping to stable semantic rule IDs.

## Acceptance

- Every corpus file is consumed once by both implementations, with inventory/result cardinalities tied out.
- Intentional expected-byte and rejection-rule tampering fails each consumer.
- Reciprocal tests use separate native processes and fresh outputs.
- Published/provider cases retain source revision and immutable bytes; unresolved source ambiguities have no invented golden output.
- Unicode, numeric bounds, duplicate names, Structured Fields ordering, base64/base64url, raw targets, trailers, and ECDSA encodings have positive and negative cases.

## Corpus layout and publication

`corpus/` contains licensed immutable source bytes and provenance under `sources/<origin>/`,
canonical manifests under `cases/<surface>/`, and an `index.json` digest inventory.
The index records case IDs, surface/class, batch counts, and an executed known-positive case.
Manifests carry source, evidence, inputs, explicit policy/clock, and independent expected results.
Named batch formats cover HTTP WG Structured Fields, Wycheproof, and RFC 9421 bases.
Numbers are tagged decimal strings; bytes use unpadded base64url objects.
Verification facts use fixed members, canonical objects, and ordered component/parameter arrays.
The [format reference](../reference/corpus-format.md) defines schemas and refusal rules.
Dispatch-only publication builds digest-verified deterministic `corpus.tar.gz` and
`corpus.sha256` assets. After reading publication back, the maintainers tag the
published commit and attach them to its GitHub release; tag pushes execute no workflow.
Publication can resume from a later dispatch after held uploads are approved.
The anonymous Hex release checksum must match the inspected package's outer SHA-256;
only missing archives upload, and retired or differing versions refuse. Readback
compares the package byte for byte and identifies the served docs by the commit their
`release.json` names, before tagging that commit and creating the GitHub release. All
consumer assets, with the served docs archive, leave the job as one `release-assets`
artifact for that release.
Neither runtime package ships the corpus; the TypeScript repository vendors its selected release.
The Elixir runner's pin changes atomically with the local index and protects inventory integrity.
The independent TypeScript pin protects cross-language identity by tag, commit, and index digest.
A self-consistent local repin does not establish counterpart adoption.
A case ID `<surface prefix>/<name>` requires `cases/<surface prefix>/<name>.json`.
`@request-seal/core` pins corpus and error vocabulary to its selected public release ([ADR 0022](0022-typescript-conformance-contract.md)).
