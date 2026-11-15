<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0021 — Keep every corpus case at its surface folder
Status: Accepted

## Context

The conformance corpus in [ADR 0009](0009-cross-language-corpus.md) is consumed by more than
one implementation. When new key-management and cross-library cases landed at the root of
`cases/`, a case's id, its manifest path and its surface no longer agreed, and each
consumer had to guess where to look. Corpus vectors also include published private keys
and secrets that a secret scanner flags.

## Decision

1. A case id is `<surface prefix>/<name>`, where the surface prefix is the surface up to
   its first `.` and the name holds no `/`. Its manifest is `cases/<id>.json`; for example,
   `cases/jws/` holds `jws.sign` and `jws.verify` cases.
2. The Elixir corpus consumer rejects any disagreement between the ID, its surface prefix and the exact cases/<id>.json manifest path. The TypeScript consumer already reads nested manifests, but must add the same equality checks and named rejection tests as part of its 0.6 parity work. The shared index contract requires that layout.
3. The secret-scan configuration lists every published or generated test vector in the
   corpus by exact file, so a new secret anywhere else still fails the scan.

## Alternatives

1. **A flat `cases/` folder.** No layout rule. Hundreds of files share one folder, and the
   id carries no route to its surface.
2. **A path-wide scanner exemption for `corpus/`.** One line. Any secret placed under the
   corpus would pass unnoticed.

## Consequences

Adding a case means choosing its surface first. The RFC 3394, RFC 7518, RFC 7520, RFC 7748,
RFC 8037, Wycheproof and cross-library cases live under `jwe/` and `key_management/`. Each
new vector file needs an exact scanner entry. The rule is documented in
`docs/reference/corpus-format.md`.
