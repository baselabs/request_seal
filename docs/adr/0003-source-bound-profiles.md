# ADR 0003: Make profiles source-bound and ambiguity fail-closed

- Status: Accepted
- Date: 2026-10-06
- Updated: 2026-10-08

## Context

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) delegates coverage,
algorithm, freshness, and trust decisions to applications. The
[Web Bot Auth protocol-00 draft](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00)
selects dictionary-member `Signature-Agent`, exact tags, discovery, and nested
coverage. A different source revision may select different acceptance rules.
Generic signature validity alone establishes none of those profile predicates.

## Decision

Every verification selects one exact source-bound profile before parsing
profile-specific fields. Generic RFC 9421 uses explicit caller policy; Web Bot
Auth selects the exact draft revision. Extension packages own other named
application profiles through [ADR 0013](0013-extension-profile-boundary.md).

There is no legacy, generic, or closest-profile fallback. A profile records
source anchors and its acceptance predicates. Conflicting source text or
examples do not broaden the accepted wire language. Preserve exact signed
bytes and reject ambiguity-dependent input until authoritative rules or
independent definitive bytes select an interpretation.

## Strongest alternatives

1. **One evolving profile name without a revision.** It conceals acceptance changes when an external draft changes.
2. **Permissive aliases and canonicalization.** They may accept a different preimage than the producer signed.
3. **Treat a sample implementation as normative.** It provides executable bytes but cannot override its cited standard.

## Deciding evidence and deletion test

The Web Bot Auth draft establishes its own field, label, discovery, and nested
signature rules. Its published Appendix E cases remain independent inputs,
including cases that reject the selected profile. The
[standards reference](../reference/standards.md) identifies the sources and the
[testing guide](../guides/testing.md) separates construction from conformance
and peer acceptance. Delete named profile boundaries and each caller must
reconstruct revision-specific coverage, algorithm, freshness, and trust rules.
Keep the boundary; reject aliases that silently broaden another profile.

## Consequences

Callers select and migrate source revisions explicitly. Profiles share RFC
machinery while retaining distinct acceptance predicates. Results expose the
selected profile and revision. A profile stamp remains descriptive; consumers
allowlist trusted verification implementations.

## Acceptance

- Cross-profile replay and tag/representation substitution reject.
- Web Bot Auth protocol-00 selects exact field and nested-coverage predicates.
- Positive and rejection evidence identifies the selected source revision.
- No spelling, algorithm, or encoding alias exists without definitive source evidence.
- An ambiguity-dependent feature cannot be advertised as conformant before its evidence is resolved.
