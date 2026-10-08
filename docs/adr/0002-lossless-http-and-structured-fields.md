# ADR 0002: Preserve lossless HTTP evidence before interpretation

- Status: Accepted
- Date: 2026-10-06

## Context

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) signs derived components and field values whose meaning depends on ordering, raw request-target forms, parameters, trailers, and related-request context. [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html) defines Structured Fields types and limits, while fields that reference older RFC 8941 do not automatically gain newer Date or Display String types. Framework maps commonly discard duplicate order, raw encoding, or trailer timing.

## Decision

Adapters must construct a lossless `Message` from field occurrences and explicit transport facts before parsing or normalization. Preserve raw target, ordered duplicate field occurrences, headers versus trailers, raw field values, response status, related request, and body availability. Structured Fields use one bounded parser with an explicit schema per protocol field/revision. Parsed structures retain ordering where the source makes order significant and never authorize a type merely because the parser recognizes it.

Component derivation consumes only this model. It covers requests, responses, related requests, all nine RFC 9421 derived components, field components, `sf`, `key`, `bs`, `tr`, `req`, and `name` (required for `@query-param`; RFC 9421 Section 2.2.8). It also covers `Accept-Signature` and multiple labeled signatures. Adapters refuse verification when required evidence is unavailable.

## Strongest alternatives

1. **Normalize into a conventional map.** It is convenient for callers and framework adapters. It loses duplicate occurrence/order evidence and can authenticate bytes the transport never carried.
2. **Keep raw bytes only and let each profile parse them.** This maximizes fidelity but duplicates complex Structured Fields and component rules, increasing change amplification and inconsistent bounds.
3. **Framework-native structs as the core model.** This reduces translation in one stack but makes RequestSeal depend on framework normalization behavior and blocks portable TypeScript corpus semantics.

## Deciding evidence and deletion test

RFC 9421 sections 2–5 and Appendix B are the primary deciding source. Delete the lossless model and every adapter/profile must relearn occurrence order, raw targets, trailer location, and request/response association; the module is deep. Delete a separate parser per profile and callers get simpler, so duplicate parsers fail the deletion test.

## Consequences

Adapters have a stricter capture contract and may reject when a framework has already consumed or normalized needed bytes. The core remains independent of transport libraries. Structured Fields evolution becomes a schema/revision decision rather than an accidental parser upgrade.

## Acceptance

- Exact published signature bases round-trip for all RFC component forms.
- Duplicate, reordered, percent-encoding, empty path/query, response-context, and trailer mutations fail as specified.
- Parser work is bounded for bytes, members, depth, integers, decimals, and parameters.
- Known RFC 8941 fields do not accept RFC 9651-only types without an explicit field revision.
- Elixir and TypeScript produce the same bases and rejection rule IDs from the same occurrence model.

