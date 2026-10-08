# ADR 0010: Treat documentation and Livebooks as tested public interfaces

- Status: Accepted
- Date: 2026-10-06

## Context

Cryptographic APIs fail in integration details: covered-byte selection, body lifecycle, proxy reconstruction, key provenance, replay timing, and authorization handoff. Generated module docs and copied snippets cannot prove these journeys. Livebook rendering also does not execute cells, and its exporter can omit unsupported/branching content unless the runner checks inventory explicitly.

## Decision

Organize documentation by complete user journeys and make every runnable example executable against the actual package. Provide Livebooks for environment, request/response signatures, components/trailers, body integrity, WBA, generic JOSE, custody, discovery/rotation, replay, Plug/Phoenix, Req/Finch, Ash authorization separation, diagnostics, interop, and operations.

The isolated notebook tool imports with pinned Livebook's real parser, rejects warnings/unsupported cells/undispatched branches, exports with the real exporter, and executes standalone Elixir child processes bounded to 300 seconds and 1 MiB of captured output each. It starts no Livebook web server. Each notebook names prerequisites, evidence class, assertions, one meaningful rejection case, cleanup, and external requirements. Credentials use named secret inputs and never appear in output. A missing real peer/store/custodian is reported as not executed and cannot become a passing substitute.

## Strongest alternatives

1. **ExDoc plus copied snippets.** It is easy to publish and search. It cannot establish execution or critical boundary behavior and copied output can go stale.
2. **Interactive Livebook-only verification.** It shows the best teaching experience. It is difficult to gate reproducibly and can hide branch/cell omissions.
3. **Unit tests only, documentation illustrative.** Tests can be exhaustive. Users still receive unverified integration instructions with different code paths.
4. **One broad demo notebook.** It reduces navigation. Prerequisites/evidence classes become tangled, failure localization worsens, and external flows encourage hidden skips.

## Deciding evidence and deletion test

OBSERVED in Livebook 0.19.10 source: importer/exporter APIs exist, exported branching-section handling is not a complete execution guarantee, and non-Elixir/smart cells require classification. Delete executable journey artifacts and callers must reconstruct dangerous ordering from reference prose; keep them. The notebook index describes available learning material and its evidence class; it does not duplicate internal work tracking.

## Consequences

Documentation failures block release like API failures. The tool graph remains separate from root runtime dependencies. External-profile notebooks require authorized real endpoints and never fabricate success. Accessibility and offline rendering remain part of documentation acceptance.

## Acceptance

- Every shipped `.livemd` is inventoried, parsed, classified, exported, and either executed or explicitly reported not executed with its real prerequisite.
- Failure, early successful exit, and omitted-cell/branch mutations turn the runner red; normal output without a final newline still completes. A fresh receipt proves the trusted export reached its end, not hostile-code containment.
- Runnable code fences are sourced from executed examples or doctests; design-only shapes are labeled proposed.
- Fresh local-path and packaged-artifact consumer runs execute the actual examples.
- Generated docs pass links/anchors, narrow-layout/browser accessibility review, and offline Markdown/EPUB checks where published.
- No notebook starts infrastructure, sends a payment instruction, or mutates an external account merely by opening.
