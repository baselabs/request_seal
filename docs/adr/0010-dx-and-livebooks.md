# 0010 — Treat documentation and Livebooks as tested public interfaces

## Context

Cryptographic APIs fail in integration details: covered-byte selection, body lifecycle, proxy reconstruction, key provenance, replay timing, and authorization handoff. Generated module docs and copied snippets cannot prove these journeys. Livebook rendering also does not execute cells, and its exporter can omit unsupported/branching content unless the runner checks inventory explicitly.

## Decision

Public documentation teaches complete user journeys with executable examples.
The isolated notebook tool uses Livebook's actual importer/exporter, rejects warnings,
unsupported cells and branches, and bounds each standalone export to 300 seconds and 1 MiB output.

## Consequences

Documentation failures block release like API failures. The tool graph remains separate from root runtime dependencies. External-profile notebooks require authorized real endpoints and never fabricate success. Accessibility and offline rendering remain part of documentation acceptance.

## Acceptance

- Shipped notebooks are inventoried, parsed, exported, and executed against the real package.
- Runtime failure, early successful exit, and omitted-cell/branch mutations reject.
- Runnable fences use evaluated examples or doctests; proposals stay visibly proposed.
- Credentials use named secrets; notebooks never start infrastructure or mutate external accounts on opening.

## Available notebooks

Environment, RFC Ed25519, sign/verify, Plug webhook, Web Bot Auth, and JOSE notebooks
are listed in [Executable Livebooks](../../livebooks/overview.md).
