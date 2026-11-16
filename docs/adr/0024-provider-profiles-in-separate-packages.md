# 0024 — Keep provider-specific profiles in separate packages

## Context

`RequestSeal.Profile` lets a package add a header contract, a key directory, a default
component set or a replay rule on top of generic RFC 9421 verification. A profile for one
provider changes when that provider changes its rules, carries that provider's test data,
and serves only that provider's integrators. [ADR 0001](0001-library-boundary.md) keeps
the core standards-only.

## Decision

1. The public package ships only profiles defined by open standards.
2. A provider-specific profile lives in its own package, built on `RequestSeal.Profile` and
   the public behaviours, with its own release cadence and support terms.
3. `RequestSeal.Profile` is under the compatibility promise, so a separate profile package
   can depend on a stable major.

## Consequences

Profile extension changes are breaking for dependent provider packages and require a major release.
