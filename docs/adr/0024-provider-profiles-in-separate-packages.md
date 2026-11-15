<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0024 — Keep provider-specific profiles in separate packages
Status: Accepted

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

## Alternatives

1. **Bundle provider profiles in the core.** One dependency for integrators. The core would
   change on every provider's schedule and carry rules it cannot verify against a standard.
2. **Publish profiles as documentation only.** No package to maintain. Each integrator
   would reimplement the profile and its tests.

## Consequences

A provider profile that once lived in this repository moved to a separate package
([LEGACY](LEGACY.md)). Changes to the profile extension surface are breaking for those
packages and wait for a major release.
