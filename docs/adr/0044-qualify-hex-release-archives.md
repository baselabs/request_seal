# 0044 — Qualify the exact Hex release archives

Status: Accepted

## Context

Building package and docs archives again at publication can produce different bytes
from those checked in qualification. A later default-branch head may also differ
from the release commit. Publication needs the exact qualified bytes and a boundary
between project code and the registry write identity.

## Decision

1. Use the pinned [shared Hex action](https://github.com/baselabs/.github) for
   qualification, upload and read-back. Declare the root package, exact archive file
   inventory and requirements in `.github/hex-packages.json`. Produce and attest the
   package, HTML docs, corpus and SBOM under the qualified commit.
2. Require a full qualified `release_commit` for default-branch dispatch. Publication
   is cache-free. This amends [ADR 0031](0031-performance-release-gates.md)'s publishing
   job description. The paired performance verdict and teardown measurement still
   gate the upload on that release commit and run without the publish environment.
3. Upload is the only job in environment `publish`. The action reads public release
   metadata anonymously and checks the organization for conflicting versions using
   the API-read key scoped to the upload step. Public and organization releases for
   one OTP application carry distinct versions. The upload action plans against
   qualified bytes before exchanging a package-scoped token.
4. Read-back uses the selected run and its manifest digest. It compares both served
   archives with the qualified bytes, verifies attestations for all consumer assets
   against the commit in the docs and hands `release-assets` to release maintainers.
   They create the GitHub release and the `baselabs_request_seal-v<version>` tag on
   that commit. The packaged changelog supplies the release notes.

## Consequences

An approval retry explicitly selects the original qualification so it reuses the
same archives. A previously published archive or docs record whose bytes or commit
differ refuses read-back. Historical `v<version>` tags still identify their original
releases. See the [release runbook](../operations/releases.md).
