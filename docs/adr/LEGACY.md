<!-- Status: maintained · Kind: decision index · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# Retired decision records and roadmap rows

Decision record numbers and roadmap row IDs are never reused. This index records each one
that no longer governs the public package and where its subject went.

## Decision records

| Record | Subject | Disposition |
|---|---|---|
| 0012 | Envelope profile for one provider | Moved to a separate provider package ([ADR 0024](0024-provider-profiles-in-separate-packages.md)). |
| 0014 | Retired record | Does not govern this public package. |

## Roadmap rows

| Row | Subject | Disposition |
|---|---|---|
| multi-signature | Quorum verification over several signature labels | Removed from the public package in 1.0.0 ([ADR 0025](0025-single-label-public-verification.md)). Accept-Signature negotiation and independent single-label verification remain public. |
| jose-compact-headers | Compact protected headers in caller order | Landed in 1.x. The 2.0 protected-member policy supersedes it ([ADR 0015](0015-jose-protected-members-and-embedded-keys.md)). |
| consumer-integration | Adoption by applications | Integration evidence lives with each application, not in this repository. |
| custody-openbao-transit | A custodian for one key service | Custodians for a named key service implement the `RequestSeal.Custody` behaviour in their own packages. |
| performance | Performance and concurrency baselines | Replaced by the 2.0 release gates (`RS-release-gates`, [ADR 0031](0031-performance-release-gates.md)). |
