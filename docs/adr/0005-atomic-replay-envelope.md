# 0005 — Claim replay atomically for the complete authenticated envelope

## Context

Nonce checking performed as a read followed by a write admits races. Claiming too early lets unauthenticated input poison a nonce; claiming each nested signature separately can make one valid nested envelope reject itself. A library cannot require a database or process, yet profiles such as Web Bot Auth may require real replay protection.

## Decision

An optional replay port atomically claims a caller-supplied commitment over one
validated signature's covered identifier and caller-defined security scope.
Profile, syntax, cryptography, digest, freshness, and trust checks precede commitment and storage.
Required missing/ambiguous input, callback/store failure, cancellation, or deadline fails closed.

## Consequences

Verification has a deliberate external commit point. A caller that retries after an indeterminate store outcome must treat the result as indeterminate, not automatically replay. Backends carry explicit operational guarantees and real concurrency evidence.

## Acceptance

- Real concurrent backend claims have one winner per namespace and commitment.
- Direct and adapter paths use the same verified inputs and callback contract.
- Retention changes never alter commitment identity or consume invalid input.
- Required missing/failed callbacks and unavailable stores reject authenticated success.
- Actual backends exercise expiry, reclamation, restart, and distributed-node guarantees.

## Selected-signature scope

One claim covers one label's authenticated components and parameters; labels do not enter identity.
[RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2) and [ADR 0025](0025-single-label-public-verification.md) define the boundary.
