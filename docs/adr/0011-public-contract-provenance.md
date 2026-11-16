# 0011 — Keep application replay identity and public-source provenance explicit

## Context

[RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2)
describes nonce-based replay considerations without defining every application's security
scope. A reusable library must preserve this caller boundary. Provider profiles and
examples also need traceable public requirements rather than private consumer precedent.

## Decision

Accept a caller-supplied commitment function for replay. It binds the selected verified
nonce, challenge, or transaction identifier to the caller's declared security scope.
RequestSeal validates the selected profile first, invokes this function once for the
complete envelope, and submits its bounded result to one atomic claim. It provides no
application-specific commitment recipe. Required callback/input/store failures reject.
ADR 0005 defines timing, cancellation, and store behavior.

HMAC key-equivalence identity is an opaque nonsecret value supplied by the trusted
custodian. RequestSeal never derives it. Existing distinct-key policy and redaction
requirements in ADRs 0004 and 0006 continue to apply.

Every public profile, corpus case, notebook, and integration example derives from a
cited public standard or public provider document. Publishing a nonstandard private
signing profile, verification-to-authorization composition, or private retry/recovery,
key-purpose, or address-selection mechanism requires explicit maintainer clearance.

## Acceptance

- Replay uses verified identifiers and caller-defined scope before one atomic claim.
- Missing/ambiguous inputs, callback/store failures, cancellation, and deadlines reject.
- Direct and adapter paths use the same callback contract; real backend races have one winner.
- HMAC equivalence identity stays opaque and custodian-supplied, with no secret derivation.
- Public examples retain cited sources and distinguish published vectors, local construction,
  and actual counterpart acceptance.

## Verification scope

Public verification selects one signature label ([ADR 0025](0025-single-label-public-verification.md)).
Opaque HMAC identity supports custody operations without adding public threshold policy.
