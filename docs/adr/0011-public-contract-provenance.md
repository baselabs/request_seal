# ADR 0011: Keep application replay identity and public-source provenance explicit

- Status: Accepted
- Date: 2026-10-06

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
key-purpose, or address-selection mechanism requires explicit owner clearance.

## Strongest alternative

Derive application replay identities and symmetric-key equivalence inside the library,
then generalize consumer integrations into profiles. This centralizes caller setup but
also makes undocumented application semantics part of a portable protocol contract.
The caller and custodian ports preserve the necessary policy without that coupling.

## Acceptance

- Required replay uses verified identifier inputs and caller-defined scope; unvalidated
  input never invokes commitment or storage. Missing/ambiguous inputs and callback/store
  errors, cancellation, and deadlines reject without an authenticated success.
- Direct and transport adapter paths invoke the same configured callback contract;
  real concurrent store evidence establishes one winner for duplicate claims.
- HMAC aliases use the custodian's opaque equivalence value; unknown equivalence cannot
  satisfy a required distinct-key threshold, and no derivation or secret escapes.
- Public protocol examples record their cited source and distinguish published vectors,
  local construction, and actual counterpart acceptance.
