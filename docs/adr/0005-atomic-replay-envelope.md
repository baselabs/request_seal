# ADR 0005: Claim replay atomically for the complete authenticated envelope

- Status: Accepted
- Date: 2026-10-06

## Context

Nonce checking performed as a read followed by a write admits races. Claiming too early lets unauthenticated input poison a nonce; claiming each nested signature separately can make one valid nested envelope reject itself. A library cannot require a database or process, yet profiles such as Web Bot Auth may require real replay protection.

## Decision

Define an optional replay port with one atomic `claim` operation. A caller-supplied commitment function binds a verified nonce, challenge, or transaction identifier to a security scope the caller defines. RequestSeal accepts that function and its bounded result; it neither derives the commitment nor supplies an application-specific recipe. The selected profile identifies the required authenticated replay identifier and validates its binding. A required policy rejects when that identifier, caller function, scope, or required store is unavailable or ambiguous.

Validate syntax, cryptography, digest, required linked objects, freshness, and trust association before invoking the commitment function and store. Claim exactly once for the complete validated envelope before returning authenticated success. Commitment and store errors, cancellation, and deadlines fail closed when replay is required. Generic cryptographic verification remains available with replay explicitly not evaluated. Retention metadata follows the authenticated validity window and never changes the caller-supplied uniqueness value. [RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2) describes nonce and replay considerations; application replay scope remains caller policy. [ADR 0011](0011-public-contract-provenance.md) records this ownership boundary.

Profiles state whether replay protection is required. Required-store absence, timeout, or error fails closed. Adapters may be in-memory, database-backed, or distributed, but documentation names the actual guarantee each has proven. Retention expiry is derived from the authenticated profile window, with bounded policy controlled by the adapter contract. Direct and adapter constructors must produce the same uniqueness key from the same authenticated envelope.

## Strongest alternatives

1. **Check then insert.** It is easy for any store. It cannot guarantee one winner under concurrency.
2. **Claim before verification.** It reduces expensive duplicate cryptography. An attacker can consume valid nonces without possessing a key.
3. **Claim once per signature.** It maps directly to RFC labels. It breaks linked/nested envelopes and creates partial-consumption recovery problems.
4. **Require one bundled replay service.** It could deliver uniform semantics. It violates the framework/store-free library boundary and forces deployment architecture on consumers.

## Deciding evidence and deletion test

The silent failure is two workers both accepting one authenticated action. Only an atomic store operation decides that race. Delete the replay port and every profile/caller must reconstruct namespacing, ordering, and failure behavior; keep it. Delete a bundled store and consumers without replay or with their own distributed store get simpler; do not bundle one as required infrastructure.

## Consequences

Verification has a deliberate external commit point. A caller that retries after an indeterminate store outcome must treat the result as indeterminate, not automatically replay. Backends carry explicit operational guarantees and real concurrency evidence.

## Acceptance

- Real concurrent calls against each advertised backend produce exactly one `:claimed` result for one namespace.
- Same nonce in distinct profiles/principals can coexist only where the namespace contract says so.
- The same duplicate input through the direct message constructor and every Req, Finch, Plug/Phoenix, and reverse-proxy constructor maps to one replay identity.
- Changing retention metadata does not modify the caller commitment.
- Actual caller functions bind verified nonce/challenge/transaction identifiers and enforce their declared scopes; missing, ambiguous, failed, or canceled required callbacks reject.
- Commitment functions are never invoked on unvalidated input; the library supplies no application commitment recipe.
- Invalid signatures and incomplete linked envelopes cannot consume a claim.
- Store outage/timeout never returns an authenticated success for a replay-required profile.
- Expiry, eviction, restart, and distributed-node behavior are exercised on the actual backend.
