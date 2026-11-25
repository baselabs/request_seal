# 0043 — Bind quorum replay to one operation

Status: Accepted.

## Context

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) defines independently
verifiable signatures and dictionary labels. It leaves multi-signature
acceptance to applications. Public RequestSeal 0.x exposed quorum verification.
The 1.0.0 release removed that API and fixed set-dependent replay in Web Bot Auth.
The earlier threat analysis in commit
`c2c4ad7311485e29593c7eb929de44e5d631a372` identifies relabeling, recombination,
and subset changes as ways to bypass a commitment over signature facts.

## Decision

Require a finite freshness policy and explicit trust resolution in each slot.
Verify every selector-eligible label against its complete slot policy. Build
key identity classes from verified observations, merging aliases and treating
unknown equivalence conservatively. An assignment uses each label and identity
class at most once. It meets required slots, bindings and distinct key,
principal or role counting rules. Authorization remains unevaluated.

Every successful quorum makes one atomic claim after assignment, binding, and
signature-negotiation checks. The commitment uses the configured namespace and optional set of
configured trusted principals, plus one identity shared by every verified
candidate. Shared-nonce mode requires one identical nonempty authenticated
nonce. Operation mode requires the same ordered mandatory components in every
slot, and derives their exact values from verified bases. Signatures and their
dictionary fields cannot appear in the commitment input. The exclusive
retention end is fixed in the replay policy. All qualifying signature windows
must fit it, including when the only supplied signatures are required ones.

## Reasons

- Relabeling leaves each authenticated nonce or operation value unchanged
  under RFC 9421 Section 7.2.5. Labels can select slots and can affect the
  verdict. An accepted relabeling cannot produce a different replay key.
- Recombined signatures from different attempts either disagree on a shared
  nonce or share the operation key. Changed operation bytes fail coverage or
  cryptographic verification under the configured slot policy. Commit to all
  effect-relevant values for the operation, and verify body integrity when it
  carries content.
- Adding or removing optional signers does not change trusted replay scope,
  identifier order, or the retention end. Commitment agreement checks every
  verified candidate, including one the assignment leaves unused. A subset
  cannot shorten the store lifetime.

A claim per slot can consume state before a quorum verdict. An aggregate over
wire labels, signature bytes, or key IDs lets the wire choose the uniqueness
boundary. The single post-verdict claim avoids both failure modes.

## Consequences

Evaluation bounds label-slot verification at 64 × 16. The 16,384-unit
assignment budget covers identity traversal, search nodes, candidate scans,
binding checks and role matching. A completed satisfying assignment may be
returned at the work bound. If none has been found, the verdict fails closed.
A cooperative monotonic deadline covers phases between callback invocations.
The caller controls resolver latency, clock agreement, safe sweep timing,
and consistent policy across verifiers.
