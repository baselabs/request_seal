# 0041 — Bind key use to purpose and signing admission

Status: Accepted.

## Context

[RFC 9421 Section 3.2.1](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2.1)
leaves application requirements to the caller. A valid signature can
authenticate bytes while using a key assigned to a different purpose.
[NIST SP 800-57 Part 1 Rev. 5 Section 5.2](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
describes limiting a key's purpose.

## Decision

Retain each key's exact algorithm and trusted purpose in custody. The handle
exposes the operation family and purpose for selection. Built-in custodians
verify the binding before key use. A binding read reports held public facts
and an RFC 7638 thumbprint when public material exists. SSH identity reads
confirm current membership.

HTTP and compact JWS signing can require the assigned purpose. Generic HTTP
verification can require a purpose from the trusted resolver. Purposes stay
outside the wire format.

Local HTTP signing may require approval inside the sensitive key process.
A gate compares canonical covered components, tag, algorithm, optional key ID,
and the approved digest, nonce, and time window. It consumes the decision
under the operation deadline before signing. A configured recorder must
succeed before return. Claims survive every subsequent failure.

## Alternatives

Sender-supplied key identifiers cannot establish issuance purpose. Assigning
approval after signing allows a denied request to reach the key. Keeping a
separate ungated capability to the same key operation undermines enforcement.

## Consequences

The caller owns purpose assignments, admission policy, the claim boundary,
clock and recording. A guarded key operation starts no background service.
An external signer can consume an admission and bind its work to the returned
base digest and exclusive expiry.
