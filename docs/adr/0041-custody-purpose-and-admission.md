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
verify the binding before key use. Assigned use requires the custodian to
report the retained algorithm and purpose through `signing_assignment/2`
under the same deadline. Legacy callbacks cannot establish an assignment.
SSH custody retains its assignment and socket path in a sensitive process
and controls socket operations from there. A binding read reports held public
facts and an RFC 7638 thumbprint when public material exists. SSH binding reads
confirm current agent membership.

Purpose assignments apply to signing and verification keys. An assigned key
requires the matching purpose and protocol for both operations. An omitted
or nil purpose works for an unassigned key. Assigned keys accept canonical
HTTP bases or compact JWS signing inputs according to their retained family.
Raw use refuses, and a JWS-bound key cannot sign an HTTP message. Existing
unassigned custody continues to support raw use and explicitly selected HTTP
JWS algorithms. Gated keys require a valid HTTP base for both operations
even with no purpose. For HTTP public keys, the policy purpose must equal
the resolver's trusted assignment. Purposes stay outside the wire format.

Local HTTP signing may require approval inside the sensitive key process.
A gate validates the typed HTTP Inner List before extracting any parameter
value. It compares canonical covered components, tag, algorithm, optional key ID,
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

SSH handles expire when their creator exits or the holder is released.
Rebuild in-memory key handles and holders during upgrade. An HTTP policy
with the exact previous shape continues to select unassigned keys.
