# 0042 — Stable operation identity and stored responses

Status: Accepted.

## Context

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) authenticates a transport
attempt. An application retry can carry a fresh nonce and a new signature after
the original operation committed and its response was lost. The receiver needs
both single-use admission for each attempt and repeatable lookup for the operation.

## Decision

Library-built replay commits to a trusted credential, principal, or key and
either the authenticated nonce or exact ordered mandatory component values.
Credential scope includes its trusted issuance purpose. Credential and principal
scope survive material rotation and key aliases when the trusted identity stays
stable. Material scope uses a public thumbprint or caller-supplied opaque
symmetric identity. Built-in policies pin one retention end for all eligible
attempts in a namespace. Verification refuses any signature window beyond it.

[Idempotency-Key draft-ietf-httpapi-idempotency-key-header-09](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header-09)
defines an RFC 9651 String, opaque key equality, fingerprint-based mismatch
detection, and distinct completed and concurrent retry outcomes. RequestSeal
requires one header occurrence with a nonempty parameter-free value of at most
256 bytes. It requires signed method, target, header Content-Digest and
Idempotency-Key, verifies retained content under RFC 9530, and claims a
transport nonce before the response lookup. The key is scoped by the trusted
namespace and principal. The fingerprint uses exact body and covered method,
target and digest bytes. Wire status mapping and key expiration policy remain
application choices. For example, applications can use 409 for in-progress and
422 for a fingerprint conflict, as the draft describes.

The store reserves atomically, renews an expired matching lease, and fences
completion with a fresh token. A completed fingerprint match returns the
recorded response. A mismatch never returns it. The client journal records
unsigned intent and generates a fresh nonce whenever it signs that intent
again. It uses caller-owned custody at reissue time.

## Reasons

A nonce identifies a transport attempt. A separate operation key allows the
same logical request to recover after a lost response. A fixed retention end
prevents alias or rotation changes from creating an earlier sweep boundary.
Reverification of the same immutable request prevents pairing a result with
different request bytes. A fenced write prevents a replaced lease from
overwriting or finalizing the active reservation.

## Consequences

Authorization and response eligibility remain current application decisions.
The application owns storage confidentiality, retention, request interpretation,
and effect uniqueness. An operation can commit before a process dies or its
lease expires. Enforce operation uniqueness where the effect commits, and
recover its outcome there before attempting the effect again.
