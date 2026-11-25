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
Operation identifiers must be unique, canonical RFC 9421 components. The
encoding length-prefixes each identifier and value separately.

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

The store reads its trusted clock at the atomic transition. Admission requires
a live prepared lease and retention window, and renewal fences completion with
a fresh token. Completion requires the current token and a live stored lease
and retention window. A completed fingerprint match returns the recorded
response and a mismatch fails. Adapter output is normalized to closed public
results before it reaches the caller or telemetry.

The client journal rebuilds each captured HTTP(S) intent before recording it,
checking that method, target and retained content survive reconstruction.
The unsigned fields must leave room in the HTTP message field budget for the
largest supported Signature-Input and Signature occurrences. On reissue it
generates a fresh nonce and uses caller-owned custody. The in-process journal
and idempotency store validate their call arguments before accessing stored
records, and reject unsupported calls without terminating the state owner.

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
