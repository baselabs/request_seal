# 0038 — Retain public-key HTTP verification records

Status: Accepted.

## Context

Later inspection requires the exact signed bytes and the public key used in
an accepted verification. Request messages may be unavailable by then.

## Decision

Explicit capture retains the base, signature, and validated public key on
a successful result. Version 1 records store those bytes, the RFC 7638
thumbprint, and descriptive profile and directory facts in a closed JSON
format. Offline checking validates the encoding and verifies the signature.

## Reasons

A deterministic record supports reproducible storage and byte comparison.
Canonical signature-base parsing checks the covered identifiers and their
order. Retaining the actual key preserves public restrictions and permits
mathematical verification after rotation. Rechecking a byte-wrapped field
requires the same canonical occurrence framing as live construction.

## Consequences

A record carries no authorization and establishes no live trust or freshness.
A retired key may still verify mathematically. Protect stored records and
sensitive covered bytes. See [RFC 9421 Section 3.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2),
[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), and [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html).

Capture an asymmetric handle's verified public material under the same
rules with or without a deny set. PSS-only keys retain the SPKI along with
any validated algorithm, use, and operation restrictions. Established
agent origin and fetch time take precedence and a supplied resolution must
agree. A Web Bot Auth held-key result retains its key-only provenance and
rejects a supplied directory. Generic HTTP capture can still include a
caller-supplied resolution for the verified key. Decode refuses duplicate and
unknown members at every object boundary.
