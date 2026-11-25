# 0036 — Check RFC 7638 public-key identity

Status: Accepted.

## Context

Wire key identifiers may be aliases. A valid seed may also derive a different
public key from the one an operator intended to install.

## Decision

Verification policies may screen the public key used for cryptography against
a caller-owned deny set. Custody import checks the public key derived from the
seed against an optional expected thumbprint or deny set before issuing a handle.

## Reasons

RFC 7638 thumbprints identify key material independent of wire names. An
active set requires public identity, including when the set is empty.

## Consequences

The caller owns distribution and freshness of its deny set. The library
starts no revocation service. See [RFC 7638 Section 3](https://www.rfc-editor.org/rfc/rfc7638.html#section-3).
