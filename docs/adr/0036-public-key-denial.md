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

A Web Bot Auth directory proof authenticates the directory body. The verified
proof signer thumbprints travel with each resolved key. Every relied-on proof
signer must pass an active deny policy and the Web Bot Auth test-key policy,
including on cache hits. A cache tombstone also drops every key whose
relied-on directory proof used the removed signer, including when a fetch
or revalidation is in progress.
Source revocations also apply to proof signers on snapshot lookup. When a
source has revocations, a signed resolution needs known signer identities.

Validate fixed-width digest entries in a plain map before admitting a set.
For a verification handle, custody resolves and screens the handle's public
key in one operation, checks any custodian verifier's verdict, and verifies
against that public key before returning it for capture.
Screening and capture in assignment-aware custody use the non-nil public
key returned with the assignment by `binding/2`. Legacy custody uses one
`public_key/1` read for screening and verification.
Seed screening runs before the private-key possession probe.
