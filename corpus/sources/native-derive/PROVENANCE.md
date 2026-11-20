# Custody derivation vectors

These are RequestSeal-native independent derivations of the public ADR 0026
framing over [RFC 5869 Sections 2.2–2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2)
and [RFC 9180 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3),
with RFC 8032 seeds, HMAC-SHA256 and RFC 3394 AES-KW probes. They are not
published external-conformance vectors for RequestSeal's framing.

`scripts/import_derivation_vectors.py` computes expectations in independent
Python standard-library code. It first checks the RFC 3394 AES-KW example,
RFC 8032 Ed25519 public key and the pinned RFC 9180 P-256/X25519 pairs.
Every family is represented. No RequestSeal output supplies an expectation;
symmetric cases compare real operation outputs, never exported child material.
The ledger lists each family. The script refreshes the digest inventory and pin.
