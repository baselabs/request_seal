<!-- Status: current · Kind: reference · Updated: 2026-10-09 · Governed by: ADR 0009 · Review when: source bytes change -->

# Source provenance

Locally constructed captures of a real HTTP exchange. The unchanged `capture.json` records the verified TLS socket method, public RFC source URL, timestamp and original byte hashes. These captures establish HTTP value-model round trips, not signing conformance.

`upstream-SHA256SUMS` files are historical copies from the original fixture
layout and are not checkable in place. The local `SHA256SUMS` and corpus index
verify this directory layout.
