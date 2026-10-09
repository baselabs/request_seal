<!-- Status: current · Kind: reference · Updated: 2026-10-09 · Governed by: ADR 0009 · Review when: source bytes change -->

# Source provenance

See the retained `upstream-PROVENANCE.md` for extraction and independent peer generation. Protocol-00 Appendix E comes from the [public draft](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.txt). Request examples produced by the public package and directory signatures produced by OpenSSL are peer evidence, not published RFC vectors.

`upstream-SHA256SUMS` files are historical copies from the original fixture
layout and are not checkable in place. The local `SHA256SUMS` and corpus index
verify this directory layout.
