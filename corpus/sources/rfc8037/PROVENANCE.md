<!-- Status: current · Kind: reference · Updated: 2026-11-13 · Governed by: ADR 0009 · Review when: source bytes change -->

# Source provenance

Published test material extracted from [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.txt), A.1. Promoted from existing fixtures without byte changes. Test keys are never operational credentials.

`upstream-SHA256SUMS` files are historical copies from the original fixture
layout and are not checkable in place. The local `SHA256SUMS` and corpus index
verify this directory layout.

`x25519.json` transcribes the public recipient, ephemeral scalar/public key, and shared secret from [RFC 8037 Appendix A.6](https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.6), also published in RFC 7748 §6.1. The ledger covers the retained A.1 material and this ECDH example.
