<!-- Status: current · Kind: reference · Updated: 2026-11-13 · Governed by: ADR 0009 · Review when: source bytes change -->

# Source provenance

Unchanged public companion vectors for [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520.html), vendored from the [IETF JOSE cookbook](https://github.com/ietf-jose/cookbook/tree/13692b68bfc18b99557a5b1ed311fd5077bfff04). Retrieved October 8, 2026. The cookbook uses the Unlicense. Published test keys are not operational credentials.

`upstream-SHA256SUMS` files are historical copies from the original fixture
layout and are not checkable in place. The local `SHA256SUMS` and corpus index
verify this directory layout.

The ECDH ledger inventories every companion JSON file. It selects §5.4/§5.5 agreement and §5.7 GCMKW stages; unrelated cookbook examples retain their existing corpus coverage. Full JWE §5.4 uses custody; §5.5 and §5.7 reject their unsupported CBC content cipher.
