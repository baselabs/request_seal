<!-- Status: current · Kind: reference · Updated: 2026-11-13 · Governed by: ADR 0009 · Review when: source bytes or pinned tools change -->

# Source provenance

Independent generated test vectors produced by `scripts/check_jose_libraries.py --generate`. Exact tools: [npm jose 6.2.17](https://github.com/panva/jose/tree/v6.2.17) (MIT) and [Erlang jose 1.11.13](https://github.com/potatosalad/erlang-jose/tree/1.11.13) (MIT). The script installs these exact versions into temporary directories, executes each producer, and checks the reverse direction with fresh RequestSeal output. It keeps tooling out of runtime dependencies.

`vectors.json` contains the producers’ token bytes and generated public test keys. `agreement` inputs and expected values come from npm jose encryption, with a separate Node cryptographic derivation for the direct CEK; no expected value comes from RequestSeal. RFC 7518 and RFC 8037 define the protocols. The ledger names every generated item by provider, algorithm, cipher, and curve. These generated keys are published test material, never operational credentials.
