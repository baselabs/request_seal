<!-- Status: current · Kind: reference · Updated: 2026-11-13 · Governed by: ADR 0009 · Review when: source bytes change -->

# Source provenance

Unchanged [C2SP Wycheproof](https://github.com/C2SP/wycheproof/tree/12fd3aaf33eb5fa1f52e026912ee00c054f9d984) public vectors. Retrieved October 8, 2026. Apache-2.0.

`upstream-SHA256SUMS` files are historical copies from the original fixture
layout and are not checkable in place. The local `SHA256SUMS` and corpus index
verify this directory layout.

| Corpus file | Upstream path at `12fd3aaf33eb5fa1f52e026912ee00c054f9d984` | SHA-256 |
| --- | --- | --- |
| `sources/wycheproof/aes_gcm_test.json` | `testvectors_v1/aes_gcm_test.json` | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` |
| `sources/wycheproof/ecdsa_secp256r1_sha256_p1363_test.json` | `testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json` | `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986` |
| `sources/wycheproof/ed25519_test.json` | `testvectors_v1/ed25519_test.json` | `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536` |
| `sources/wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json` | `testvectors_v1/rsa_oaep_2048_sha256_mgf1sha256_test.json` | `83dce701e3d8640ac56e6d7bf37a5a8f9bd6a336e1e932a1e9bfe4ba9c5ea3a9` |
| `sources/wycheproof/aes_wrap_test.json` | `testvectors_v1/aes_wrap_test.json` | `2fdb3661fd8823d1ec50e03886b24066415018975677dff83d83e77f5a51562d` |
| `sources/wycheproof/ecdh_secp256r1_test.json` | `testvectors_v1/ecdh_secp256r1_test.json` | `cdb8bd5d1206fddb6618c69ffa18f303b4752caba321d348d4aacae3f20cbec4` |
| `sources/wycheproof/ecdh_secp384r1_test.json` | `testvectors_v1/ecdh_secp384r1_test.json` | `25a9c41573dbea97c5b4be2dd00369fa68dc37ac8f41807d8e16226d188ec6a7` |
| `sources/wycheproof/x25519_test.json` | `testvectors_v1/x25519_test.json` | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` |

The ECDH/AES-KW/X25519 ledger accounts for every test in these four newly copied, unchanged files. Exclusions are explicit; strict ASN.1 and zero-output rejection choices are recorded as corpus overrides.
