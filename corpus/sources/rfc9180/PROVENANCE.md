# RFC 9180 derivation vectors

`derive-key-pairs.json` is a lossless extraction of the first E, R, and S
DeriveKeyPair examples for each of KEM 0x0010 and 0x0020 from the
[RFC 9180 TestVectors reference](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json).
Each item is its upstream array index and role. Only the KEM identifier, IKM,
serialized private scalar and serialized public key are retained. The ledger
accounts for every extracted item. Full HPKE encryption is not claimed.

The pinned upstream file has no KEM 0x0011 (P-384) vector. The corpus's P-384
case is explicitly an independent derivation from Section 7.1.3, reproduced by
`scripts/import_derivation_vectors.py`, not an upstream published vector.
