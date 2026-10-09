<!-- Status: current · Kind: reference · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Domain glossary


| Term | Meaning |
|---|---|
| Message | One HTTP request or response with raw field occurrences and its relevant transport context. |
| Component | A field or derived value selected by an RFC 9421 component identifier and parameters. |
| Signature base | The exact ordered bytes authenticated by the selected signature. |
| Signature label | The dictionary key linking one Signature-Input entry to one Signature entry. |
| Profile | An explicit standards/application contract constraining coverage, algorithms, freshness and trust. |
| Cryptographic validity | The signature matches the selected key and exact base; no authority is implied. |
| Identity attribution | Verified association between the signing key and a claimed agent/domain/issuer. |
| Authentication | Successful cryptography plus all required profile, trust, integrity, time and replay rules. |
| Authorization | The caller's decision about what the authenticated party may do. |
| Custodian | Owner of signing, secret-bearing verification, or key-unwrapping capability; an opaque handle may invoke a remote HSM/KMS without exposing its key. |
| Trust resolver | A caller-configured mechanism binding key material to an allowed identity and profile. |
| Replay claim | An atomic claim using a caller-supplied commitment bound to a verified nonce, challenge, or transaction identifier and caller-defined security scope; expiry controls retention. |
| Key-equivalence identity | Trusted algorithm-appropriate identity used to deduplicate aliases of one key; public components for asymmetric keys, an opaque custodian-supplied value for symmetric keys that RequestSeal never derives. |
| Envelope | Source-selected authenticated unit: HTTP signatures and required nested signatures, or explicitly selected generic JOSE nesting. |
| Transport evidence | Caller declarations are declared; trusted adapter connection observations may establish actual prerequisites under the selected policy. |
| Recipient integrity | Successful authenticated decryption under an approved recipient key; independently required origin and request association remain separate. |
| Content digest | Hash of the HTTP message content; distinct from a selected representation's digest. |
| Counterpart | A specific independent implementation or deployed peer used for interoperability evidence. |
| Conformance corpus | Source-attributed positive and negative wire cases with deterministic expected results. |
| Compatibility profile | Explicit handling of a named counterpart's documented deviation; never core fallback. |
| Evidence resolution | Obtaining definitive bytes/rules where source text or examples conflict. |
