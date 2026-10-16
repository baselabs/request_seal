<!-- Status: current · Kind: reference · Updated: 2026-10-14 · Governed by: public architecture · Review when: the referenced contract or implementation changes -->

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
| Key handle | An opaque, algorithm-bound reference to a key held by a custodian; private key bytes never leave the custodian. |
| Signing spec | The label, algorithm, covered components, lifetime, and optional parameters of a signature to create (`t:RequestSeal.signing_spec/0`). |
| Policy | The verifier's explicit acceptance choices: algorithms, required components, key resolver, freshness, body integrity, and replay (`RequestSeal.Policy`). |
| Key resolver | The policy's caller function returning the authoritative algorithm and public key or verification function for a key ID; it establishes no identity. |
| Agent trust function | The Web Bot Auth policy's `agents` function mapping a `Signature-Agent` location and type to a trusted source or key set before attribution. |
| Verification result | The facts established by a successful verification (`RequestSeal.Verification`); `authorization` is always `:not_evaluated`. |
| Principal | The verified attribution in a result. Generic results are `:unattributed`; Web Bot Auth reports an agent or a held key. |
| Held key | A public key the verifier configured directly; verification attributes only its thumbprint, never an agent URL. |
| Thumbprint | The RFC 7638 SHA-256 JWK thumbprint identifying a public key; Web Bot Auth uses it as the key ID. |
| Possession proof | A signed key-directory response; it proves possession of the listed keys, not the identity of their owner. |
| Profile stamp | The descriptive profile name in a result; consumers allowlist the profiles they trust. |
| Replay namespace | The caller's trust and tenant scope under which replay claims are unique. |
| Retention end | The first second at which a replay claim may be swept; `RequestSeal.Policy` defines how it is derived. |
| Quorum slot | One expected signer position in a quorum, with its own label selector and complete policy. |
| Counting unit | What a quorum threshold counts: distinct keys, caller-bound principals, or roles. Labels never count. |
| Error layer | The check that rejected a message, such as `:fields`, `:policy`, `:crypto`, `:content`, `:freshness`, or `:replay`. |
| Correlation | A random token in an error that lets logs and reports refer to one failure without recording its inputs. |
| Replay claim | An atomic claim using a caller-supplied commitment bound to a verified nonce, challenge, or transaction identifier and caller-defined security scope; expiry controls retention. |
| Key-equivalence identity | Trusted algorithm-appropriate identity used to deduplicate aliases of one key; public components for asymmetric keys, an opaque custodian-supplied value for symmetric keys that RequestSeal never derives. |
| Envelope | Source-selected authenticated unit: HTTP signatures and required nested signatures, or explicitly selected generic JOSE nesting. |
| Transport evidence | Caller-declared HTTP version and TLS facts (`evidence: :declared`); a declaration cannot prove a connection's security prerequisites. |
| Recipient integrity | Successful authenticated decryption under an approved recipient key; independently required origin and request association remain separate. |
| Content digest | Hash of the HTTP message content; distinct from a selected representation's digest. |
| Counterpart | A specific independent implementation or deployed peer used for interoperability evidence. |
| Conformance corpus | Source-attributed positive and negative wire cases with deterministic expected results. |
| Compatibility profile | Design term with no API yet: explicit handling of a named counterpart's documented deviation; never core fallback. |
| Evidence resolution | Design term with no API: obtaining definitive bytes or rules where source text or examples conflict. |
