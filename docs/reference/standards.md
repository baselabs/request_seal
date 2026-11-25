# Standards and counterpart contracts

These are primary technical inputs, first read on October 6, 2026. Recheck the
relevant source when changing its surface. No linked example alone proves peer acceptance.

| Contract | Scope |
|---|---|
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) | HTTP message signatures, canonical bases, trusted freshness intervals, retained verification records, algorithms, responses, trailers, challenges, vectors, and replay defense. |
| [HTTP signature registry](https://www.iana.org/assignments/http-message-signature) | Exact registered algorithm names and parameters. |
| [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html), [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html) | Structured Fields; apply the field's selected schema and referenced types. |
| [Idempotency-Key draft-09](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header-09) | Structured Field String operation keys, request fingerprints, completed retries, and conflicts. |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) | Content and representation digests and preference fields. |
| [Web Bot Auth WG draft, protocol-00](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00) | The supported, explicitly stamped draft revision for the profile and discovery. A newer revision (protocol-01) exists; it is not yet selectable, and protocol-00 stays selectable when it is. |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | Generic compact JWS and JWE, and one-level JWS-in-JWE nesting (`RequestSeal.JOSE`). |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | JWS and JWE algorithms. JWE encryption uses RSA-OAEP, RSA-OAEP-256, A128KW, A256KW, and ECDH-ES (direct, +A128KW, +A256KW) with the Concat KDF below; decryption also admits A128GCMKW, A256GCMKW, and `dir`. Content encryption is A128GCM or A256GCM. |
| [RFC 7518 §4.6.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2) | ECDH-ES Concat KDF with SHA-256, AlgorithmID, party information, and key length; direct agreement derives a CEK and +KW derives a KEK. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) | HKDF-SHA256 extract/expand with versioned RequestSeal family and domain framing for custody derivation. |
| [RFC 9180 §7.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3) | DeriveKeyPair for P-256, P-384, and X25519 children; this does not implement an HPKE encryption API. |
| [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394.html) | AES Key Wrap for A128KW and A256KW, held in custody (`RequestSeal.Custody.wrap/3`). |
| [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) | X25519 key agreement for ECDH-ES. ECDH-ES also runs over P-256 and P-384. |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) | JWK, thumbprints and deny sets, OKP keys (Ed25519 and X25519) and JOSE `EdDSA`. |
| [NIST SP 800-57 Part 1 Rev. 5 §5.2](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Key purpose separation. |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) | Ed25519 signatures. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) | HTTP semantics, message syntax, target forms, URI authority grammar, and segment decoding for signed-path tenant selection. |
| [CIMD-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html) | OAuth client ID metadata documents as a discovery source, with the root-path rule of [CIMD-03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03) Section 3. |
| [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) | HTTP caching: bounded key-cache freshness, `Age`, `Cache-Control`, `Expires`, and conditional revalidation for discovery fetches (a key cache, not a shared HTTP cache). |
| [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html), [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html), [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332.html), [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656.html) | SSH agent identity listing and signing for `RequestSeal.Custody.SSHAgent`. |
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html) | JSON syntax underlying strict protected-header and object-content decoding; RequestSeal additionally rejects duplicates and floats and bounds every tree. |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) | JSON canonicalization for corpus verification objects. |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | JWT best current practices; RequestSeal applies explicit algorithm allowlists and has no JWT claims policy. |
| [Livebook importer](https://github.com/livebook-dev/livebook/blob/v0.19.10/lib/livebook/live_markdown/import.ex), [exporter](https://github.com/livebook-dev/livebook/blob/v0.19.10/lib/livebook/notebook/export/elixir.ex) | Actual notebook parse/export API and branch behavior. |
| [ExDoc](https://hexdocs.pm/ex_doc/ExDoc.html) | Generated API and guide tooling. |

## Source-bound profile selection

[RFC 9421 Sections 2.5 and 7.2.5](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.5)
define signature bases and label handling. RequestSeal quorum rules are local
policy over independently verified signatures, with one assignment-independent
replay claim. See the [quorum guide](../guides/quorum.md).

Generic RFC 9421 requires caller-supplied coverage, algorithm, freshness, replay,
and trust policy. Web Bot Auth protocol-00 selects its exact dictionary-member
`Signature-Agent` representation, labels, tags, discovery types, and nested
coverage. Another source revision cannot silently broaden these predicates.
Source-bound acceptance is an accepted architectural decision, and the
[testing guide](../guides/testing.md) distinguishes published
vectors, independent construction, and deployed-peer evidence.

Generic HTTP and JOSE identifiers are separate exact wire tokens. Structured
Field parameter names cannot contain uppercase letters. The HTTP algorithm
`ed25519` and JOSE `EdDSA` require explicit selection in their own registries.
Policy allowlists and signature parameters never alias the two registries; only a
JWKS key's asserted `alg` accepts either spelling and normalizes once at import. Sources include
[RFC 9421 Sections 2.3, 2.5, 3.3.6, and 3.3.7](https://www.rfc-editor.org/rfc/rfc9421.html),
[RFC 8941 Section 3.1.2](https://www.rfc-editor.org/rfc/rfc8941.html), and
[RFC 8037 Section 3.1](https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1).

Application profiles live in extension packages through the bounded extension
surface. Core standards are not
weakened to accommodate conflicting examples. Definitive source evidence is
required before advertising an ambiguity-dependent rule as conformant.

## Provenance

Store immutable public captures with original source URL, retrieval time, content digest,
license and source revision before deriving corpus cases. Store release receipts separately
from human guides. Independent published vectors and local examples have distinct labels.
No secret, customer payload, or private source belongs in the public corpus.

## Conformance corpus

`corpus/` preserves the cited standards and provider bytes alongside independent
expectations. See [the corpus format](corpus-format.md) for the index, manifests,
canonical results and checksummed release assets.
