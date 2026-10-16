<!-- Status: current · Kind: reference · Updated: 2026-10-14 · Governed by: public architecture · Review when: the referenced contract or implementation changes -->

# Standards and counterpart contracts


These are primary technical inputs, first read on October 6, 2026. Recheck the
relevant source when changing its surface. No linked example alone proves peer acceptance.

| Contract | Scope |
|---|---|
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) | HTTP message signatures, algorithms, derived fields, responses, trailers, challenges, vectors. |
| [HTTP signature registry](https://www.iana.org/assignments/http-message-signature) | Exact registered algorithm names and parameters. |
| [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html), [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html) | Structured Fields; apply the field's selected schema and referenced types. |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) | Content and representation digests and preference fields. |
| [Web Bot Auth WG draft](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00) | Current draft profile and discovery, subject to change. |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | Generic compact JWS and JWE, and one-level JWS-in-JWE nesting (`RequestSeal.JOSE`). |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | JWS and JWE algorithms, RSA-OAEP and AES-GCM key wrapping. |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) | JWK, thumbprints, OKP keys and JOSE `EdDSA`. |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) | Ed25519 signatures. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) | HTTP semantics, message syntax, target forms, and URI authority grammar for messages and discovery fetches. |
| [CIMD-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html) | OAuth client ID metadata documents as a discovery source. |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) | JSON canonicalization for corpus verification objects. |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | JWT best current practices; RequestSeal applies explicit algorithm allowlists and has no JWT claims policy. |
| [Livebook importer](https://github.com/livebook-dev/livebook/blob/v0.19.10/lib/livebook/live_markdown/import.ex), [exporter](https://github.com/livebook-dev/livebook/blob/v0.19.10/lib/livebook/notebook/export/elixir.ex) | Actual notebook parse/export API and branch behavior. |
| [ExDoc](https://hexdocs.pm/ex_doc/ExDoc.html) | Generated API and guide tooling. |

## Source-bound profile selection

Generic RFC 9421 requires caller-supplied coverage, algorithm, freshness, replay,
and trust policy. Web Bot Auth protocol-00 selects its exact dictionary-member
`Signature-Agent` representation, labels, tags, discovery types, and nested
coverage. Another source revision cannot silently broaden these predicates.
Source-bound acceptance is an accepted architectural decision, and the
[testing guide](../guides/testing.md) distinguishes published
vectors, independent construction, and deployed-peer evidence.

Generic HTTP and JOSE identifiers are separate exact wire tokens. Structured
Field parameter names cannot contain uppercase letters. The HTTP algorithm
`ed25519` and JOSE `EdDSA` require explicit selection in their own registries;
no spelling alias or automatic cross-profile fallback exists. Sources include
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
