<!-- Status: current · Kind: reference · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Standards and counterpart contracts


These are primary technical inputs read for the design on October 6, 2026. Recheck the
relevant source before implementing its surface. No linked example alone proves peer acceptance.

| Contract | Scope |
|---|---|
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) | HTTP message signatures, algorithms, derived fields, responses, trailers, challenges, vectors. |
| [HTTP signature registry](https://www.iana.org/assignments/http-message-signature) | Exact registered algorithm names and parameters. |
| [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html), [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html) | Structured Fields; apply the field's selected schema and referenced types. |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) | Content and representation digests and preference fields. |
| [Web Bot Auth WG draft](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00) | Current draft profile and discovery, subject to change. |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | JWS and JWE machinery where the actual selected profile uses them. |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) | JWK, thumbprints, OKP keys. |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | JWT algorithm, issuer, audience, type and validation rules. |
| [Livebook importer](https://github.com/livebook-dev/livebook/blob/v0.19.10/lib/livebook/live_markdown/import.ex), [exporter](https://github.com/livebook-dev/livebook/blob/v0.19.10/lib/livebook/notebook/export/elixir.ex) | Actual notebook parse/export API and branch behavior. |
| [ExDoc](https://hexdocs.pm/ex_doc/ExDoc.html) | Generated API and guide tooling. |

## Source-bound profile selection

Generic RFC 9421 requires caller-supplied coverage, algorithm, freshness, replay,
and trust policy. Web Bot Auth protocol-00 selects its exact dictionary-member
`Signature-Agent` representation, labels, tags, discovery types, and nested
coverage. Another source revision cannot silently broaden these predicates.
The [profile decision](../adr/0003-source-bound-profiles.md) defines source-bound
acceptance, and the [testing guide](../guides/testing.md) distinguishes published
vectors, independent construction, and deployed-peer evidence.

Generic HTTP and JOSE identifiers are separate exact wire tokens. Structured
Field parameter names cannot contain uppercase letters. The HTTP algorithm
`ed25519` and JOSE `EdDSA` require explicit selection in their own registries;
no spelling alias or automatic cross-profile fallback exists. Sources include
[RFC 9421 Sections 2.3, 2.5, and 3.3.6](https://www.rfc-editor.org/rfc/rfc9421.html),
[RFC 8941 Section 3.1.2](https://www.rfc-editor.org/rfc/rfc8941.html), and
[RFC 7518 Section 3.5](https://www.rfc-editor.org/rfc/rfc7518.html).

Application profiles live in extension packages through the bounded surface in
[ADR 0013](../adr/0013-extension-profile-boundary.md). Core standards are not
weakened to accommodate conflicting examples. Definitive source evidence is
required before advertising an ambiguity-dependent rule as conformant.

## Provenance

Store immutable public captures with original source URL, retrieval time, content digest,
license and source revision before deriving corpus cases. Store release receipts separately
from human guides. Independent published vectors and local examples have distinct labels.
No secret, customer payload, or private source belongs in the public corpus.
