# 0013 — Keep named application profiles in extension packages

## Context

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) assigns application
coverage, algorithm, freshness, and trust decisions to profiles. Named application
profiles need that shared machinery without making application contracts part of
the framework-independent core or allowing extensions to impersonate core names.

## Decision

Named application profiles use `RequestSeal.Profile`: `valid_signature_input?/1`,
`dictionaries/2`, `preflight/4`, and `verify_label/6`, under the 1.x compatibility promise.
Extensions enforce public source-specific predicates and trusted principal attribution;
the core enforces the explicitly supplied generic policy.

An extension profile map has at most eight atom keys and a required
`name: {package, kind}` of atoms, with package distinct from
`:request_seal`, `:rfc9421`, and `:web_bot_auth`.
The module defines its name at compile time, never from wire data.
Bare atom names and core package namespaces reject with `:invalid_profile` at `:input`.
Other values are atoms, integers from -999,999,999,999,999 to 999,999,999,999,999,
or binaries up to 256 bytes. Generic verification rejects `:profile` and `:principal`
options with the same bounded error; named core profiles retain their predicates.

A profile stamp records selection rather than proof that source-specific rules ran.
Consumers allowlist trusted profiles and verification implementations.
Ash retains its closed core-profile allowlist.
Replay commitments receive the selected profile for caller-defined scope.
Cryptographic validity and attribution grant no authorization.

## Internal dependencies

Undocumented helpers are not extension API. Extensions carry their own JOSE
support, message validation, source URL/origin validation, and replay composition.
`RequestSeal.Custody.run/2` is a documented public boundary for operation
deadlines and cancellation. `RequestSeal.Replay.Claim.valid?/1` exposes bounded
claim validation. JWS verification and JWE encryption/decryption document their
explicit policy and callback shapes; these primitives establish no application
profile enforcement or authorization. Generic signing uses public
`RequestSeal.JOSE.JWS.sign_protected/4` for caller-serialized protected bytes.
`RequestSeal.Discovery.Source.directory_id?/1` is publicly documented.

## Consequences

Extensions share lossless field parsing, coverage, freshness, cryptography,
content checks, and replay while independently maintaining named application
profiles. Their public requirements must retain cited public provenance under
ADR 0011. Undocumented internals do not become part of this public surface.

## Acceptance

- Core-owned names, bare atom names, non-atom keys, oversized maps, and invalid metadata values reject.
- A package-namespaced profile verifies selected bytes and stamps the result.
- Ash rejects an extension result before invoking caller bindings.
- Caller commitments can separate the same nonce by profile name and reject duplicates.

## Reserved package names

The core additionally reserves the hyphenated package names `:"request-seal"`
and `:"web-bot-auth"`. These join the original reserved names to prevent
extensions from impersonating the published core package and named profile.
The remaining extension contract is unchanged.

## Proposed extension support

[ADR 0028](0028-strict-json-object-decoding.md) proposes a strict public JSON object decoder;
[ADR 0015](0015-jose-protected-members-and-embedded-keys.md) proposes required protected members.
