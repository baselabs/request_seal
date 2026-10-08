# ADR 0013: Keep named application profiles in extension packages

- Status: Accepted
- Date: 2026-10-08

## Context

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) assigns application
coverage, algorithm, freshness, and trust decisions to profiles. Named application
profiles need that shared machinery without making application contracts part of
the framework-independent core or allowing extensions to impersonate core names.

## Decision

Named application profiles live in extension packages against the documented
`RequestSeal.Profile` surface: `dictionaries/2`, `preflight/4`, and
`verify_label/6`. This surface is unstable; pin RequestSeal exactly.
Extensions select and enforce their public source-specific
predicates before returning success and own any trusted principal attribution.
The core pipeline enforces the explicitly supplied generic policy.

An extension profile map has at most eight atom keys and a required
`name: {package, kind}` with atom values and a package distinct from
`:request_seal`, `:rfc9421`, and `:web_bot_auth`.
The extension module defines that name as a compile-time constant, never from
wire data. Bare atom names and the core package namespace reject with
`:invalid_profile` at the `:input` layer. Other values are limited to atoms,
integers from -999,999,999,999,999 through 999,999,999,999,999, or binaries of
at most 256 bytes. The generic verifier refuses both
`:profile` and `:principal` options with the same bounded error. Core named
profiles retain their own acceptance predicates.

A profile stamp records selection, not proof that source-specific rules ran.
Consumers must allowlist trusted profiles and verification implementations.
The Ash adapter retains its closed core profile allowlist. Replay commitments
receive the selected profile so callers can bind claims to their security scope.
Cryptographic validity and principal attribution grant no authorization.

## Internal dependencies

Undocumented helpers are not extension API. Extensions carry their own JOSE
support, message validation, source URL/origin validation, and replay composition.
RequestSeal.Custody.run/2 remains an undocumented, exactly pinned dependency
for operation deadlines and cancellation. Generic signing uses public
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
