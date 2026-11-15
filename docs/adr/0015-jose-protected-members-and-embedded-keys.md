<!-- Status: proposed · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0015 — Require declared protected members and approve embedded public keys
Status: Proposed

## Context

A compact JWS or JWE protected header can carry members that the library never reads. In
the 1.x policies the caller inspects the decoded header only after success, so an
unexpected member, or an expected member with the wrong value, reaches the application
unless every caller writes the same check. Key resolvers also receive the header before
authentication. Some protocols carry the signing public key in the JWS `jwk` member, which
1.x always refuses, so those protocols parse JOSE themselves. RFC 7515 Section 4.1.3
defines `jwk`; RFC 8725 recommends verifying that headers match the application's
expectations.

## Decision

1. `RequestSeal.JOSE.JWS.verify/2` takes a policy with exactly `:algorithms`, `:timeout`,
   `:key_resolver` and `:protected`. `RequestSeal.JOSE.JWE.decrypt/2` takes `:protected`
   beside its key-management, content and deadline keys
   ([ADR 0016](0016-bounded-jwe-open-coordinator.md)). There are no defaults.
2. For JWE, `:protected` is exactly `%{expected: map, permitted: names}`. For JWS it also
   carries `embedded_key: :refuse | :require`. Expected values compare by exact decoded
   JSON equality. An absent member and a different value both return
   `:protected_mismatch`, and the reason never names the member. The expected map has at
   most 64 string keys and serializes to at most 16,384 bytes; permitted names are a unique
   list of at most 64 strings. Overlap between the two, an extra field, or naming a member
   the library reads itself (`alg` and `jwk` for JWS; `alg`, `enc`, `iv`, `tag`, `epk`,
   `apu` and `apv` for JWE) is `:invalid_policy`. An empty expected map is valid; the
   application chooses how complete its expectations are.
3. Every received member is read by the selected algorithm, expected, or permitted. Any
   other member returns `:unexpected_member`. Member and expectation checks run before key
   resolution.
4. Under `embedded_key: :require`, `jwk` must be a public RSA key (only `kty`, `n`, `e`;
   2,048 to 8,192 bits), an EC key (only `kty`, `crv`, `x`, `y`; P-256 or P-384) or an OKP
   Ed25519 key (only `kty`, `crv`, `x`) that `RequestSeal.PublicKey.import/2` accepts.
   Private members, `oct`, X25519, a non-object or an import failure return
   `:invalid_header` at layer `:input`. Shape precedes binding: a valid key that does not
   fit `alg` returns `:algorithm_mismatch` at layer `:key`. The resolver receives the
   imported key and may answer only `key: :embedded`; the signature is always checked with
   that key over the received bytes.
5. Under `embedded_key: :refuse`, `jwk` is `:unsupported_header`, and the resolver answers
   with a `RequestSeal.PublicKey` or a `:verify` handle bound to `{:jws, alg}`.
6. `jku` and `x5u` stay unsupported. `x5c` passes through uninterpreted only when the
   policy expects or permits it, and the library performs no certificate path validation.
7. An embedded-key verification proves only that the embedded key signed the received
   bytes. It makes no claim, method, URI, time, replay, identity or authorization decision;
   an application that needs one builds it on the verified result.

## Alternatives

1. **Keep the 1.x shape and let callers inspect headers after success.** The call stays
   small. Each caller must repeat the check, and an unread member passes silently.
2. **A caller predicate over the header.** Flexible. It runs caller code on
   unauthenticated data inside the verification deadline and has no bounded refusal
   reason.
3. **Treat an embedded key as an identity.** Convenient for protocols that carry the key.
   It confuses key possession with identity and moves trust decisions into the library.
4. **Keep refusing `jwk` in every case.** The smallest surface. Protocols that carry the
   signing key in the header then parse and verify JOSE outside the library.

## Consequences

Every JOSE verify and decrypt policy changes in 2.0; the upgrade guide maps each 1.x
policy. Headers read before authentication are untrusted: a forged header that matches the
expectations can still reach resolution and custody, so resolvers must have no
authorization, replay or other trusted side effects. Expected values are public context.
The `jwe.protected` corpus surface carries the cross-language cases, and the TypeScript
package adopts the same policy in its next minor line. This record stays Proposed until
the change lands on the main branch.
