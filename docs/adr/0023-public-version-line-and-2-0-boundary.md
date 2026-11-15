<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0023 — Version the public line by semver and put the 2.0 breaks in one release
Status: Accepted

## Context

The 1.0.0 release put the public modules, behaviours and `RequestSeal.Profile` under the
compatibility promise. Custody delivery, key handles, JOSE policy and generated keys all
need breaking changes. Spreading them across several majors would make every application
migrate more than once, and the TypeScript package and other implementations follow the
Elixir corpus.

## Decision

1. The public package follows semantic versioning. Behaviours and `RequestSeal.Profile` are
   stable within a major.
2. Every 2.0 break ships in one release: indexed unwrap through a sink, AES-KW custody,
   ECDH-ES, protected-member policy, the bounded JWE coordinator, custody generation and
   derivation, removal of raw-key closures, and the install-bound replay store.
3. Later work is additive minor lines on 2.x: 2.1 webhook-secret custody, 2.2 further JOSE
   serializations and key formats, and 2.3 JWT
   ([ADR 0032](0032-json-serializations-and-jwt-line.md)).
4. @request-seal/core 0.6.0 follows the public Elixir 2.0.0 release and repins its corpus, error vocabulary and reciprocal peer to that release.
5. A breaking change after 2.0 waits for 3.0; it is never folded into a minor line.

## Alternatives

1. **Ship each break as its own major.** Each change lands as soon as it is ready.
   Applications migrate repeatedly, and the corpus forks across majors.
2. **Deprecate in 1.x and remove later.** Gentler migration. The deprecated closure and
   byte-return paths keep key material where the new design forbids it.

## Consequences

The 2.0 release waits on its slowest required slice, including an outside release
([ADR 0029](0029-ash-onetime-2-custody-and-install-bound-replay.md)). A single upgrade
guide covers every break. The 1.x line receives only security fixes after 2.0.
