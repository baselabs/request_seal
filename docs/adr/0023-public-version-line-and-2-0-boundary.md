# 0023 — Version the public line by semver and put the 2.0 breaks in one release

## Context

The 1.0.0 release put the public modules, behaviours and `RequestSeal.Profile` under the
compatibility promise. Custody delivery, key handles, JOSE policy and generated keys all
need breaking changes. Spreading them across several majors would make every application
migrate more than once, and the TypeScript package and other implementations follow the
Elixir corpus.

## Decision

Public packages follow semantic versioning; behaviours and `RequestSeal.Profile` are stable within a major.
The 2.0 contract groups indexed unwrap, AES-KW custody, ECDH-ES, protected-member policy,
bounded JWE coordination, generation/derivation, handle-only keys, and install-bound replay.
Breaking changes require a major release and cannot enter a minor line.
Webhook-secret custody, additional JOSE serializations/key formats, and JWT are additive contracts
([ADR 0032](0032-json-serializations-and-jwt-line.md)).
Counterparts adopt each major's corpus, error vocabulary, and reciprocal peer together.

## Consequences

The 2.0 release waits on its slowest required slice, including an outside release
([ADR 0029](0029-ash-onetime-2-custody-and-install-bound-replay.md)). A single upgrade
guide covers every break. The 1.x line receives only security fixes after 2.0.
