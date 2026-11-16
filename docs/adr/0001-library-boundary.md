# 0001 — Own one native standards library

## Context

RequestSeal must cover complete RFC 9421 semantics, all current IANA algorithms, RFC 9651 Structured Fields, RFC 9530 digests, the source-selected Web Bot Auth draft and generic compact JOSE. It must work without a framework, network, process, or store. Elixir is the project-owned reference implementation; native TypeScript implements the same contract and corpus without a Go runtime.

## Decision

Own HTTP message-signature parsing, bases, Structured Fields schemas, digests, profiles,
results, and the shared corpus in one Elixir library over OTP cryptographic primitives.
Public semantics remain independent of other signature libraries.

## Consequences

RequestSeal carries full responsibility for standards maintenance and corpus quality. Consumers get one coherent model, error vocabulary, profile selection, and adapter contract. Cryptographic and JOSE primitive implementation stays with established runtimes/libraries rather than being rewritten. TypeScript remains a separate native package and shares data, not runtime code.

## Acceptance

- One ordinary Elixir consumer installs without Phoenix, Ash, a daemon, network configuration, or a store.
- Every required RFC/profile feature maps to owned code and shared-corpus cases.
- OTP and JOSE boundaries are covered by real primitive/vector evidence.
- No public module merely forwards another signature library's API.
- Native TypeScript runs reciprocal corpus checks without Elixir or Go.

## Native primitives

Compact JOSE and public-key handling use bounded owned machinery over OTP
`:crypto` and `:public_key`; no JOSE runtime dependency is required.
Published vectors and independent cryptographic peers exercise those boundaries.
The portable corpus defines exact shared bytes and rejection semantics.

## Native counterpart

The separate native npm package `@request-seal/core` shares corpus data and
semantic contracts with Elixir, without sharing runtime code.
Its corpus identity pins a release tag, source commit, and index digest.
Each repository adopts a new corpus identity explicitly.

## Key-management primitives

ECDH-ES follows [ADR 0018](0018-ecdh-es-key-agreement.md);
AES Key Wrap custody follows [ADR 0019](0019-aes-key-wrap-custody.md).
