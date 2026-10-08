# ADR 0001: Own one native standards library

- Status: Accepted
- Date: 2026-10-06

## Context

RequestSeal must cover complete RFC 9421 semantics, all current IANA algorithms, RFC 9651 Structured Fields, RFC 9530 digests, the source-selected Web Bot Auth draft and generic compact JOSE. It must work without a framework, network, process, or store. Elixir is the project-owned reference implementation; native TypeScript implements the same contract and corpus without a Go runtime.


## Decision

Build one Elixir library that owns HTTP message-signature parsing, signature-base construction, Structured Fields schemas, digest integration, named profiles, layered results, and the shared corpus. Use OTP `:crypto`/`:public_key` through an internal algorithm boundary. Use one qualified JOSE dependency for JWK/JWS/JWT/JWE primitives required by generic JOSE and discovery; it does not own RequestSeal profile decisions or result semantics. Exact dependency versions are selected and locked by the implementation/release qualification gate rather than guessed in this design record.

Prefer qualified internal reuse plus targeted extensions where a candidate preserves the complete required behavior. Implement owned machinery where qualification fails. An internal translating adapter may hide a dependency model completely; reuse does not require a second public API. Existing signature libraries also remain independent interoperability counterparts and sources of adversarial vectors. RequestSeal may contribute corrections upstream, but its public contract cannot be a pass-through wrapper over one of them.

## Strongest alternatives

1. **Owned public semantics over a qualified internal engine and targeted extensions.** This preserves RequestSeal's model, errors, profiles, custody, and corpus while reusing protocol machinery. It is preferred when actual qualification proves raw occurrences, targets, trailers, multiple signatures, bounds, and errors survive its internal boundary. A different internal type alone is not a reason to reject it.
2. **Entirely owned protocol machinery over runtime primitives.** This permits exact control where an engine cannot preserve required semantics. Choose it for demonstrated qualification failures; ownership by itself is not evidence that new parser/base code is better. Candidate-specific extensions must be tested before concluding that a reported feature gap precludes reuse.
3. **One Go core called from both languages.** One executable implementation could reduce duplicated protocol logic. It adds a runtime/process or NIF boundary, weakens Elixir installation/custody ergonomics, and violates the accepted native-language contract.
4. **Two unrelated implementations and test suites.** This maximizes idiomatic freedom. It lacks one semantic arbiter and makes quiet drift in profiles and rejection behavior likely.

## Deciding evidence and deletion test

An owned semantic boundary keeps the message model, profiles, errors, and custody contracts independent of an internal dependency. Internal reuse is selected through actual lossless qualification, not by exposing a second public model. Retain an internal adapter only when it hides real representation or lifecycle differences. A pass-through wrapper that hides no knowledge is inlined. Published vectors and differential cases decide whether a candidate preserves the required behavior; source inspection alone does not prove that qualification.

## Consequences

RequestSeal carries full responsibility for standards maintenance and corpus quality. Consumers get one coherent model, error vocabulary, profile selection, and adapter contract. Cryptographic and JOSE primitive implementation stays with established runtimes/libraries rather than being rewritten. TypeScript remains a separate native package and shares data, not runtime code.

## Acceptance

- One ordinary Elixir consumer installs without Phoenix, Ash, a daemon, network configuration, or a store.
- Every required RFC/profile feature maps to owned code and shared-corpus cases.
- OTP and JOSE boundaries are covered by real primitive/vector evidence.
- No public module merely forwards another signature library's API.
- Native TypeScript runs reciprocal corpus checks without Elixir or Go.


## Amendment

October 8, 2026: the TypeScript counterpart is deferred; RequestSeal is Elixir only. The cross-language corpus format remains a design for later use.
