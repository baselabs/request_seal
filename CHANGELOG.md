# Changelog

## Unreleased

- Added lossless request/response builders and framework-free spec signing shared with the Req and Finch adapters. The quick start uses exact body bytes and an explicit verification policy.
- Custody runners and middle processes now set sensitivity before every operation. JWE handle-binding failures follow the same random-CEK authentication path and complete error as OAEP/GCM failures; direct unwrap rejects empty OAEP plaintext with `:decryption_failed`. Added recipient-handle guides and startup health checks.
- Added algorithm-bound local RSA-OAEP and RSA-OAEP-256 decryption custody, private PEM/PKCS #8 DER/JWK import, and `RequestSeal.Custody.unwrap/3`; JWE resolvers accept unwrap handles while retaining random-CEK fallback and identical OAEP/GCM failure errors.
- Added executable installation and integration examples, task-oriented guides, and grouped API documentation. Documentation metadata is retained in hidden HTML comments; the documentation check requires byte-identical tested Elixir examples.
- The TypeScript counterpart and npm package remain deferred; this release targets the Elixir library.

- JOSE protected headers now use compact JSON with top-level members in caller order.
- Feature-adaptive public-key encoding supports Elixir 1.18 or newer on OTP 27 or newer, tested in CI on Elixir/OTP pairs 1.18.4/27, 1.19.5/28, and 1.20.4/29. PKCS #8 v2 (OneAsymmetricKey) containers reject. CI validates all three pairs and optional client floors on the floor toolchain.
- Added fixed-seed parser, signature, and replay properties with 300 runs per property, real cryptography, and caller-provisioned PostgreSQL storm checks.
- Compact and nested JOSE parsing stops at the first excess segment instead of allocating all attacker-supplied segments.
- Discovery rejects trailing non-JSON whitespace according to [RFC 8259 Section 2](https://www.rfc-editor.org/rfc/rfc8259.html#section-2).
- Added reproducible input-ceiling and RSA-OAEP failure-timing measurements; the threat model records the observed distributions.

- Added a package-namespaced extension surface for named application profiles.
- Added explicit directory-assigned discovery key IDs while retaining computed thumbprints for identity, revocation, and removal.
- Added `RequestSeal.JOSE.JWS.sign_protected/4` for caller-serialized protected JSON bytes with the same bounds and header rejections as `Header.json/1`.
- Added explicit Web Bot Auth protocol-00 signing and source-bound verification with nested coverage and whole-envelope replay; deployed-verifier acceptance remains open.
- `RequestSeal.Verification` inspection no longer shows `principal` for any profile; access authenticated principals explicitly.

- Plug verification requires the original replay adapter and, after any replay read, full draining with a digest matching the complete captured body. Partial reads, unread-suffix tampering, and replaced adapters reject before key resolution. The configured RequestSeal body reader records invocation; custom readers that bypass both it and the adapter remain a documented caller-configuration boundary.
- Invalid replay lengths return bounded errors without rewinding. Malformed response callback state produces an empty unsigned failure; absent callback state remains supported. Parameterized `set-cookie` coverage also rejects pending cookies.

- Plug verification permits unread raw bodies after pass-through parsing, including requests without a content type. Trusted IPv6 ranges containing IPv4-mapped addresses also match native IPv4 peers; unrelated transition forms do not acquire IPv4 trust.
- Plug Capture omits connection headers on HTTP/2 rejects. Retained-body replay runs at the adapter for multipart and default readers, honors read lengths, and checks a handed-out byte digest before verification. Wrapper readers must preserve returned bytes.
- Plug response signing runs after registered callbacks and rejects covered `set-cookie` fields when response cookies await Plug's later merge, including cookies added by session callbacks. Explicit final cookie headers remain signable.

- Plug verification rejects required or covered `@request-target`, `@target-uri`, and `@query` with `:unsupported_component` when exact transport evidence is unavailable. Response signing refuses the same related-request components; path, method, authority, fields, and content coverage remain usable.

- Added optional Plug/Phoenix request capture, explicit trusted-origin reconstruction, private verification results, parser body replay, and final-response signing bound to the captured request.
- Added bounded compact JWS/JWE and one-level nesting with pinned algorithms, protected bytes, sensitive results, published RFC/Wycheproof vectors, real entropy failure, and reciprocal Node WebCrypto/OpenSSL checks.
- Req signing rejects transport overrides outside an explicit option allowlist; allowed cross-origin redirects strip standard and caller-declared credential headers. Verified responses use bounded collection and verification before retry or redirect, including intermediate responses. Function signers share custody deadlines and cancellation.
- Local custody now keeps key material in sensitive per-handle holder processes with random 32-byte tokens and constant-time token checks; holders live until creator exit or explicit `RequestSeal.Custody.Local.release/1`, so long-lived owners must release unused handles or reuse handles created at startup.
- Added explicit Ash actor/tenant/context bindings, authorization-enabled scopes, and real ETS policy denial and tenant-isolation checks.
- Added optional Req/Finch adapters with final-attempt signing, fresh retry/redirect parameters, explicit origin policy, exact response association, and bounded verified streaming delivery.
- Added RFC public-key thumbprints and explicit HTTPS directory/JWKS/CIMD discovery with signed possession proofs, address and byte limits, cancellation, and a caller-started cache for freshness, rotation, removal, and revocation.
- Discovery cache freshness honors Cache-Control before Expires with Date/Age accounting; fallback freshness defaults to 300 seconds and negative entries are capped at 300 seconds. CIMD failures are not cached, expired snapshots are not served after refresh failure, and 5xx status failures are retryable while 4xx failures are not.
- Added post-validation nonce replay commitments, bounded deadlines and retention, atomic caller-owned ETS and optional Postgrex stores, and real concurrency checks.
- `verify/3` intentionally fails closed with `:duplicate_label` for repeated labels within or across Signature-Input or Signature field occurrences, per [RFC 9421 Section 3.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2).
- Signing and single-label/quorum verification reject repeated parameter names in either signature dictionary with `:duplicate_parameter`.
- Key resolvers accept an optional `:identity` member carrying trusted `RequestSeal.KeyIdentity` for quorum key-equivalence counting; identities remain internal and establish no principal attribution.
- Added explicit RFC 9421 quorum verification, trusted key/principal/role counting, nested bindings, and Accept-Signature challenge negotiation.
- Quorum results use a plural label-keyed `signatures` map for assigned signatures; `satisfied` includes optional slots, and negotiation can be fulfilled by a verified eligible label outside the counted assignment.
- Quorum assignment maximizes distinct units before filled slots, enforces unique labels and merged identity classes, and searches binding alternatives under a 131,072-node budget. New identity-bridging evidence can reduce an otherwise feasible count; budget exhaustion succeeds only with a policy-satisfying assignment.
- Quorum verification rejects required replay before callbacks and stores run. Slot policies accept retained-body Content-Digest checks, rejecting representation digests and caller-fed digest state.
- Added opaque caller-owned key handles, local OTP/private PEM/JWK custody, trusted symmetric equivalence, monitored deadlines and cancellation, and verified non-exporting OpenSSH agent signing.
- Added explicit generic RFC 9421 policy, single-label layered verification, caller-owned signing functions, bounded safe errors, and published signed-message checks.
- Added six HTTP signature primitives, explicit JWS algorithm selection, public key formats and binding, published vectors, and reciprocal OpenSSL checks.
- Added RFC 9530 content/representation digests, bounded incremental SHA-256/SHA-512 hashing, explicit trailer checks, and digest preference fields.
- Added RFC 9421 signature-base construction with all derived components, ordered field parameters, bounded safe errors, and independent Sections 2, 4.3 and Appendix B vectors.
- Added bounded RFC 8941/9651 Structured Fields parsing, canonical serialization, explicit field type schemas, and ordered Message occurrence processing with independent HTTP WG vectors.
- Digest `check/3` and `check_stream/3` reject repeated supported checksum algorithms with `:conflicting_digest`, including identical checksums.
- Streaming `init/3` accepts an explicit `max_bytes` above 16 MiB; retained-body `compute/3` and `check/3` keep that hard limit.
- Digest `preferences/3` rejects sections other than `:headers` and `:trailers`.
- Added lossless HTTP message constructors and validators for raw ordered fields, request-target forms, response linkage, explicit trailers, caller-owned body availability, and declared transport facts, with bounded errors and redacted inspection.
- Added executable API documentation, published RFC inputs, and a captured HTTP exchange for message preservation and rejection tests.
- Established the local Elixir library scaffold and exact development toolchain.
- Defined HTTP signature and Web Bot Auth scope, architecture decisions, public technical explanations, and interoperability principles.
- Added official-Livebook execution tooling and a published RFC signature learning notebook.
- No signing, verification, discovery, replay, or protocol adapter API has been released.
