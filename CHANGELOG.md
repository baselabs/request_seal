# Changelog

## 0.4.1 - Unreleased

- `RequestSeal.Custody.sign/3`, `verify/4`, `RequestSeal.Crypto.sign/4` and `verify/5` accept `max_bytes:` (1–16,777,216, default 1,048,576). The default and the existing `:invalid_data` rejection are unchanged. Out-of-range or non-integer values reject with `:invalid_options` before handle, capability, or algorithm validation. `unwrap/3` does not accept it. `Crypto.max_bytes_ceiling/0` exposes the shared ceiling.
- Direct `Custody.Local.sign/4`, `Local.verify/5`, `Custody.SSHAgent.sign/4`, and `SSHAgent.verify/5` callback calls (outside `RequestSeal.Custody`) accept up to the 16,777,216-byte ceiling; `Local` previously stopped at 1 MiB. They reject larger or nonbinary inputs with the bare reason `{:error, :invalid_data}` before reading the key reference, so such inputs no longer report `:key_mismatch` or a `RequestSeal.Crypto.Error` struct first. The public `RequestSeal.Custody` and `RequestSeal.Crypto` functions are unchanged for callers that pass no `max_bytes:`.
- Third-party custodians that sign with `Crypto.sign/4` or verify with `Crypto.verify/5` must pass `max_bytes: RequestSeal.Crypto.max_bytes_ceiling()`; custody has already enforced the caller's bound.
- The SSH-agent custodian forwards larger requests unchanged. [OpenSSH caps the whole agent message at 256 KiB](https://github.com/openssh/openssh-portable/blob/V_9_9_P1/ssh-agent.c), including protocol overhead, so the practical payload limit is slightly under 262,144 bytes. Observed with OpenSSH 9.9 and Ed25519: 262,000 bytes signed successfully; 262,200 returned `:custodian_protocol`.
- `RequestSeal.Message`, `Body`, JWS, and the Plug keep their fixed 1 MiB limits. This release does not propagate the new custody/crypto opt-in to those APIs. `RequestSeal.SignatureBase` retains its separate 1 MiB ceiling.

## 0.4.0 - 2026-10-10

- Accept an algorithm-bound `RequestSeal.KeyHandle` in the explicit
  `RequestSeal.sign/4` form. `signing_timeout` accepts 1–300,000 ms, default 5,000.
  The existing arity-two function signer stays synchronous and preserves its
  existing errors and wire bytes.
- A handle/spec algorithm mismatch in that form returns reason
  `:signer_algorithm_mismatch`, layer `:input`, and the exact message string
  `"signer algorithm does not match signature specification"`.
- Preserve custody signing failures as `RequestSeal.Error` with reason
  `:signing_failed`, layer `:crypto`, and a bounded `RequestSeal.Custody.Error`
  in `source`. For the existing signing-spec path with a `KeyHandle`, the reason
  was `:signer_failed`, now `:signing_failed` with the custody error as `source`.
  Core errors add `message` and `source` fields, both nil for existing
  non-custody failures. Malformed signing output uses custody
  `:invalid_signing_output`; malformed custody errors use `:custodian_failure`
  on both HTTP signing paths.
- Add caller-supervised `RequestSeal.Custody.Local.Owner` for Ed25519 seeds
  from tagged environment, file, and file-from-environment sources. Encodings
  are `:base64url`, `:base64`, `:hex`, and `:raw`; source inputs are bounded to
  4,096 bytes and decoded seeds to 32 bytes. Files require mode 0600 or stricter
  and must be regular, not symbolic links. Bad keys report bounded statuses
  and fail closed without preventing startup.
- Owner restart rereads sources and retires cached handles. Fetch per operation
  or fetch again and retry once on `:key_not_found`; prefer direct file sources
  in production. Environment variables are never deleted by the Owner.
- Owner queries distinguish `:owner_unavailable` from an unconfigured key.
  Empty environment values and empty file paths from environment variables
  report `:unconfigured`. Files removed or replaced after initial checks report
  `:insecure_file`. Encoded seeds require canonical trailing bits and trim only
  ASCII space, tab, CR, and LF. Base64url padding remains optional.
- Owner terminate and crash reports discard private reason terms while retaining
  configured key names, bounded statuses, and an atom failure reason.

## 0.3.1 - 2026-10-09

- Tighten corpus validators to skip `.DS_Store` only for empty regular files or
  files starting with Finder metadata magic; reject other contents and directories.
  Refuse release packaging if any `.DS_Store` exists and exclude the name from tar
  as a second guard.

## 0.3.0 - 2026-10-09

- Reject Structured Fields byte sequences with nonzero unused base64 pad bits
  under RFC 4648 Section 3.5; retain missing-padding recovery under RFC 8941
  Section 4.2.7. Pin the affected HTTP WG cases to rejection.
- Enforce RFC 3986 Section 3.2.2 IP-literal grammar for message authorities:
  accept IPv6 and IPvFuture, reject bracketed IPv4 forms and zone identifiers.
- Add a canonical conformance corpus, source provenance, digest inventory, full
  batch execution, rejection rule mapping, and mutation checks.
- Execute all twelve RFC 9421 signature bases and five Appendix B.4
  transformations independently; correct rejection inputs to isolate one defect.
- Publish deterministic checksummed corpus assets from release tags.
- Bound caller clocks and replay sweeps at 253,402,300,799 Unix seconds;
  retain the Structured Fields wire integer range. ETS and Postgres sweeps now
  reject negative inputs. Generic verification rejects negative caller clocks.
- Reject replay claims whose retention end exceeds 253,402,300,799; no accepted
  sweep clock can evict them. Stores return their existing invalid-claim failure.
- Reject generic and Web Bot Auth verification whose derived replay retention
  end exceeds 253,402,300,799 with `:retention_exceeded` at `:replay` before
  commitment or storage. Bound policy `max_age` at the same maximum;
  larger values reject with `:invalid_policy`. Skew retains its existing
  0..86,400-second range.
- Upgrade note: Postgres replay rows written before 0.3.0 with `retain_until`
  above 253,402,300,799 are never swept by `sweep/3`. Operators can remove them
  manually (replace `replay_claims` with the caller-selected table name):
  `DELETE FROM "replay_claims" WHERE retain_until > 253402300799;`
- Reserve hyphenated core profile package names.
- Document the separate TypeScript package in progress and corpus vendoring.

## 0.2.0 - 2026-10-09

- Document `RequestSeal.Custody.run/2` as a public deadline and cancellation
  boundary, with sensitive workers, caller and context-owner monitoring,
  nested cancellation, bounded failures, and revocable replies with cleanup.
- Change the formerly undocumented `Custody.run/2` return contract: bare `:ok`
  returns `{:ok, :ok}`; other bare returns become `:custodian_failure`; non-Context
  arguments return `:invalid_options` instead of raising; context-owner death
  returns a nonretryable `:custodian_failure` error instead of silence. An owner
  already dead at entry prevents callback execution.
- Document the dirty-NIF cancellation limit: cleanup waits for the runner's exit,
  so a long native call can overshoot the deadline.
- Add `RequestSeal.Profile.valid_signature_input?/1` for parsed RFC 9421
  Signature-Input Inner List semantics, delegating to the shared validator.
- Document `RequestSeal.Replay.Claim.valid?/1` without changing its validation.
- Document JWS verification and JWE encryption/decryption arguments, exact
  policy shapes, error results, and executable cryptographic examples.

## 0.1.0 - 2026-10-08

First public release: RFC 9421 HTTP Message Signatures, source-selected Web Bot Auth,
compact and nested JOSE, caller-owned key custody and discovery, replay protection,
and optional Plug/Phoenix, Req, Finch, Ash, ash_hooks, and ash_onetime integrations.
Includes executable guides, published-vector checks, and Livebooks.

- Cover webhook URL queries, generate a new nonce per attempt, reject duplicate
  signed fields, and preserve transport exceptions with distinct signing errors.
- Bind inbound webhook policy resolution to tenant and key reference.
- Validate durable replay claims before encoding and anchor retention to the
  database transaction clock; retain spent nonces across indeterminate timeouts.
- Preserve portable replay guide coverage and require optional integration
  metadata and Elixir 1.20 or newer for publishing.

- Added optional `RequestSeal.Replay.AshOnetime` for independently committed durable nonce claims, deadline propagation, and ash_onetime-managed retention and cleanup. It is the recommended durable store; `Replay.Postgres` remains available.
- Added `RequestSeal.AshHooks.Http` for final-byte RFC 9421 signing through ash_hooks' bounded transport, and `RequestSeal.AshHooks.verify_signature/4` for Provider delegation. Added executable webhook and durable replay examples.
- Optional ash_onetime `~> 1.5` and ash_hooks `~> 2.0` run on the latest Elixir lane; Elixir 1.18/1.19 omit them. Raised the Ash dependency floor to 3.34.3.

- Req and Finch accept the same defaulted signing specs as `RequestSeal.sign/4`, with fresh nonces per attempt and unchanged full-spec wire bytes.
- Plug verification accepts zero-arity policy functions and policy MFAs, validates their results per request, and contains callback failures.
- Req and Finch reject the `:nonce` option; selected nonces regenerate per attempt or invocation.
- Spec signing preserves `:unsupported_component` and `:invalid_request` errors and bounds callback faults without hiding internal exceptions.
- Core spec signing defaults metadata and requires a positive integer expiry; negative clocks reject.
- `sign/4` documents separate types for explicit-input function signing and spec function or key-handle signing.
- The request builder lowercases scheme/host, omits default ports, and rejects fragments and invalid UTF-8 before URL parsing.


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
