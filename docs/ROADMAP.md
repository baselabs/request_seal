<!-- Status: maintained · Kind: roadmap · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# RequestSeal roadmap

RequestSeal is a standards-only Elixir library for HTTP Message Signatures (RFC 9421), content digests (RFC 9530), Web Bot Auth, compact JOSE and key custody. It owns a language-neutral conformance corpus; @request-seal/core 0.5.0 pins the v1.0.0 corpus, while native parity with the unreleased 2.0 corpus is planned for 0.6.0. Version 1.0.0 is released. The objective of this roadmap is the 2.0 release, which puts every private-key operation behind custody handles and opens JWE through one bounded coordinator, followed by additive 2.x lines for webhook-secret custody, further JOSE formats and JWT. Rows are ordered by dependency, each with observable acceptance; decisions are recorded in `docs/adr/`, and retired records and rows in [LEGACY.md](adr/LEGACY.md).

## Status board

<!-- status-board:start -->
One line per row, grouped by status and in roadmap order within each group; badges follow the evidence recorded in each row, and `test/roadmap_board_test.exs` checks that the board and the tables agree.

| Badge | Meaning |
|---|---|
| ✅ | Done and verified: landed, and the row records live, hosted or full-lifecycle evidence with no open item inside its claim |
| 🟢 | Done, not verified: landed, but the evidence is local or partial, or live, peer or production proof is still owed |
| 🟡 | Partly done: some increments landed, scoped work remains |
| 🔵 | Designed, ready to build: a judged design input or ADR with stated acceptance, nothing landed |
| ⚪ | Needs design: only a charter, strategy or posture reference |
| ⛔ | Blocked: waits on an owner decision or an outside release or service |
| ⚠️ | Watch: a known gap or risk (a flag in the Watch column beside any badge) |

Counts: ✅ 3 · 🟢 23 · 🟡 2 · 🔵 12 · ⚪ 6 · ⛔ 2

| Status | Row | Where it stands | Watch |
|---|---|---|---|
| ✅ | foundation | Scaffold, contracts and executable documentation baseline; superseded in scope by the 1.0.0 release |  |
| ✅ | elixir-range | Elixir `~> 1.18` on OTP 27 or newer |  |
| ✅ | security-hardening | Property suites, measured parser ceilings and replay storms |  |
| 🟢 | wire-model | Lossless message constructors and validators |  |
| 🟢 | structured-fields | Bounded RFC 8941 and RFC 9651 parsing and serialization |  |
| 🟢 | signature-base | RFC 9421 signature bases from the lossless message |  |
| 🟢 | crypto | Six HTTP signature primitives, JWS selection and key formats |  |
| 🟢 | content-integrity | RFC 9530 Content-Digest and Repr-Digest |  |
| 🟢 | verification-policy | Single-label `verify/3` and `sign/4` with explicit policy |  |
| 🟢 | custody | 1.x signing custody; unwrap and wrap custody have their own row |  |
| 🟢 | discovery | HTTPS key discovery with SSRF defenses and a caller-started cache | ⚠️ IPv6 end to end and the live directory check not re-probed |
| 🟢 | replay | Required-replay mode with ETS and Postgres stores | ⚠️ Restart proof is opt-in, not in CI |
| 🟢 | web-bot-auth | Web Bot Auth signing and source-bound verification | ⚠️ Deployed-verifier acceptance open; the draft's examples contradict its own Section 5.2.1 |
| 🟢 | plug-phoenix | Plug and Phoenix capture, verify and response signing | ⚠️ No tested transport exposes the raw request target, so `@request-target`, `@target-uri` and `@query` fail closed |
| 🟢 | req-finch | Req and Finch signing and response verification |  |
| 🟢 | ash | Ash scope mapping with `authorize?: true` always | ⚠️ Tenant isolation proven on the ETS layer only |
| 🟢 | corpus | Shared, source-attributed corpus with tagged release assets |  |
| 🟢 | typescript | `@request-seal/core` 0.5.0 released |  |
| 🟢 | supply-chain | 1.0.0 release workflow and three-lane CI | ⚠️ SBOM and provenance not re-verified |
| 🟢 | release | 1.0.0 published | ⚠️ Full journeys after a registry install not re-run |
| 🟢 | jose-envelopes | Compact JWS and JWE with one-level nesting | ⚠️ RSA-OAEP timing uniformity not measured |
| 🟢 | profile-extension-surface | `RequestSeal.Profile` facade, stable within 1.x |  |
| 🟢 | replay-ash-onetime | Optional replay store over ash_onetime, released in 1.0.0 | ⚠️ Persistence proof not re-run for this board |
| 🟢 | RS-custody-unwrap-sink | Indexed unwrap through a sink and AES-KW wrap on main | ⚠️ Unreleased; hosted CI not re-checked for this board |
| 🟢 | RS-ecdh-es | ECDH-ES over P-256, P-384 and X25519 on main | ⚠️ Unreleased; hosted CI not re-checked for this board |
| 🟢 | RS-corpus-layout | Every case at `cases/<surface prefix>/<name>` | ⚠️ Unreleased; hosted CI not re-checked for this board |
| 🟡 | documentation | Guides and reference for 1.x ship; 2.0 currency remains | ⚠️ README lists Ash `>= 3.37.2` and ash_hooks `~> 2.0 or ~> 3.0`; `mix.exs` requires Ash `>= 3.37.4` and ash_hooks `>= 3.0.0` |
| 🟡 | livebooks | Six notebooks ship; 2.0 currency remains |  |
| 🔵 | RS-custody-generate | Designed; nothing landed |  |
| 🔵 | RS-closure-removal | The unreleased branch removes JWS verification closures and JWE unwrap closures; remaining closure removal and the public object decoder are unbuilt | ⚠️ The complete change is not on main |
| 🔵 | RS-release-gates | Paired release gates are proposed; the reviewed branch has no paired single-token/page gate benchmark | ⚠️ A verdict requires the implemented harness and an isolated benchmark host; holder capacity uses a separate harness |
| 🔵 | RS-object-content-guide | Missing |  |
| 🔵 | RS-custody-generation-guide | Missing |  |
| 🔵 | RS-upgrade-guide | Missing |  |
| 🔵 | RS-batch-livebook | Missing |  |
| 🔵 | RS-ecdh-livebook | Missing |  |
| 🔵 | RS-published-docs-anchors | Repair identified; not started | ⚠️ Defect observed in the published docs earlier; not re-executed for this board |
| 🔵 | RS-release-2.0 | Waits on every 2.0 slice, gate and guide | ⚠️ Waits on RS-ash-onetime-2, which is blocked |
| 🔵 | RS-typescript-parity | Designed; waits on public 2.0 |  |
| 🔵 | finch-final-bytes | Final-message signing exists; no sent, not-sent or outcome-unknown classification |  |
| ⚪ | RS-jwe-coordinator | An unreleased branch implements protected-member policy and batch JWE decryption; the coordinator design needs revision | ⚠️ The replacement design has not been accepted |
| ⚪ | RS-decision-hook-recipe | Missing; needs a recipe design |  |
| ⚪ | RS-credential-proxy-recipe | Missing; needs a recipe design |  |
| ⚪ | RS-json-formats | Scope recorded in ADR 0032; no judged design |  |
| ⚪ | RS-jwt | Scope recorded in ADR 0032; no judged design |  |
| ⚪ | RS-capture | Contract recorded in ADR 0030; unbuilt | ⚠️ ADR 0030 is Proposed; the contract has not had an independent design review |
| ⛔ | RS-ash-onetime-2 | Designed; waits on the ash_onetime 2.0 release | ⚠️ The ash_onetime 2.0 release is outside this repository |
| ⛔ | RS-webhook-custody | Designed for 2.1; waits on the ash_hooks 3.2.0 release | ⚠️ Nothing landed |

Updated November 15, 2026.
<!-- status-board:end -->

## Queue

| ID | Outcome | Acceptance | Waits on |
|---|---|---|---|
| RS-jwe-coordinator | Open JWE through one bounded coordinator, with protected-member policy for JWS and JWE and `JWE.decrypt_many/2` ([ADR 0015](adr/0015-jose-protected-members-and-embedded-keys.md), [ADR 0016](adr/0016-bounded-jwe-open-coordinator.md)) | `decrypt/2` and `decrypt_many/2` end each phase with the ADR 0016 outcome at R, U and D; one custody unwrap per exact handle; no plaintext before full authentication; unread protected members return `:unexpected_member`; `embedded_key: :require` accepts only the ADR 0015 key shapes; caller death cancels every worker; the `jwe.protected` and `jwe.decrypt_many` corpus surfaces pass in both consumers on all three CI lanes | None |
| RS-custody-generate | Generate and derive keys inside custody ([ADR 0026](adr/0026-custody-key-generation-and-derivation.md)) | Local.generate/2 returns handles for the ADR 0026 algorithms, sizes and curves; a child is unusable before acknowledged atomic commit; uncommitted candidates expire or end on owner death; failed derive and explicit commit refusal return ordinary errors; a lost commit result triggers one release under a fresh 1,000 ms context; only unconfirmed destruction of a possibly committed child returns {:cleanup_required, cleanup, error}; derivation vectors cover every family; no raw key export. | RS-jwe-coordinator |
| RS-closure-removal | Replace raw-key closures with key handles and decode JSON objects strictly ([ADR 0027](adr/0027-key-handles-replace-closures.md), [ADR 0028](adr/0028-strict-json-object-decoding.md)) | No public entry point accepts a key closure; the `signer` and `verify_fun` types are gone; a mutation guard catches each forbidden caller-code surface; Accept-Signature fulfillment returns `:negotiation_unfulfillable` when no handle fits; `decode_object/2` refuses duplicates, depth, width, length and integer range per ADR 0028; `content: :object` returns no plaintext on a decode failure | RS-custody-generate |
| RS-ash-onetime-2 | ash_onetime 2 key custody and an install-bound replay store ([ADR 0029](adr/0029-ash-onetime-2-custody-and-install-bound-replay.md)) | `RequestSeal.AshOnetime.Custody` implements `AshOnetime.KeyCustody`; `Replay.AshOnetime.store` requires `:install` and takes only `:partition` and `:prefix`; one winner under concurrent claims, expiry and cancellation on real Postgres; every replay error stays nonretryable | RS-closure-removal; the ash_onetime 2.0 release |
| RS-release-gates | Paired performance gates for the single-token and page workloads ([ADR 0031](adr/0031-performance-release-gates.md)) | The benchmark measures both gates with at least 20 alternating paired rounds on separate virtual machines and exits zero; it exits nonzero when any gate fails or is unmeasured | RS-jwe-coordinator |
| documentation | Complete developer documentation, current for 2.0 ([ADR 0010](adr/0010-dx-and-livebooks.md)) | Architecture, threat model, the JOSE guide, release operations, the 2.x compatibility promise, the standards list (RFC 3394, the ECDH-ES Concat KDF, RFC 7748), README dependency floors and CHANGELOG match the 2.0 code; executable snippets run; ExDoc builds with no warnings or broken anchors The roadmap and each public ADR/index path are deliberately added by exact path to mix.exs’s public-document inventory; package inclusion, ExDoc links, metadata and disclosure checks cover every added document. | RS-jwe-coordinator, RS-custody-generate, RS-closure-removal, RS-ash-onetime-2 |
| RS-object-content-guide | Guide for strict JSON object decoding ([ADR 0028](adr/0028-strict-json-object-decoding.md)) | A guide covers `decode_object/2`, `content: :object`, the result's object and the no-plaintext-on-decode-failure rule, with runnable examples | RS-closure-removal |
| RS-custody-generation-guide | Guide for custody key generation and derivation ([ADR 0026](adr/0026-custody-key-generation-and-derivation.md)) | A guide covers `Local.generate/2`, derive and commit, cleanup and release, written against the landed contract | RS-custody-generate |
| RS-upgrade-guide | Upgrade guide at `docs/guides/upgrading-to-2.0.md` ([ADR 0023](adr/0023-public-version-line-and-2-0-boundary.md)) | Maps every 1.x call that changes to its 2.0 form: protected maps, decrypt budgets, indexed unwrap and its results, closure removal, generation and derivation, strict object decoding, the replay `:install` option, and version and corpus pins | RS-jwe-coordinator, RS-custody-generate, RS-closure-removal, RS-ash-onetime-2 |
| RS-decision-hook-recipe | Recipe for a signed decision hook | The hook request is signed; the allow or deny response is signed and bound to the request with `;req`; a Standard Webhooks response is documented as unauthenticated; the recipe links the ash_hooks guide | None |
| RS-credential-proxy-recipe | Recipe for an egress signing proxy | A runnable recipe signs outbound requests in a proxy that holds custody handles, using the existing Req and Finch adapters and no new API | None |
| livebooks | Executable Livebook curriculum, current for 2.0 ([ADR 0010](adr/0010-dx-and-livebooks.md)) | Every notebook pins `~> 2.0` and runs in a fresh process against 2.0; the overview lists every notebook; no fake peer or silent skip | RS-jwe-coordinator, RS-custody-generate, RS-closure-removal |
| RS-batch-livebook | Notebook for batch JWE decryption ([ADR 0016](adr/0016-bounded-jwe-open-coordinator.md)) | A notebook exercises `decrypt_many/2` positional results, outer failures, grouping by handle and cancellation | RS-jwe-coordinator |
| RS-ecdh-livebook | Notebook for ECDH-ES ([ADR 0018](adr/0018-ecdh-es-key-agreement.md)) | A notebook runs ECDH-ES agreement, encryption and decryption over P-256 and X25519, with rejection cases | None |
| RS-published-docs-anchors | Repair the published `KeyIdentity.same?/2` summary anchor | The generated docs link the `same?/2` summary to its function anchor, and a link check over the built docs passes | None |
| RS-release-2.0 | Publish public 2.0.0 ([ADR 0023](adr/0023-public-version-line-and-2-0-boundary.md)) | Every 2.0 row above is on main; the release gates pass; docs and notebooks are current; the `v2.0.0` tag, the corpus release asset and `mix.exs` agree; a registry install runs the getting-started journey | RS-jwe-coordinator, RS-custody-generate, RS-closure-removal, RS-ash-onetime-2, RS-release-gates, documentation, RS-object-content-guide, RS-custody-generation-guide, RS-upgrade-guide, RS-decision-hook-recipe, RS-credential-proxy-recipe, livebooks, RS-batch-livebook, RS-ecdh-livebook, RS-published-docs-anchors |
| RS-typescript-parity | `@request-seal/core` 0.6 native parity on the 2.0 corpus ([ADR 0022](adr/0022-typescript-conformance-contract.md)) | The TypeScript package repins to the 2.0 corpus and vocabulary, passes every 2.0 surface natively on Node, Deno, Bun and the browser lanes, and passes reciprocity against the published 2.0 package | RS-release-2.0 |
| RS-webhook-custody | Webhook-secret custody in 2.1 | {:standard_webhooks, "v1"} secrets sign and verify through custody; {:sender_hmac, digest} is verify-only by kind. RequestSeal.Custody.Durable provides caller-selected exclusive references, idempotent store/destroy, permanent destruction tombstones and linearizable store/destroy. RequestSeal.AshHooks.Custody implements the ash_hooks 3.2.0 AshHooks.Custody behaviour and passes its conformance suite; secrets remain in custody. | RS-release-2.0; the ash_hooks 3.2.0 release |
| RS-json-formats | JOSE serializations and key formats in 2.2 ([ADR 0032](adr/0032-json-serializations-and-jwt-line.md)) | Flattened and general JSON serialization, AAD, detached content, the RFC 9864 `Ed25519` name, DER ECDSA, SEC1 compressed points and COSE_Key, each with corpus cases and TypeScript parity | RS-release-2.0 |
| RS-jwt | `RequestSeal.JWT` in 2.3 ([ADR 0032](adr/0032-json-serializations-and-jwt-line.md)) | JWT over JWS limited to RFC 7519, the RFC 8725 best practices, the RFC 7523 assertion profile and the `oauth-id-jag+jwt` identity assertion type, with corpus cases and TypeScript parity; protocols that bind tokens to HTTP requests or TLS connections stay outside this line | RS-release-2.0 |
| RS-capture | Non-sending bounded `RequestSeal.Capture.capture/2` ([ADR 0030](adr/0030-bounded-non-sending-capture.md)) | Returns `{:ok, conn}` or `{:error, reason, conn}` and never sends or halts; one byte budget and one read deadline across reads; retained bytes never exceed the limit and over-read is at most one HTTP/1 chunk or HTTP/2 DATA frame; oversized or incomplete HTTP/2 streams are cancelled; later readers use the replay; proven on real HTTP/1 and HTTP/2 adapters | None |
| finch-final-bytes | Finch final-byte exposure ([ADR 0007](adr/0007-framework-and-proxy-adapters.md)) | Real Finch over Bandit: bytes handed back equal bytes on the wire; timeout and drop after send report outcome unknown, refusals report not sent; mutation proofs | None |

## Landed

| ID | Outcome | Acceptance | Evidence |
|---|---|---|---|
| foundation | Development foundation ([ADR 0001](adr/0001-library-boundary.md)) | Root gate, exact-pin rejection probes, package build inspection and audit; protocol APIs claimed only by their own rows | 674c1a4; final local gate, exact artifact and notebook, hosted Linux CI; released 1.0.0 (`mix.exs:50`) |
| wire-model | Lossless HTTP message model ([ADR 0002](adr/0002-lossless-http-and-structured-fields.md)) | Round-trip real HTTP adapter captures without lost occurrences, percent-encoding or context; reject ambiguous or missing data | Captured HTTP round trips and local rejection checks; hosted Linux CI on a5e416a in all three lanes |
| structured-fields | Structured Fields ([ADR 0002](adr/0002-lossless-http-and-structured-fields.md)) | Independent vectors for every type, duplicates and parameter order; fuzz and mutation bounds; revision-inappropriate types rejected | All 2,137 HTTP WG vectors pass; mutation-proven guards (77c0189, 8a7553d); hosted Linux CI on a5e416a in all three lanes |
| signature-base | Signature-base construction ([ADR 0002](adr/0002-lossless-http-and-structured-fields.md)) | Every RFC vector reconstructs exact bytes; alternate encodings, field ambiguity and lost response context fail correctly | All 12 published bases byte-exact (9b9346e, 28ba18f, 7b304eb); hosted Linux CI on 462ed7d |
| crypto | Cryptographic algorithms ([ADR 0001](adr/0001-library-boundary.md)) | Independent published vectors and reciprocal implementations; key, type and algorithm mismatches; malformed ECDSA, RSA, HMAC and Ed25519 inputs | RFC 9421, RFC 8032 and RFC 6979 vectors byte-exact; OpenSSL reciprocal both ways (fd53bf2); hosted Linux CI on 462ed7d |
| content-integrity | Content and representation digests ([ADR 0002](adr/0002-lossless-http-and-structured-fields.md)) | Hash real transmitted bytes incrementally; changed or truncated content fails; representation semantics and unknown algorithms covered | 90cd649, 8a982a6; hosted Linux CI on a5e416a in all three lanes |
| verification-policy | Public verification and signing APIs ([ADR 0006](adr/0006-verification-results-and-observability.md), [ADR 0025](adr/0025-single-label-public-verification.md)) | Cryptographically valid but policy-invalid input cannot return authenticated success; all public defaults, options and errors tested and documented | 9e9dd3c, 6a08483; hosted Linux CI on 462ed7d |
| custody | Caller-held signing custody ([ADR 0004](adr/0004-key-custody-and-discovery.md)) | Real local and authorized external signer evidence; no private material crosses public serialization or telemetry | Per-handle holder processes and OpenSSH agent signing (98c61e3, 462ed7d); hosted Linux CI on 462ed7d including the ssh-agent tests |
| discovery | Trusted identity and key discovery ([ADR 0004](adr/0004-key-custody-and-discovery.md)) | Real configured endpoints, verified key and domain association, rebinding, redirect, private-network, body and key-count limits, outage and revocation cases | a368248; hosted Linux CI on a5e416a in all three lanes |
| replay | Freshness and replay ([ADR 0005](adr/0005-atomic-replay-envelope.md), [ADR 0011](adr/0011-public-contract-provenance.md)) | One winner under real concurrent store claims for a caller-supplied commitment bound to a verified nonce and caller-defined scope; post-validation claim; cancellation, error, outage and retention tested; no unauthenticated poisoning | 9b41ab7; one winner across pools and a peer node on real Postgres; real-Postgres restart proof |
| web-bot-auth | IETF Web Bot Auth ([ADR 0003](adr/0003-source-bound-profiles.md), [ADR 0025](adr/0025-single-label-public-verification.md)) | Positive independent requests and directories, required-field failure and cross-profile attack cases; separate proof classes documented | 9c0cb1f, 2ac0761, 898944f, 879a588, 9a41468; positive vectors from an independent implementation and OpenSSL; live directory test run |
| plug-phoenix | Plug and Phoenix adapters ([ADR 0007](adr/0007-framework-and-proxy-adapters.md)) | Actual transport verifies exact body, target and response context; parser order, duplicate verification and unauthorized identity cases covered | 40a20d1, d5d3354, 294d572, d6409e9, 7133d72; HTTP/1.1, h2c and TLS h2 over real Bandit and Phoenix; hosted Linux CI on 7133d72 |
| req-finch | Req and Finch adapters ([ADR 0007](adr/0007-framework-and-proxy-adapters.md), [ADR 0020](adr/0020-separate-deadline-clocks.md)) | Actual outbound stack preserves signed bytes and cross-origin boundaries; transformations, retries and cancellation cannot reuse unsafe signatures | dafcde4; hosted Linux CI on 7133d72 |
| ash | Ash integration ([ADR 0007](adr/0007-framework-and-proxy-adapters.md)) | Actual Ash actions deny authenticated actors lacking authority; tenant context and policy failures covered | 590d937; no-Ash build compiles warning-free; hosted Linux CI on 7133d72 |
| elixir-range | Supported Elixir and OTP range ([ADR 0008](adr/0008-toolchain-and-compatibility.md)) | Capability-based key encoding on every supported release; three CI lanes (floor, mid, latest) bound by the gate | 70f511f, 175cd2a, a5e416a; hosted Linux CI on a5e416a in all three lanes (`.github/workflows/ci.yml:16-23`) |
| corpus | Portable conformance corpus ([ADR 0009](adr/0009-cross-language-corpus.md), [ADR 0021](adr/0021-corpus-case-layout.md)) | Language-neutral schema, licensed provenance, deterministic inventory, tamper evidence and executed selected cases | `docs/reference/corpus-format.md`; index pinned by the Elixir and TypeScript consumers; corpus published with v1.0.0 |
| typescript | Native TypeScript parity ([ADR 0022](adr/0022-typescript-conformance-contract.md)) | Reciprocal real Elixir and TypeScript execution with identical accept and reject outcomes across supported runtimes; all HTTP, JOSE and Web Bot Auth contracts run natively | `@request-seal/core` 0.5.0 pinned to corpus v1.0.0; 32 reciprocity rounds each direction against the published package |
| security-hardening | Adversarial and resource hardening | Recorded deterministic ceilings, measured CPU and memory bounds and meaningful mutation rejection; JOSE, AEAD and entropy resource bounds; no partial response release | 300 fixed-seed runs per property suite; 64-way ETS and Postgres replay storms (90d878f, bd2e147, 1921ecf); hosted Linux CI on 1921ecf in all three lanes, Postgres storm included |
| supply-chain | Package and dependency integrity ([ADR 0008](adr/0008-toolchain-and-compatibility.md)) | Exact tarball inspected and installed, supported Linux lanes and macOS check, dependency and advisory review, source and artifact identity verified | Release workflow and lanes in `docs/operations/releases.md` and `.github/workflows/ci.yml` |
| release | Public release and maintenance ([ADR 0023](adr/0023-public-version-line-and-2-0-boundary.md)) | Authorized publish followed by actual registry install and full promised journeys; support channels and migration behavior verified | Tag v1.0.0; `mix.exs:50`; CHANGELOG 1.0.0 notes with upgrade steps from 0.5 |
| jose-envelopes | Bounded JOSE envelope primitives ([ADR 0001](adr/0001-library-boundary.md), [ADR 0004](adr/0004-key-custody-and-discovery.md)) | Independent published vectors; algorithm, key, critical-header, Base64 and duplicate-member bounds; actual entropy failure; OAEP, IV and tag rejection; reciprocal randomized cross-decryption | 9c48edc, a91ec73, 0d22603; RFC 7515, RFC 7516, RFC 7520 and Wycheproof vectors; 32 and 32 reciprocal Node WebCrypto rounds |
| profile-extension-surface | Named-profile extension surface ([ADR 0013](adr/0013-extension-profile-boundary.md), [ADR 0024](adr/0024-provider-profiles-in-separate-packages.md)) | Core names and invalid metadata reject; extension-selected members verify without widening core authorization; profile-scoped replay and foreign-profile rejection proven with actual cryptography | `lib/request_seal/profile.ex`; under the compatibility promise (`docs/reference/compatibility.md:31-33`) |
| replay-ash-onetime | Replay on ash_onetime ([ADR 0005](adr/0005-atomic-replay-envelope.md), [ADR 0008](adr/0008-toolchain-and-compatibility.md)) | Atomic claim under concurrency against real Postgres; retention and outage fail closed | `lib/request_seal/replay/ash_onetime.ex` in v1.0.0 |
| RS-custody-unwrap-sink | Indexed custody unwrap through a sink and AES-KW custody ([ADR 0017](adr/0017-indexed-unwrap-through-a-sink.md), [ADR 0019](adr/0019-aes-key-wrap-custody.md)) | `unwrap/5` delivers through `Custody.Sink` from the key-holding process; `Custody.unwrap/3` returns ordered results for 1 to 10,000 items; `wrap/3` is AES-KW only; GCMKW and `dir` handles cannot wrap | 87e3b23; `lib/request_seal/custody.ex:52-63`, `:99-102`, `:188-189` |
| RS-ecdh-es | ECDH-ES key agreement ([ADR 0018](adr/0018-ecdh-es-key-agreement.md)) | RFC 7518, RFC 7520, RFC 7748, RFC 8037 and Wycheproof vectors pass; independent JOSE implementations decrypt the output and the library decrypts theirs | bd080a5; `lib/request_seal/jose/key_management/agreement.ex` |
| RS-corpus-layout | Corpus case layout and vector allowlist ([ADR 0021](adr/0021-corpus-case-layout.md)) | The Elixir consumer rejects a case whose id, manifest path and surface prefix disagree; the secret scan lists every corpus vector by exact file. The TypeScript consumer’s matching equality checks remain part of its 0.6 parity work. | eaae6f0; `docs/reference/corpus-format.md:10-11` |
