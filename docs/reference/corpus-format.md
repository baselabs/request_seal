<!-- Status: current · Kind: reference · Updated: 2026-10-09 · Governed by: ADR 0009 · Review when: corpus schema, surfaces, or publication changes -->

# Conformance corpus format

The repository's `corpus/` is the shared, language-neutral semantic contract.
Expectations come from cited public vectors or independent derivations. A consumer
must never regenerate them using the implementation under test. Corpus files are
repository tooling and release assets; the Hex and npm packages exclude them.

## Layout and encoding

`index.json` inventories `sources/<origin>/` and `cases/<surface>/`. Sources retain
upstream fixture bytes, licenses, provenance and SHA-256 inventories. Manifests and
the index use [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) canonical JSON:
sorted object keys by UTF-16 code units, compact encoding, unmodified Unicode,
and arrays in semantic order. The corpus uses a number-free I-JSON profile.
Every exact integer is `{"int":"253402300799"}`; exact decimals are
`{"dec":"1.25"}`. This also applies to batch counts. Bytes are
`{"b64":"<base64url without padding>"}`. Ordered JSON occurrences use
`{"pairs":[["name","value"]]}`. A source reference is
`{"ref":{"file":"sources/...","pointer":"/0/message"}}`, with an
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901.html) JSON pointer.
Source files themselves retain their original numeric and binary encodings.

## Index

Format `request-seal-conformance-corpus-index/1` requires:

- `elixir_release`: the source release tag, first published with `v0.3.0`.
- `files`: every regular file below sources and cases, sorted by relative path,
  each with `path` and lowercase hexadecimal `sha256`.
- `cases`: unique `id`, `manifest`, `surface` and `class` entries. A batch also
  carries its tagged `count` and `not_applicable` count, including zero.
- `known_positive`: a listed positive case that must execute successfully.

The Elixir consumer pins the index SHA-256 in its test support. Another repository
pins the release tag, source commit and index SHA-256 together. Consumers verify
that pin before trusting the inventory, verify every file digest, reject unlisted
or missing files and unsafe paths, execute each single and asserted batch item once, and tie out
counted not-applicable items against their declared counts in each batch, and
executed plus not-applicable count against singles plus declared batch counts. A digest mismatch or
unknown format rejects the whole corpus before conformance results are accepted.

## Single manifests

Format `request-seal-conformance-case/1` requires `id`, `surface`, `class`,
`evidence_class`, `source`, `inputs` and `expected`. Source identity contains
`document`, `section` and `url`. Evidence is `published_vector` or
`reviewed_derivation`; the latter requires `derivation`. Every `positive` reference must name an existing case other than itself and
requires `reviewed_derivation`. Authored rejection cases
name their `positive` baseline and describe one defect, derived from the cited
clause before executing either implementation.

Classes are `byte_exact`, `verify_only` and `rejection`. Byte-exact outputs compare
encoded bytes or canonical results exactly. Verify-only cases validate published
signatures or decrypt existing ciphertext; randomized output is never a golden
signing expectation. Rejections compare `expected.rule_id`. Core and JOSE rules
use `<kind>/<layer>.<reason>`; other errors use `<kind>/<reason>`. One consumer
function maps each of the eleven error structs to its kind.

Required replay on the `verify` surface uses a descriptor with `identifier: "nonce"`,
`store: "ets"`, `commitment: "identifier"`, namespace bytes, and a tagged timeout.
The consumer owns the real ETS store for that case and closes it after execution.

Optional `keys` references identify named source keys. `policy` supplies each
required algorithm, coverage, resolver, freshness, content and replay choice.
`now` injects the evaluation clock; `nonce` supplies deterministic signing input.
Callbacks are selected by semantic input descriptors: real local keys or an
explicit faulting callback for a caller-boundary rejection. They are not service
replies. No network discovery or PostgreSQL service is required by the corpus.

| Surface | Inputs | Expected positive |
| --- | --- | --- |
| `structured_fields.parse`, `.serialize` | Field type, revision, mode, raw bytes or typed tree | Canonical `bytes` |
| `message.validate` | Lossless message, ordered field occurrences, retained or unavailable body | `valid` |
| `signature_base.build` | Message, Signature-Input Inner List, explicit field schemas | `base` bytes |
| `sign` | Message, explicit or generated-metadata spec, clock/nonce options, source key | Exact appended field pairs for HMAC, Ed25519, RSA v1.5; `valid` after verification for ECDSA and RSA-PSS |
| `verify`, `quorum.verify` | Message, selected label or quorum and explicit policy | Canonical verification facts or verified quorum validity |
| `accept_signature.parse` | Raw field bytes, explicit target kind | Canonical `bytes` |
| `digest.content` | Exact body bytes, selected algorithms and field kind | Canonical digest `bytes` |
| `crypto.verify` | Algorithm, public source key, data and signature bytes | `valid` |
| `key.import` | Public material and format | `{"valid":true,"public":{"thumbprint":"<RFC 7638 thumbprint>"}}` |
| `jws.sign`, `jws.verify`, `jwe.decrypt`, `nested.decrypt` | Compact bytes or protected occurrence pairs, keys and pinned policy | Exact compact bytes or verified/decrypted `payload` |
| `web_bot_auth.verify` | Message, injected directory body, trusted origins, explicit clock and policy | Per-label canonical verification facts |
| `discovery.body` | Injected body, source kind/location, limits and evaluation clock | Public key thumbprints |
| `replay.claim` | Namespace/key bytes, created/expires/max-age/skew, clock | Retention end and optional lowercase hexadecimal row |
| `profile.name` | Package/kind pair and bounded metadata | `valid` |

HTTP message attributes match the existing RFC 9421 fixture shape. Manifest-owned
field and body bytes use byte tags; `append_fields` appends ordered occurrences,
and `message_override` changes a single validated attribute for a rejection.
If the referenced message already contains `Signature-Input` and `Signature`,
as in RFC 9421 Appendix B.4, those occurrences are used directly; appending them
again would introduce duplicate labels rather than verify the published message.
The replay surface uses the real caller-owned ETS store and verifies the actual
receipt and stored row. Its `operation: "sweep"` form checks the explicit sweep
clock; the adapter's raw invalid-input failure maps to `replay/invalid_options`
for this surface. Caller clocks and sweeps are integers from 0 through 253,402,300,799.
Verification with required replay and a derived retention end above that maximum
rejects with `core/replay.retention_exceeded` before commitment or storage. Direct
store calls keep the existing invalid-claim failure; negative retention ends
remain already-expired claims. Policy max-age above the clock maximum rejects
with `core/input.invalid_policy`; skew retains its existing integer range of
0..86,400 seconds. These contracts are recorded in CHANGELOG 0.3.0.
Retention is the minimum present freshness end: expiration
plus skew, or creation plus max-age plus skew plus one. Expiration is exclusive;
max-age accepts its final second.

## Batch manifests

Format `request-seal-conformance-batch/1` uses `class: "mixed"` and a `batch`
object with source `file`, versioned `item_format`, tagged `count`, and
`"not_applicable": {"int":"<count>"}` (zero when every item is asserted). The index
repeats both counts. Each batch compares its independently counted not-applicable
items with the declared count; a mismatch rejects with `not_applicable_count`.
Each asserted upstream item executes exactly once;
not-applicable items remain in the listed count and are counted separately.
Parse and serialize checks of the same item are one execution, not two inventory items.

Named formats are `httpwg-structured-fields/1`, `wycheproof-aes-gcm/1`,
`wycheproof-rsa-oaep/1`, `wycheproof-ed25519/1`, `wycheproof-ecdsa/1` and
`rfc9421-signature-bases/1`. Each has one consumer implementation.
HTTP WG format uses the original `name`, `raw`, `header_type`, `expected`,
`must_fail`, `can_fail` and `canonical` members, including serialization-only
files. Every `can_fail` item has exactly one `pins` entry, with chosen outcome
and clause-based reason. No other item has a pin.

Batch manifests may declare per-item `overrides` keyed by decimal `tcId` or
upstream `name`. A rejection override is
`{"outcome":"reject","rule_id":"<stable rule>","clause":"<cited section>"}`;
a non-applicable override is
`{"outcome":"not_applicable","reason":"<why this surface cannot exercise the item>"}`.
Every listed override must name an item present in the source. The consumer
follows the upstream verdict for every unlisted item; adapter code must not
contain implicit outcome overrides. Non-applicable items are reported separately:
listed batch items = asserted batch items + not_applicable;
executed = singles + asserted batch items.

Wycheproof formats enumerate all groups and tests, preserving `tcId`, inputs and
valid/invalid outcomes. The AES suite exercises the real JOSE GCM primitive through
GCM key unwrapping with empty AAD, under the selected compact JWE restrictions.
The selected key-wrap set is A128GCMKW/A256GCMKW; it excludes A192GCMKW,
which [RFC 7518 Section 4.7](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7)
also registers. The declared overrides reject 192-bit keys under that selection
and IVs other than 96 bits or tags other than 128 bits under Section 4.7.1.
Arbitrary non-empty AAD is not applicable: AES GCM key wrapping uses empty AAD
under Section 4.7.
Non-empty RSA-OAEP labels are not applicable because JOSE selects the empty
label (RFC 7518 Section 4.3). All these decisions live in each manifest.
RSA-OAEP otherwise applies SHA-256/MGF1 SHA-256. The signature suites use raw
Ed25519 and fixed-width ECDSA P1363. Without an override, AES items require
128- or 256-bit keys and empty AAD, RSA-OAEP items require empty labels, and
all Wycheproof items require a valid or invalid verdict. Unsupported shapes,
including `acceptable`, reject with `unexpected_item_shape` and the item ID.

`rfc9421-signature-bases/1` enumerates each original item followed immediately by
its `transformations` in source order. Each transformation is a separate sub-item
with its own execution count and zero-based batch position. The twelve original
items and five Appendix B.4 transformations therefore declare a count of 17.
Original items compare the built base byte for byte to their published `base`.
Transformation sub-items inherit the parent's `parameters` and published `base`,
build from their own `message`, and compare equality to `same_base`: `true`
requires equality, and `false` requires different bytes. A build error fails
either comparison. Message construction matches the published-vector tests:
ordered field occurrences, authoritative request method/target/scheme/authority,
or response status and recursively constructed related request. Existing signature
fields remain single occurrences. This format preserves every published base and
transformation expectation; separating transformations corrects the adapter's
comparison of a built-base result to a boolean and makes each check count once.

## Canonical Verification

`expected.verification` has the fixed members `label`, `signature`, `profile`,
`content`, `freshness`, `replay`, `principal` and `authorization`. Object bytes use
RFC 8785 key order; arrays preserve base and wire order.

`signature` contains `algorithm`, `covered` as identifier/ordered-parameter pairs,
ordered decoded `parameters`, nullable `keyid` and `crypto: "valid"`. Profile
names are `rfc9421`, `web_bot_auth` with the exact selected revision, or an
extension package/kind pair. Content is `not_required` or digest facts (`kind`,
`checked`, tagged `bytes`, `unsupported`). Freshness is `not_evaluated` or
`now`, `created`, nullable `expires`/`max_age` and `skew`, with tagged integers.
Replay is `not_required` or namespace/key bytes and a tagged retention end.
Principal is `unattributed` or trusted origin, source kind and thumbprint.
Authorization is always `not_evaluated`. Web Bot Auth groups those facts by label.
Parameter order is recovered from the actual parsed wire input and checked
against the successful API result; a host map's iteration order is not wire order.

## Changes from the design note

This reference governs the format. Verification objects use RFC 8785 sorted
keys rather than the design note's listed member order; semantic arrays remain
ordered. Batch counts use `{"int":"..."}` rather than bare integers. The source
origin for public HTTP examples is `local-http`, not `local-keys`. Deterministic
HTTP signing (HMAC, Ed25519, RSA v1.5) and JWS signing (HS256, EdDSA, RS256)
compare exact output bytes; ECDSA and RSA-PSS use verification only. Positive
key imports include the RFC 7638 public thumbprint. Per-item overrides and separate
non-applicable counts supersede implicit adapter outcomes. Publication begins at
`v0.3.0`, the release containing these contracts and the corpus.

## Publication and vendoring

From `v0.3.0` onward, the `v*` release workflow requires the index release tag
and package version to match the pushed tag, runs the Elixir corpus test against
its pinned index digest, and verifies the inventory, creates a deterministic
`corpus.tar.gz` with fixed timestamp and numeric ownership, and publishes that
asset plus `corpus.sha256` on the tag's GitHub release. The archive root contains exactly `index.json`, `sources/`, and `cases/`;
both consumers refuse other paths in the corpus root. Existing assets are downloaded
and compared byte for byte; a differing digest fails publication without replacement.
Missing assets are uploaded to existing releases. The TypeScript package `request-seal` vendors `conformance/` from one
release tag. Its source pin records tag, commit and index SHA-256; updating the
pin and vendored bytes is a reviewed commit. Corpus data stays outside published
runtime packages.
