<!-- Status: current · Kind: reference · Updated: 2026-11-13 · Governed by: public architecture · Review when: corpus schema, surfaces, or publication changes -->

# Conformance corpus format

The repository's `corpus/` is the shared, language-neutral semantic contract.
Expectations come from cited public vectors or independent derivations. A consumer
must never regenerate them using the implementation under test. Corpus files are
repository tooling and release assets; the Hex and npm packages exclude them.

## Layout and encoding

`index.json` inventories `sources/<origin>/` and `cases/<surface prefix>/` (for example, `cases/jws/` holds `jws.sign` and `jws.verify` cases). Sources retain
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

- `elixir_release`: `v` followed by the package version in `mix.exs`. The declared gate fails when they differ, and the release workflow publishes the corpus only for a tag equal to both.
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
| `verify` | Message, selected label and explicit policy | Canonical verification facts |
| `accept_signature.parse` | Raw field bytes, explicit target kind | Canonical `bytes` |
| `digest.content` | Exact body bytes, selected algorithms and field kind | Canonical digest `bytes` |
| `crypto.verify` | Algorithm, public source key, data and signature bytes | `valid` |
| `key_management.aes_kw/v1` | `alg` (A128KW/A256KW), `kek` byte tag, `operation` (wrap/unwrap), and `key_data` or `wrapped` byte tag | `wrapped` or `key_data` byte tag |
| `key_management.ecdh_kdf/v1` | `z`, `apu`, `apv` byte tags; `algorithm_id` string; `keydatalen` tagged bits (128/256) | `output` byte tag |
| `key_management.agree/v1` | `alg`, `enc`, `recipient` JWK pairs, `recipient_private` JWK pairs/source ref, `ephemeral_private` byte tag, optional `cek` byte tag for +KW, decoded `apu`/`apv` byte tags | `cek`, `encrypted_key` byte tags and `epk` JWK pairs |
| `key.import` | Public material and format | `{"valid":true,"public":{"thumbprint":"<RFC 7638 thumbprint>"}}` |
| `jws.sign`, `jws.verify`, `jwe.decrypt`, `nested.decrypt` | Compact bytes or protected occurrence pairs, keys and pinned policy | Exact compact bytes or verified/decrypted `payload` |
| `web_bot_auth.verify` | Message, injected directory body, trusted origins, explicit clock and policy | Per-label canonical verification facts |
| `discovery.body` | Injected body, source kind/location, limits and evaluation clock | Public key thumbprints |
| `replay.claim` | Namespace/key bytes, created/expires/max-age/skew, clock | Retention end and optional lowercase hexadecimal row |
| `profile.name` | Package/kind pair and bounded metadata | `valid` |

The consumer also accepts `digest.content` and `nested.decrypt`; the current corpus contains no cases for them.

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

## AES-KW source ledger

The `key_management.aes_kw/v1` surface uses RFC 3394 sections 4.1 through 4.6.
Sections 4.1, 4.3, 4.5, and 4.6 assert published wrap and unwrap bytes. Sections
4.2 and 4.4 assert `jose/key.algorithm_mismatch` because their 192-bit KEKs
cannot supply either supported algorithm's exact key width. Primitive key data
may be 192 bits even though JWE content keys are only 128 or 256 bits.

Each new source has `ledger.json` beside its published vectors. Every upstream
item appears exactly once as `{"item":"<id>","case":"<case id>"}` or
`{"item":"<id>","excluded":"<reason>"}`. Consumers reject missing or duplicate
items, rows with neither or both dispositions, missing cases, and empty
exclusions. RFC 3394's ledger points to each wrap case; its `-unwrap` companion
asserts the inverse independently. Bytes retain the existing `b64` tag; no
hexadecimal or numeric encoding is added to manifests.

## ECDH sources and deterministic agreement

The KDF surface reproduces RFC 7518 Appendix C with SHA-256, length-prefixed
AlgorithmID and parties, a 32-bit key length in SuppPubInfo, and empty
SuppPrivInfo. Agreement uses the internal deterministic
`KeyManagement.Agreement` stage with a published or peer-generated ephemeral
private scalar and, for +KW, the independently selected CEK. The adapter also
unwraps the encrypted key under `recipient_private` and the returned public
`epk`, asserting the same CEK. Public `agree/4` uses CSPRNG inputs instead.

RFC 7520 §5.4 decrypts through a real P-384 custody handle. §5.5 and §5.7
reject at JWE because A128CBC-HS256 is outside its content-cipher list; §5.5's
agreement and §5.7's AES-GCMKW primitive stages pass independently. §5.7 is
GCMKW, not RFC 3394 AES-KW. The Wycheproof ledger accounts for every AES-KW,
P-256/P-384 ECDH, and X25519 test at the provenance-pinned commit. Unsupported
192-bit KEKs and valid compressed EC points are explicit exclusions. Strict
ASN.1 rejection choices and zero shared secrets are manifest overrides.

Cross-library fixtures name npm jose 6.2.17 or Erlang jose 1.11.13 and include
only generated public test keys. `scripts/check_jose_libraries.py --generate`
reproduces them using those exact tools; `scripts/import_ecdh_vectors.py`
imports source expectations and updates the inventory and pin. Normal
`scripts/check.py` also makes fresh RequestSeal output and has both independent
libraries decrypt it. Both tools are pinned by content as well as version:
`scripts/jose_libraries/package-lock.json` carries the npm tarball's integrity
and `scripts/jose_libraries/mix.lock` the Hex checksums, so a changed artifact
fails to install. Tool installations live in temporary directories and never
become package runtime dependencies.

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
`rfc9421-signature-bases/1`, `wycheproof-aes-kw/1`, `wycheproof-ecdh/1`,
`wycheproof-x25519/1`, `rfc7748-x25519/1`, `rfc8037-epk/1`, and
`rfc7520-gcmkw/1`. Each has one consumer implementation. The RFC formats
check their published shared secret/public ephemeral key or decrypt the
published GCMKW stage without admitting CBC content encryption.
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
This decrypt-only AES-GCMKW surface selects A128GCMKW/A256GCMKW; it excludes A192GCMKW,
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
including `acceptable` on the older formats, reject with `unexpected_item_shape` and the item ID.

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
Replay is always `not_required` in canonical verification facts; successful required replay is exercised on the `replay.claim` surface (tagged retention end and optional stored row).
Principal is `unattributed` or an object with `agent` (trusted origin), `source` (discovery type) and `thumbprint`.
Authorization is always `not_evaluated`. Web Bot Auth groups those facts by label.
Parameter order is recovered from the actual parsed wire input and checked
against the successful API result; a host map's iteration order is not wire order.

## Format decisions

This reference governs the format. Verification objects use RFC 8785 sorted
keys; semantic arrays remain ordered. Batch counts use `{"int":"..."}` rather
than bare integers. The source origin for public HTTP examples is `local-http`. Deterministic
HTTP signing (HMAC, Ed25519, RSA v1.5) and JWS signing (HS256, EdDSA, RS256)
compare exact output bytes; ECDSA and RSA-PSS use verification only. Positive
key imports include the RFC 7638 public thumbprint. Per-item overrides and separate
non-applicable counts supersede implicit adapter outcomes.

## Publication and vendoring

The `v*` release workflow requires the index release tag
and package version to match the pushed tag, runs the Elixir corpus test against
its pinned index digest, and verifies the inventory, creates a deterministic
`corpus.tar.gz` with fixed timestamp and numeric ownership, and publishes that
asset plus `corpus.sha256` on the tag's GitHub release. The archive root contains exactly `index.json`, `sources/`, and `cases/`;
both consumers refuse other paths in the corpus root. Existing assets are downloaded
and compared byte for byte; a differing digest fails publication without replacement.
Missing assets are uploaded to existing releases. A tag whose package version differs from `elixir_release` fails this workflow and publishes nothing. Corpus assets are attached to every GitHub release of v0.3.0 and later except v0.4.1. The TypeScript package `@request-seal/core` vendors `conformance/` from one
release tag. Its source pin records tag, commit and index SHA-256; updating the
pin and vendored bytes is a reviewed commit. Corpus data stays outside published
runtime packages.
