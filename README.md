# RequestSeal

**Status:** current · **Kind:** guide · **Updated:** 2026-10-08 · **Governed by:** public architecture and accepted ADRs · **Review when:** the public contract or implementation changes

HTTP message signatures and agent authentication for Elixir only.

Package: Hex `request_seal`, Elixir namespace `RequestSeal`.
The TypeScript counterpart and npm package are deferred, not planned for the current release.

The scope covers RFC 9421 HTTP Message Signatures, Structured Fields,
content digests, generic JOSE, and the source-selected Web Bot Auth draft.
Optional Plug/Phoenix, Req/Finch, and Ash integrations are implemented.

**Current checkout:** lossless HTTP message values, Structured Fields, content digests,
signature-base construction, cryptographic primitives, caller-owned key custody, and
generic RFC 9421 `RequestSeal.verify/3`, `RequestSeal.sign/4`, and composite
`RequestSeal.verify_quorum/3`. Single-label verification requires an
explicit `RequestSeal.Policy` and signature label; it reports complete policy facts with
`principal: :unattributed` and `authorization: :not_evaluated`. Signing uses a
caller-owned function. `RequestSeal.Custody` signs exact bytes with opaque local OTP
handles or an explicitly selected OpenSSH agent, and enforces deadlines and caller
cancellation. Module documentation describes the implemented API options, bounds, and
errors. Required replay accepts a caller commitment bound to the verified nonce and
caller namespace, with local ETS or optional Postgrex atomic storage and bounded retention.
Importing the library starts no store or connection. Published RFC vectors exercise these
APIs. Explicit bounded HTTPS discovery supports directories, JWKS, and CIMD with
caller-configured sources and an optional caller-started cache. Optional Req/Finch
adapters sign finalized requests and verify associated responses. `RequestSeal.Ash.scope/2`
maps verified facts through explicit caller actor/tenant bindings to authorization-enabled
Ash scopes. Optional Plug/Phoenix adapters capture retained request bytes, verify
requests, and sign responses. Generic compact JWS/JWE and one-level JWS-in-JWE
nesting and explicit Web Bot Auth protocol-00 signing/verification are implemented.
Named application profiles compose the generic machinery through the unstable
`RequestSeal.Profile` extension surface; pin it exactly. Node WebCrypto is an
independent verifier for tests, not a TypeScript product.

Start with [local development](docs/guides/getting-started.md) and
[the executable notebooks](livebooks/README.md). Read the
[architecture](docs/design/architecture.md), [threat model](docs/design/threat-model.md),
[testing guide](docs/guides/testing.md), and [technical decisions](docs/adr/0001-library-boundary.md)
for the intended contracts and verification method.

## Development

Install the exact versions in `.tool-versions` using your version manager, then run:

```sh
mix deps.get
python3 scripts/check.py
```

The gate builds ExDoc, runs tests, checks the public documentation inventory, and
executes both Livebooks through the official parser and exporter. It fetches the
notebook toolchain's locked dependencies when needed. Dependency resolution and advisory checks use the registry;
registry access can be needed on later runs too. Tests start temporary local HTTP/TLS
listeners and an OpenSSH agent; the notebook runner starts no Livebook web server.
Database and deployed-source tests are opt-in; the default gate requires no database
or external credential.
See [contributing](CONTRIBUTING.md) for the development contract.

## Verification results

`RequestSeal.verify/3` returns one `RequestSeal.Verification` for the selected label.
`RequestSeal.verify_quorum/3` returns `RequestSeal.Quorum.Verification`: `signatures`
is a label-keyed map of the assigned single-label results, `qualifying` records their
slots and caller counting bindings, and `count` counts distinct configured units.
`required` lists required slots; `satisfied` includes assigned optional slots too.
Negotiation checks the verified eligible pool, so a challenge can fulfill
`Accept-Signature` without appearing in the assigned result map. Quorum policies
reject required replay and representation digests; required content digests use
retained message bytes. Caller counting bindings establish no identity attribution.

## Discovery

Construct a trusted `RequestSeal.Discovery.Source` with an explicit HTTPS location
and `:directory`, `:jwks_uri`, or `:cimd` type. `RequestSeal.Discovery.fetch/2`
fetches once; callers start SSL and select trust roots, permitted addresses,
redirect policy, and byte/key/time bounds. No message-supplied key ID selects a URL.
Directory possession proofs are required by default and establish possession,
with principal attribution owned by the selected profile's trust policy.

`RequestSeal.Discovery.resolver/2` connects a fetched KeySet or `{cache, source}`
to a generic policy's key resolver with an explicit algorithm allowlist. Default
key IDs are RFC thumbprints. JWKS/CIMD sources may explicitly use directory-assigned
IDs; thumbprints still govern identity, revocation, and removal. Signed directory
sources require thumbprint IDs. `RequestSeal.Discovery.Cache.start_link/1` starts
only on caller request; refresh, removal, and invalidation are explicit. The cache
never serves an expired snapshot after a failed refresh and has no background timer.
See the discovery modules for freshness, cancellation, and source restrictions.

## Replay

Generic single-label verification selects either `replay: :not_required` or a
required nonce policy with caller `namespace`, `commitment`, `store`, and `timeout`.
Required replay needs bounded freshness. After cryptography, coverage, freshness,
and content checks, the caller commitment receives authenticated facts and returns
1–256 bytes; RequestSeal submits one atomic claim under a shared deadline. It
supplies no application commitment recipe. Duplicate claims, unavailable stores,
and indeterminate timeouts reject authentication.

`RequestSeal.Replay.ETS.start_link/1` creates a caller-owned local store with an
explicit capacity; `store/1` references it. Owner termination loses its claims.
The optional `RequestSeal.Replay.Postgres.store/2` references an existing caller
connection and explicit table; `ddl/1` returns SQL the caller executes. It starts
no database or pool. Persistence follows the caller's database configuration.
Claims never extend retention or evict entries; callers sweep explicitly at the
exclusive retention end using clocks consistent with their verifiers. Web Bot Auth
claims once after every selected signature and nested requirement succeeds.
See [replay-store testing](docs/guides/testing.md#replay-stores) for opt-in database
and restart checks.

## Public contract

The design separates HTTP representation, signature construction, cryptographic
validation, profile requirements, identity trust, body integrity, and replay
enforcement. A valid signature establishes facts about covered bytes; the calling
application decides authorization. See the [glossary](docs/reference/glossary.md)
and [standards reference](docs/reference/standards.md).

Working examples use the actual runtime and distinguish independent vectors from
local round trips and deployed-peer acceptance. Proposed API shapes are labeled.
Published installation instructions will target an actual verified release.

Project code is licensed under [Apache-2.0](LICENSE). Shipped RFC code components carry BSD-3-Clause attribution in [NOTICE](NOTICE). External vectors retain their
[attribution](NOTICE). Read [SECURITY.md](SECURITY.md) before reporting sensitive issues.
