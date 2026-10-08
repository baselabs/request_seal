# RequestSeal

**Status:** current · **Kind:** guide · **Updated:** 2026-10-08 · **Governed by:** public architecture and accepted ADRs · **Review when:** the public contract or implementation changes

HTTP message signatures and agent authentication for Elixir.

Package family: Hex `request_seal`, npm `request-seal`, Elixir namespace `RequestSeal`.

The scope covers RFC 9421 HTTP Message Signatures, Structured Fields,
content digests, generic JOSE, and the source-selected Web Bot Auth draft.
The design includes optional
Plug/Phoenix, Req/Finch, and Ash integrations and a native TypeScript counterpart.

**Current checkout:** lossless HTTP message values, Structured Fields, content digests,
signature-base construction, cryptographic primitives, caller-owned key custody, and
generic RFC 9421 `RequestSeal.verify/3`, `RequestSeal.sign/4`, and composite
`RequestSeal.verify_quorum/3`. Single-label verification requires an
explicit `RequestSeal.Policy` and signature label; it reports complete policy facts with
`principal: :unattributed` and `authorization: :not_evaluated`. Signing uses a
caller-owned function. `RequestSeal.Custody` signs exact bytes with opaque local OTP
handles or an explicitly selected OpenSSH agent, and enforces deadlines and caller
cancellation. Module documentation defines every option, default, bound, and safe
error. Required replay accepts a caller commitment bound to the verified nonce and
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
`RequestSeal.Profile` extension surface; pin it exactly. Native TypeScript acceptance
remains separate.

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
registry access can be needed on later runs too. It starts no web server and requires no database or external credential.
See [contributing](CONTRIBUTING.md) for the development contract.

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
