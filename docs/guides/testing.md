<!-- Status: current · Kind: guide · Updated: 2026-10-09 · Governed by: public architecture, threat model, and accepted ADRs · Review when: an advertised capability, test runner, or evidence source changes -->

# Testing and evidence


**What you will build:** A verification workflow that distinguishes cryptographic validity, protocol behavior, and acceptance by another implementation. You will run the default gate, choose focused checks for properties and integrations, and identify when a deployed peer or caller-provisioned database is needed to establish a claim.

## Run the current gate

The gate requires Node 24.21.0 and the OpenSSL command-line tool on macOS and
Linux; Windows developers use WSL2. Node is pinned in `.tool-versions` and CI
because the reciprocal JOSE tests run the independent Node WebCrypto peer.
OpenSSL supplies the reciprocal signature checks. Both tools must be on `PATH`.

```sh
mix deps.get
python3 scripts/check.py
```

The gate checks formatting, warnings-as-errors compilation, tests, public-document
inclusion and links, ExDoc output, dependency advisories, and official Livebook
import/export and execution. It runs each notebook in a fresh Elixir process and
requires evidence that the export reached its final assertion. Integration tests start
temporary local HTTP/TLS listeners and a real OpenSSH agent; the notebook runner
starts no Livebook web server. Tests clean up their listeners and agent processes.

Default tests use repository fixtures, real local cryptography, and local integration
processes. The SSH custody tests require `ssh-agent`, `ssh-add`, and `ssh-keygen`.
Database and deployed-source checks are opt-in. Public
documentation and notebooks are enumerated explicitly in mix.exs. The document
checker rejects unapproved documents, missing metadata, private targets, machine
paths, and known internal-process prose. This is a bounded disclosure check;
maintainers still review the actual content before approving an inclusion.

## Input properties and measurements

The declared gate includes `test/property/`. Each property executes 300 successful
generated cases with an explicit fixed seed and no elapsed-time cutoff:

| Suite | Properties | Seed |
| --- | ---: | ---: |
| Structured Fields | 4 | 9651 |
| Signature base | 4 | 9421 |
| JOSE | 5 | 7516 |
| Discovery | 3 | 7638 |
| ETS replay | 1 | 6401 |
| PostgreSQL replay | 1 | 6402 |

```sh
mix test test/property --warnings-as-errors
ASDF_ELIXIR_VERSION=1.18.4-otp-27 ASDF_ERLANG_VERSION=27.3.4 MIX_BUILD_ROOT=_build/floor mix test test/property --warnings-as-errors
MIX_ENV=test mix run bench/ceilings.exs
```

The benchmark is an explicit command, outside the default gate. It reports
nearest-rank p50/p99 time and reductions at input ceilings, plus 1,000 decrypt
samples per OAEP outcome. Measurement method, environment, distributions, and
interpretation appear in the [threat model](../design/threat-model.md).
Generated local keys establish implementation behavior; published vectors remain
separate conformance evidence. Replay properties release 64 tasks together for
both shared and distinct nonce storms. They check every stored claim, exclusive
expiry, and bounded ETS memory or PostgreSQL storage after reclamation. The
PostgreSQL property is included whenever `REQUESTSEAL_REPLAY_PG_URL` is set;
connection, SQL, or contention failures fail the property without a skip fallback.

## Replay stores

The default gate excludes database tests and starts no database. ETS tests exercise
64 concurrent claims, exact capacity, cancellation, outages, retention, and the
published RFC 9421 B.2.1 signature. Required replay never invokes commitment on
invalid cryptography, unknown keys, expired input, or mismatched body content.

For a caller-provisioned PostgreSQL 18 database, set its URL and run:

```sh
REQUESTSEAL_REPLAY_PG_URL="$REPLAY_DATABASE_URL" mix test test/replay_postgres_test.exs test/replay_test.exs
```

The `:postgres` tag is excluded unless `REQUESTSEAL_REPLAY_PG_URL` is set. These
checks create and drop their own tables, race 64 tasks across two independent
pools and one additional claim on an OTP peer node, block a primary key in a real
transaction, terminate a backend over SQL, and drop a table. The caller must
allow these operations on a disposable database. No container is started by tests.
CI runs this database check separately from the offline default gate.

To run the optional server restart persistence test, also supply a command that
restarts the PostgreSQL server process while preserving its data directory. The command must
use a fast shutdown (for example `kill -INT 1` against a containerized server
whose restart policy restarts it): PostgreSQL's default smart shutdown (`SIGTERM`)
waits for every open session, so the test's own pools would keep the server
half-stopped and no fresh connection would ever succeed:

```sh
REQUESTSEAL_REPLAY_PG_URL="$REPLAY_DATABASE_URL" \
REQUESTSEAL_REPLAY_PG_RESTART_CMD="$REPLAY_DATABASE_RESTART_CMD" \
mix test test/replay_postgres_test.exs
```

The `:postgres_restart` tag is excluded unless both variables are set. The test
executes the supplied command with `System.cmd("sh", ["-c", cmd])` and requires
exit status zero. It then polls every second for up to 120 seconds, checking
both the original pools and a fresh connection. Original pools must return a
duplicate or a bounded, nonretryable store error, never a new claim for the
existing commitment. After recovery, it checks the duplicate store result and
the commit path's `:replayed` rejection, then claims a new commitment.
Use a disposable database whose server may be restarted; the command must keep
the existing data directory and return only after initiating the restart.
This optional test must be executed before claiming server restart persistence.

`Replay.ETS` loses claims when its owner stops; it is local and not durable.
`Replay.Postgres` relies on the caller's database persistence. Connection replacement
preserves rows. Server/storage restart survival is a separate deployment check.
Explicit sweeps use a trusted Unix-second clock consistent with verifier clocks;
when verifying published historical vectors, use matching historical sweep times.
Multi-node operators sweep at `now - max_internode_skew` to preserve claims while
any verifier still accepts the authenticated input.
One namespace should use one freshness bound because duplicates never extend retention.
Retention ends at the first rejected second, keeping the last accepted second intact.
Neither claims nor background timers evict rows.

## HTTP capture evidence

The message tests round-trip saved HTTP/1.1 request/response bytes captured over verified
TLS from the HTTP Working Group
[public RFC source](https://raw.githubusercontent.com/httpwg/http-core/main/rfc9112.xml).
The fixture manifest records capture method, timestamp, and SHA-256 hashes. Tests also
exercise RFC 9421 target forms, ordered repeated fields, invalid representation, stream
ownership, and declaration boundaries. These are value-model checks; framework adapter
and signature conformance remain separate acceptance.

## What each kind of evidence establishes

| Evidence | Establishes |
|---|---|
| Primary-source trace | A behavior is associated with the relevant external rule. |
| Independent published vector | Agreement with the exact externally supplied bytes. |
| Local primitive or generated-key round trip | Actual runtime behavior and local self-consistency. |
| Independent implementation | Agreement with that implementation on the selected cases. |
| Real framework, store, network, or custodian | The named integration's observed byte and lifecycle behavior. |
| Deployed counterpart exchange | Acceptance or rejection by that exact peer under its stated preconditions. |
| Headless notebook execution | The selected code assertions completed; interactive UI behavior is separate. |

The [RFC Ed25519 notebook](../../livebooks/rfc-ed25519.livemd) checks OTP against
independently published signature bytes and rejects altered path/signature bytes.
The [environment notebook](../../livebooks/environment.livemd) checks installation
and prerequisites against the real checkout; the runner validates the published
Hex install cell before substituting that checkout. The release runbook checks
registry installation separately. Neither establishes RequestSeal parser, profile, or peer support.

## Web Bot Auth evidence

`test/web_bot_auth_test.exs` separates these proof classes:

| Class | Cases and limits |
|---|---|
| Published vector | Protocol-00 E.1.1 and E.2.1 verify exact generic bases and cryptography, then reject profile label and lifetime violations. E.1.2/E.2.2 reject legacy fields. E.2.3 verifies directory body and possession proof. |
| Independent implementation | Requests produced by pinned `web-bot-auth@0.2.0` cover directory, JWKS URI, CIMD, target URI, digest, RSA, held-key, and nested interactions. Fixtures retain provenance, integrity, license, generator, and checksums. |
| Independent primitive: request | The published E.2.1 Ed25519 request signature is reproduced with OpenSSL. |
| Independent primitive: directory | The OpenSSL-signed hand-derived directory response is verified by RequestSeal; this is separate from the published E.2.3 vector. |
| Real adapter | The controlled TLS directory publisher and caller cache resolve keys, verify possession proof, enforce removal, and reject cross-directory key substitution. |
| Real store | Caller-owned ETS receives one claim after all labels and nested coverage succeed; duplicate nonces, missing nonces, commitment failure, and outage reject. |

The request fixtures establish agreement with the pinned independent signer on
these cases. Caller-trusted offline KeySets establish the explicit trust callback
contract; they do not stand in for a network fetch. Directory proof is a possession
fact, distinct from caller-approved attribution. None of these tests establishes
request acceptance by a deployed verifier; counterpart exchange is separate.

## Add meaningful coverage

Test the complete result and its trust boundaries. A valid signature does not by
itself establish body integrity, trusted identity, freshness, replay protection, or
caller authorization. Negative cases must change meaningful authenticated bytes or
violate a specific policy requirement and assert the resulting stable failure.

Use real runtime types and actual integrations. Keep provider-origin expectations
independent of the implementation under test. Exercise concurrency on the advertised
backend and preserve exact wire occurrences through framework adapters. Prove new
guards reject the mutation they claim to catch; a happy path alone is insufficient.

Conformance claims identify the implementation, selected cases, executed entry point,
source revision, and counterpart assumptions. Incomplete external checks remain
explicit. Public release acceptance also installs the actual built artifact in a
clean consumer and inspects generated documentation and interactive notebook features.

## Notebook runner checks

The declared gate executes real child processes for completion, early-success exit,
runtime failure, deadline, and output-limit checks. The official Livebook importer and
exporter process mutations of the published notebook: empty code, omitted export,
branched sections, unsupported cells, and import warnings must reject. Every nonempty
code cell must occur in order in the export, including repeated cells. Notebook output
is limited to 1 MiB and execution to 300 seconds; timeout/failure cleans up its process
group. These are runner checks, not remote profile acceptance.

The toolchain check validates the library's Elixir range and OTP floor separately
from the exact development and notebook identity in `.tool-versions`. CI declares
floor and middle test lanes and a latest full-gate lane; each channel has a drift rejection check. CI actions use immutable
commits resolved from their official repositories. Dependency audit evidence covers
Hex-reported retirements and advisories; it does not claim every advisory database was
queried independently.

## Conformance corpus

`corpus/` holds unchanged public source bytes and canonical manifests. See the
[format reference](../reference/corpus-format.md) for schemas, evidence classes,
number/byte tags and vendoring rules. `mix test test/corpus_test.exs` verifies the
index pin and every file digest, executes singles and batch items exactly once,
and compares bytes, canonical verification facts and rejection rule IDs.
`MIX_ENV=test mix run scripts/check_corpus_mutations.exs` requires each named
inventory, count and expectation mutation to fail. Both checks run in the declared
gate. The corpus uses injected source bodies and a real caller-owned ETS store;
PostgreSQL integration checks still require the explicit database URL.
