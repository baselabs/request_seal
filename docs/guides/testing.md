# Testing and evidence

## Run the current gate

Use the Elixir/OTP pairs and Node pin in `.tool-versions`, with OpenSSL and
OpenSSH tools (`ssh-agent`, `ssh-add`, `ssh-keygen`) on `PATH`.
Commands support macOS and Linux; Windows development uses WSL2.
CI runs the full gate on Linux and the Python process-ownership tests on macOS,
including kqueue timeout and closed-descriptor cleanup checks.
```sh
mix deps.get
python3 scripts/check.py
```
Tests use real local cryptography and temporary integration processes; no service starts automatically.
Set `REQUESTSEAL_REPLAY_PG_URL` for database tests. Use `mix test --include live_source`
for live directories; `REQUESTSEAL_DISCOVERY_CACERTS` can select a PEM trust bundle.

## Input properties and measurements

The declared gate includes `test/property/`. Each property executes 300 successful
generated cases with an explicit fixed seed and no elapsed-time cutoff:

```sh
mix test test/property --warnings-as-errors
ASDF_ELIXIR_VERSION="$(awk '$1 == "elixir" {print $NF}' .tool-versions)" ASDF_ERLANG_VERSION="$(awk '$1 == "erlang" {print $NF}' .tool-versions)" MIX_BUILD_ROOT=_build/floor mix test test/property --warnings-as-errors
MIX_ENV=test mix run bench/ceilings.exs
```

The benchmark reports local resource use and OAEP timing; it establishes no conformance claim.
Generated-key measurements and independent published vectors are distinct evidence.
Replay properties race 64 tasks over shared and distinct nonces, checking every stored
claim, exclusive expiry, and reclaimed ETS memory or PostgreSQL storage.
The PostgreSQL property runs when `REQUESTSEAL_REPLAY_PG_URL` is set;
connection, SQL, and contention failures fail without a skip fallback.

## Replay stores

Without `REQUESTSEAL_REPLAY_PG_URL`, the gate excludes database tests; it never starts a database. ETS tests exercise
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
CI supplies a PostgreSQL 18 service URL to every Linux runtime lane, so these tests run in the floor
and mid `mix test` steps and inside the latest lane's declared gate.

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

## What each kind of evidence establishes

Published vectors establish agreement with externally supplied bytes; local generated-key
round trips establish runtime behavior and self-consistency. Independent implementations
establish agreement on selected cases; real integrations establish their byte and lifecycle behavior.
Deployed counterpart exchanges establish acceptance by that peer under its preconditions.
The [RFC Ed25519 notebook](../../livebooks/rfc-ed25519.livemd) checks published RFC 9421
bytes directly with OTP and RequestSeal, including altered-byte rejection.
Other [notebooks](../../livebooks/overview.md) use locally generated keys.
The runner validates Hex install cells before substituting the checkout; registry installation is separate.
Headless assertions establish neither interactive UI behavior nor deployed-peer acceptance.

## JWE lifecycle gates

`python3 -B scripts/mutations.py` verifies 69 distinct reversing patches. It
first requires the selected test to pass on a clean tree, once per distinct
command and baseline commit. Each applied patch must then fail with its named
assertion; reversal must leave a clean tree. Equivalent changed lines are
rejected even when patch headers, context, whitespace, or the location of a
duplicated line within the same function differ. Function names and arities
distinguish edits in different functions.

`python3 -B scripts/jwe_teardown_gate.py --output teardown.json` records absolute
trigger-to-last-end-marker monotonic microseconds against Bounds B(10,000), and
derived K_pf against Bounds K_pf. The constants are 170 ms and 5 ms respectively;
the gate reads them from the library. JSON and Markdown retain each scenario's
maximum as a fraction of B and derived K_pf as a fraction of its bound.

Linux samples require `/proc/loadavg` at most the host's available logical CPUs
(falling back to the main node's online schedulers when unknown), and CPU steal
from `/proc/stat` at most 5% over the sample window. The artifact records the raw
counters, loads, steal percentages, online schedulers, logical CPUs, CPU model
and OTP release. Counter windows span at least 20 ms to avoid zero-tick windows
for short units; the observation delay stays outside every timed unit. A zero
elapsed window is rejected. Final report sends target an observer whose recorded
message queue flag must be `off_heap`.
The Python runner reads `/proc/stat` and `/proc/loadavg` before and after the
Elixir run, retaining those independent brackets. Every per-attempt CPU counter
must be monotonic and lie within those brackets. Python checks load against the
recorded host admission capacity and its own logical CPU count.
Load and steal share 30 host-condition attempts. Placements have
20 attempts; a handoff completed before D is retried. Exhausting either budget
fails, with the observed attempts. No host rejection becomes a skip or a relaxed
runtime bound.

## Web Bot Auth evidence

`test/web_bot_auth_test.exs` checks protocol-00 E.1.1/E.2.1 generic bases and cryptography,
then rejects profile label/lifetime violations; E.1.2/E.2.2 reject legacy fields.
E.2.3 checks directory body and possession proof. Pinned `web-bot-auth@0.2.0` fixtures
exercise independent request signing; OpenSSL checks request and hand-derived directory signatures.
Controlled TLS publishers exercise discovery, possession proof, removal, and cross-directory rejection.
Real ETS claims follow successful single-signature validation; extra selected signatures reject before storage.
Offline KeySets exercise explicit caller trust and do not substitute for network discovery.
Possession proof and caller-approved attribution remain separate.
These tests do not establish request acceptance by a deployed verifier.

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
