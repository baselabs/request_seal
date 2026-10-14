<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Develop RequestSeal


**What you will build:** A local development environment for RequestSeal, with the full verification gate and generated documentation. You will run the same commands on macOS and Linux (or WSL2), then explore the tested APIs and notebooks before making changes.

## Prerequisites

To develop this repository, use Elixir 1.20.4 built for OTP 29, Erlang/OTP 29.1.1,
Python 3.12 (the version CI runs), Git, Hex, Node 24.21.0, the OpenSSL command-line tool, and OpenSSH tools (`ssh-agent`,
`ssh-add`, and `ssh-keygen`). Node is required for the
reciprocal JOSE tests against the independent Node WebCrypto peer; OpenSSL runs
reciprocal signature checks. `.tool-versions` records the exact Elixir/OTP and
Node versions. Use a version manager such as asdf
or mise, then confirm `elixir --version` from this checkout. macOS and Linux use the
same commands; Windows developers use a clone inside WSL2's filesystem.
For the supported consumer range, see the [README](../../README.md).

## Run the actual checks

```sh
mix deps.get
python3 scripts/check.py
```

The first run installs the locked documentation dependencies. The isolated notebook project
has its own lockfile because Livebook and ExDoc currently require different parser versions.
No server, container, provider account, or key is needed. PostgreSQL-backed replay tests
run only when `REQUESTSEAL_REPLAY_PG_URL` is set. [Testing and evidence](testing.md)
describes every check the gate runs and what each one proves.

For focused development:

```sh
mix format --check-formatted
mix compile --warnings-as-errors
mix test --warnings-as-errors
mix docs --warnings-as-errors
python3 scripts/check.py --notebooks-only
```

Open `doc/index.html` for the generated documentation. Open the files linked in
[the notebook guide](../../livebooks/README.md) in Livebook for interactive reading.
The headless gate verifies code; it does not certify interactive browser accessibility.

## Use RequestSeal in an application

Follow the [README installation steps](../../README.md#installation). Module
documentation is the API reference; its examples run as doctests in the declared gate.

Read [the architecture](../design/architecture.md) for implemented contracts and
separately labeled proposed extensions. See [testing and evidence](testing.md)
for the current checks and the proof required for conformance claims.
