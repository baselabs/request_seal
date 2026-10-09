<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Develop RequestSeal


**What you will build:** A local development environment for RequestSeal, with the full verification gate and generated documentation. You will run the same commands on macOS and Linux (or WSL2), then explore the tested APIs and notebooks before making changes.

## Prerequisites

To develop this repository, use Elixir 1.20.4 built for OTP 29, Erlang/OTP 29.1.1,
Python 3.11 or newer, Git, Hex, Node 24.21.0, the OpenSSL command-line tool, and OpenSSH tools (`ssh-agent`,
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
No server, database, container, provider account, or key is needed for the shipped notebooks.
Every subprocess has a bounded deadline; each exported notebook has a 300-second limit
and a 1 MiB output limit. The runner checks nonempty code and complete ordered export,
and the gate executes rejection checks for empty/omitted code, branches, unsupported
cells, import warnings, early exit, failure, deadlines, and output limits. The library
range and OTP floor are checked separately from exact development and notebook pins.
All three CI lanes and immutable action references have drift rejection checks. Failures retain the command and output; no fallback
reports a skipped check as successful.

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

## Install from Hex

In another Elixir project, add `{:request_seal, "~> 0.2.0"}` to your `mix.exs`
dependency list and run `mix deps.get`. The `RequestSeal.Message` module documentation contains executable request construction
and validation examples. `FieldOccurrence` retains exact name/value bytes and section;
`Body` records caller-owned availability without reading streams; `TransportFacts`
records declarations without promoting them to observed connection evidence. Their
constructor and rejection doctests run in the declared gate. `RequestSeal.sign/4`
accepts one signature specification and a caller-owned signer; `RequestSeal.verify/3`
requires an explicit policy and label. `RequestSeal.verify_quorum/3` accepts an
explicit quorum policy. Their module documentation defines the implemented APIs.

Read [the architecture](../design/architecture.md) for implemented contracts and
separately labeled proposed extensions. See [testing and evidence](testing.md)
for the current checks and the proof required for conformance claims.
