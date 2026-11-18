# Develop RequestSeal

This guide is for contributors. To use RequestSeal in your application, start with the [README](../../README.md#installation).

Contributors edit and inspect source locally. Repository builds and tests run only
in GitHub-hosted qualification on a `kci/` ref, never on a workstation or build box.
Pull requests execute no project code. A maintainer reviews a contribution and
submits the candidate through the landing process; `qualified` must pass before
it reaches the default branch.

## Runtime and checks

`.tool-versions` is the single source for exact Elixir/OTP pairs in the floor,
mid and latest lanes and for Node. Hosted jobs install each pair strictly and
refuse differing installed versions. Python 3.12 runs the gate. Linux jobs use
OpenSSL and OpenSSH tools (`ssh-agent`, `ssh-add`, `ssh-keygen`) for actual peers;
Node runs reciprocal JOSE checks. The full gate runs on Linux, with separate
Python process-ownership coverage on macOS.

The latest qualification lane executes these commands from the repository root:

```sh
mix deps.get --check-locked
python3 scripts/check.py
```

The gate compiles, tests, checks formatting and static analysis, builds documentation,
executes notebooks, audits dependencies through both feeds, and inspects the package.
Floor and mid lanes run the suite on their exact runtimes. The
[testing guide](testing.md) describes each proof and its evidence limits.
Read the [Livebooks](../../livebooks/overview.md) and generated documentation to
explore the APIs; browser accessibility requires a separate inspection.

## Use RequestSeal in an application

Follow the [README installation steps](../../README.md#installation) and executable module examples.
The [architecture](../design/architecture.md) defines contracts; [testing and evidence](testing.md) defines conformance evidence.
