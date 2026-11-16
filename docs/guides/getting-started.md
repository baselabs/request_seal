# Develop RequestSeal

This guide is for contributors. To use RequestSeal in your application, start with the [README](../../README.md#installation).

**What you will build:** A local development environment for RequestSeal, with the full verification gate and generated documentation. You will run the same commands on macOS and Linux (or WSL2), then explore the tested APIs and notebooks before making changes.

## Prerequisites

To develop this repository, use Elixir 1.20.4 built for OTP 29, Erlang/OTP 29.1.1,
Python 3.12 (the version CI runs), Git, Hex, Node 24.21.0, the OpenSSL command-line tool, and OpenSSH tools (`ssh-agent`,
`ssh-add`, and `ssh-keygen`). Node is required for the
reciprocal JOSE tests against the independent Node WebCrypto peer; OpenSSL runs
reciprocal signature checks. `.tool-versions` lists the exact Elixir/OTP pair of every CI
lane, the development default first, and the Node version; Python is not pinned there, and CI uses 3.12. Use a version manager such as asdf
or mise, then confirm `elixir --version` from this checkout. macOS and Linux use the
same commands; Windows developers use a clone inside WSL2's filesystem.
For the supported consumer range, see the [README](../../README.md).

## Run the actual checks

Clone the repository and run from its root:
```sh
git clone https://github.com/baselabs/request_seal.git
cd request_seal
mix deps.get
python3 scripts/check.py
```
For focused development:

```sh
mix format --check-formatted
mix compile --warnings-as-errors
mix test --warnings-as-errors
mix docs --warnings-as-errors
python3 scripts/check.py --notebooks-only
```

Open `doc/index.html` for generated docs and the [Livebooks](../../livebooks/overview.md) for interactive use.
The headless gate checks code assertions; browser accessibility needs a separate check.

## Use RequestSeal in an application

Follow the [README installation steps](../../README.md#installation) and executable module examples.
The [architecture](../design/architecture.md) defines contracts; [testing and evidence](testing.md) defines conformance evidence.
