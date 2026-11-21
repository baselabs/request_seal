# Develop RequestSeal

This guide is for contributors. To use RequestSeal in your application, start with the [README](../../README.md#installation).

Edit RequestSeal source and executable documentation, then qualify the candidate on GitHub-hosted runners. Repository compilation, tests, notebooks, and generated documentation run only in hosted qualification on a `kci/` ref. Application users can run the examples in their own Mix projects.

## Prerequisites

To develop this repository, use the latest Elixir/OTP pair and Node pin from
`.tool-versions`, Python 3.12 (the version CI runs), Git, Hex, the OpenSSL
command-line tool, and OpenSSH tools (`ssh-agent`,
`ssh-add`, and `ssh-keygen`). Node is required for the
reciprocal JOSE tests against the independent Node WebCrypto peer; OpenSSL runs
reciprocal signature checks. `.tool-versions` lists the exact Elixir/OTP pair of every CI
lane, the development default first, and the Node version; Python is not pinned there, and CI uses 3.12. Use a version manager such as asdf
or mise, then confirm `elixir --version` from this checkout. macOS and Linux use the
same commands; Windows developers use a clone inside WSL2's filesystem.
For the supported consumer range, see the [README](../../README.md).

## Run the actual checks

Clone the repository to edit source. Pure Python source checks can run without
compilation:

```sh
python3 -I -B scripts/check_docs.py --source-only
python3 -I -B scripts/check_error_reasons.py
```

Maintainers submit the full candidate commit through the declared landing
process. Hosted qualification runs the covering portions of
`python3 scripts/check.py`, including formatting, compilation, tests, ExDoc,
packed-source notebooks, and disclosure checks, before the default branch
advances. Do not run repository builds or runtime checks on a developer machine.
Pull requests execute no project code. See [Contributing](../../CONTRIBUTING.md).

The [Livebooks](../../livebooks/overview.md) are interactive consumer examples.
Their headless hosted gate checks code assertions against the inspected packed
archive; browser accessibility needs a separate check.

## Use RequestSeal in an application

Follow the [README installation steps](../../README.md#installation) and executable module examples.
The [architecture](../design/architecture.md) defines contracts; [testing and evidence](testing.md) defines conformance evidence.
