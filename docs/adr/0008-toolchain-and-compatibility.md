# 0008 — Separate exact development identity from proven consumer compatibility

## Context

OBSERVED in the scaffold: Elixir 1.20.4 and Erlang/OTP 29.1.1 are exact development pins, with an OTP 29 config assertion. Required developer platforms are macOS and Linux; Windows developers use WSL2 through the Linux path. CI runs the full gate on Linux and Python process-ownership tests on macOS. OBSERVED in the Hex dependency metadata recorded in the two lockfiles: root ExDoc 0.40.4 requires `earmark_parser ~> 1.4.46`, while the Livebook 0.19.10 Hex release requires `earmark_parser 1.4.44`; the notebook tool also has older exact transitives with advisories requiring inspection. These are separate dependency domains, not a reason to loosen either graph silently.

## Decision

The library declares proven consumer compatibility separately from development pins.
Consumers require Elixir `~> 1.18`, OTP 27+, and OTP `:json` availability.
Notebook tooling is an isolated pinned Mix project using real Livebook import/export
and bounded standalone Elixir execution, with no Livebook web server.

## Consequences

Two lockfiles and two audit surfaces are maintained. Development identity is unambiguous. Package metadata can eventually support more runtime pairs than development uses, but only with receipts. macOS/Linux setup commands remain the same; exercised-platform claims name the actual run.

## Acceptance

- Claimed consumer pairs install and execute actual package entry points.
- Root and notebook dependency graphs resolve independently with inspected advisories and packages.
- Real notebook import/export and execution reject failures and omitted cells.

## Runtime and tooling guarantees

The root config checks the OTP floor; Mix checks `:json` because consumers do not load library config.
`.tool-versions` selects exact development and compatibility-test identities;
notebook tooling retains its own exact Elixir/OTP assertions.
macOS and Linux use the same commands; Windows uses WSL2. CI runs the full gate
on Linux and Python process-ownership tests on macOS.
CI actions require immutable commit SHAs.
Public-key encoders try ASN.1 term parameters, then DER where the runtime requires it,
without predicting encoder support from an OTP version string.
PKCS #8 v2 (OneAsymmetricKey) rejects with `:unsupported_format` on supported runtimes.
Finch and Req stay optional and never start caller pools.
`scripts/check_optional_clients.py` reads Mix's evaluated dependency requirements
and tests exact published floors in fresh consumers, using real cryptography,
TCP listeners, an OpenSSH agent, and PostgreSQL.
Core consumer checks run without clients or frameworks installed.
CI derives the floor, mid, and latest runtime lanes and Node pin from `.tool-versions`.
Root and notebook lockfiles retain separate license and advisory checks.
Publishing safety is defined by the runtime guard and actual Hex artifact metadata.

## Optional integrations

ash_onetime and ash_hooks development dependencies require Elixir 1.20+.
Published optional requirements are built on the latest toolchain and remain available to consumers.
Core checks ensure optional bridges do not compile without their dependencies.
Owned integrations exercise real PostgreSQL migrations and Bandit delivery.

## Dependency ranges

Published dependencies declare tested floors independently of the development lock.
Stable ranges use `>= FLOOR and < NEXT_MAJOR.0.0`; existing 0.x ranges and
ash_onetime's `~> 1.9 and >= 1.9.2` retain their shapes.
Fresh consumers resolve every published dependency available on the toolchain at
its exact floor, assert the lock, compile with warnings as errors, and run its
covering tests. The latest lane also tests the ash_onetime and ash_hooks floors.
Development and test dependencies admit the lock and cap below the next major;
0.x development ranges use a pessimistic minor cap. Every lock may advance within
its declared range without changing a consumer floor.
