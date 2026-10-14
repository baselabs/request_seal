<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture and accepted ADRs · Review when: the disclosure route, release policy, or referenced contract changes -->

# Security and disclosure

RequestSeal signs and verifies HTTP messages and JOSE envelopes. Its security contract,
trust boundaries, and threat responses are in [the threat model](docs/design/threat-model.md).

## Reporting a vulnerability

Never put private keys, tokens, customer payloads, credentials, or exploitable undisclosed
details into public issues, logs, notebooks, or chat transcripts.

This repository does not yet publish a private disclosure route: GitHub private
vulnerability reporting is not enabled and no security contact address is listed. Until
one is documented here, contact the maintainer through an already established private
channel and request secure coordination before sharing sensitive material.

## Supported releases

Releases are published on [Hex](https://hex.pm/packages/request_seal). No supported-release
window or response-time commitment is declared yet; the [changelog](CHANGELOG.md) records
each release.

Release acceptance requires supported-release policy, dependency/advisory checks, patched
artifacts, provenance, coordinated disclosure guidance, and a tested revocation/upgrade
procedure. The [release runbook](docs/operations/releases.md) owns those steps.
