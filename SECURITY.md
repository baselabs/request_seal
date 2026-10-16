<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture · Review when: the disclosure route, release policy, or referenced contract changes -->

# Security and disclosure

RequestSeal signs and verifies HTTP messages and JOSE envelopes. Its security contract,
trust boundaries, and threat responses are in [the threat model](docs/design/threat-model.md).

## Reporting a vulnerability

Never put private keys, tokens, customer payloads, credentials, or exploitable undisclosed
details into public issues, logs, notebooks, or chat transcripts.

Report vulnerabilities privately through GitHub: open the repository's
[Security tab](https://github.com/baselabs/request_seal/security) and choose
"Report a vulnerability," or go directly to
[the private report form](https://github.com/baselabs/request_seal/security/advisories/new).
Only the reporter and the maintainers can see the report. Do not open a public issue
for a vulnerability.

## Supported releases

Releases are published on [Hex](https://hex.pm/packages/request_seal). No supported-release
window or response-time commitment is declared yet; the [changelog](CHANGELOG.md) records
each release.

Release acceptance requires supported-release policy, dependency/advisory checks, patched
artifacts, provenance, coordinated disclosure guidance, and a tested revocation/upgrade
procedure. The [release runbook](docs/operations/releases.md) owns those steps.
