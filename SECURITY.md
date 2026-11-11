<!-- Status: current · Kind: guide · Updated: 2026-11-11 · Governed by: public architecture · Review when: the disclosure route, release policy, or referenced contract changes -->

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

Releases are published on [Hex](https://hex.pm/packages/request_seal); the
[changelog](CHANGELOG.md) records each release.

| Version | Security fixes |
| --- | --- |
| Latest 1.x minor | Yes |
| Earlier 1.x minors | No: upgrade within 1.x, which is compatible by the [compatibility policy](docs/reference/compatibility.md) |
| 0.x | No. 0.x releases affected by a published advisory are retired on Hex with reason `security` |

A fix ships in a new patch or minor release of the latest 1.x line, with its advisory
published on the repository's Security tab and a changelog entry under `Security`. No
response-time commitment is declared. Moving from 0.x to 1.0 requires changing your
dependency requirement (`~> 0.5` never matches 1.0.0); the changelog's 1.0.0 entry lists
what changed.

## Published advisories

| Advisory | Affected | Fixed | Summary |
| --- | --- | --- | --- |
| [GHSA-vj55-78vg-59wf](https://github.com/baselabs/request_seal/security/advisories/GHSA-vj55-78vg-59wf) | 0.1.0 to 0.5.2 | 1.0.0 | Web Bot Auth required replay could accept a captured request again after relabeling, removing or recombining its signatures. Generic `RequestSeal.verify/3` is not affected. 0.1.0 to 0.5.2 are retired on Hex with reason `security`. |

The changelog's [1.0.0 entry](CHANGELOG.md) says who is affected and what to change when upgrading.
