# Security and disclosure

**Status:** current · **Kind:** guide · **Updated:** 2026-10-06 · **Governed by:** public architecture and accepted ADRs · **Review when:** the referenced contract or implementation changes

The current scaffold does not implement authentication. The security contract for the
intended library is in [the threat model](docs/design/threat-model.md).

Never put private keys, tokens, customer payloads, payment data, or exploitable undisclosed
details into public issues, logs, notebooks, or chat transcripts. Before a public release,
the maintainer must configure and verify a private disclosure channel and document its exact
route here. No unverified contact address or remote reporting feature is claimed.

Until that route exists, contact the maintainer through an already established private
channel and request secure coordination before sharing sensitive material. This repository
does not yet declare a supported public release or response-time commitment.

Release acceptance requires supported-release policy, dependency/advisory checks, patched
artifacts, provenance, coordinated disclosure guidance, and a tested revocation/upgrade
procedure. The [release runbook](docs/operations/releases.md) owns those steps.
