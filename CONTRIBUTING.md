<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public contract or implementation changes -->

# Contributing


Read the [architecture](docs/design/architecture.md),
[threat model](docs/design/threat-model.md), [technical decisions](docs/adr/0001-library-boundary.md),
and [testing guide](docs/guides/testing.md). Setup and commands are in
[Develop RequestSeal](docs/guides/getting-started.md).

Every public profile, corpus case, notebook, and integration example must derive from
a cited public standard or public provider document. Owner clearance is required before
publishing a nonstandard private signing profile, verification-to-authorization composition,
or private retry/recovery, key-purpose, or address-selection mechanism. Public sources
establish protocol requirements; private consumer implementations do not establish them.

Read the normative source for the behavior you change. Add meaningful positive and
rejection tests, observe the expected failure, implement the correction, and run the
affected checks. Independent vectors, local round trips, and deployed counterpart
acceptance are distinct kinds of evidence. Use the actual substrate for integrations.

Keep the core independent of framework processes and ambient configuration. Preserve
ordered/raw transport information, caller-owned custody, explicit profiles, and safe
results. Document each option and error at its public boundary. Add the corresponding
guide, executable example, notebook, and corpus case as capabilities are implemented.

Run the declared gate, `python3 scripts/check.py`, before delivering a change. It checks
formatting, compilation, tests, public documentation, optional clients, dependency
advisories, and shipped notebooks. Run the actual profile,
corpus, and counterpart checks required by the behavior being changed. Record which
checks executed; avoid performance or conformance claims from a local self-round-trip.

Add a substantive ADR when ownership, wire acceptance, compatibility, or trust changes.
Review should challenge unnecessary complexity and lost required behavior. Resolve
findings and inspect the repair diff. Document incomplete external evidence honestly.

The public document list in mix.exs is shared by ExDoc and the Hex package. New public
guides and notebooks require deliberate inclusion. Keep execution plans, private
integration details, local tooling state, credentials, and review transcripts out of
public files. Follow [SECURITY.md](SECURITY.md) for sensitive reports.
