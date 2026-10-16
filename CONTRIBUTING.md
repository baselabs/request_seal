<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture · Review when: the public contract or implementation changes -->

# Contributing

Open issues and pull requests at [baselabs/request_seal](https://github.com/baselabs/request_seal).
Contributions are licensed under Apache-2.0, as section 5 of the [license](LICENSE) describes.
Report vulnerabilities as [SECURITY.md](SECURITY.md) describes, never in a public issue.

Read the [architecture](docs/design/architecture.md),
[threat model](docs/design/threat-model.md),
and [testing guide](docs/guides/testing.md). Setup and commands are in
[Develop RequestSeal](docs/guides/getting-started.md). Applications install from Hex
with `{:request_seal, "~> 0.5.1"}` in their `mix.exs` dependency list.

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

Run the declared gate, `python3 scripts/check.py`, before delivering a change;
[testing and evidence](docs/guides/testing.md) lists what it checks. Run the actual profile,
corpus, and counterpart checks required by the behavior being changed. Record which
checks executed; avoid performance or conformance claims from a local self-round-trip.

Record a substantive architectural decision when ownership, wire acceptance, compatibility, or trust changes.
Review should challenge unnecessary complexity and lost required behavior. Resolve
findings and inspect the repair diff. Document incomplete external evidence honestly.

The public document list in mix.exs is shared by ExDoc and the Hex package. New public
guides and notebooks require deliberate inclusion. A notebook that needs credentials
must use named secrets, redact its output, and never perform a side effect simply
because a reader opened it. Keep execution plans, private
integration details, local tooling state, credentials, and review transcripts out of
public files. Follow [SECURITY.md](SECURITY.md) for sensitive reports.
