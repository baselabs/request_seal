# Contributing

Open issues and pull requests at [baselabs/request_seal](https://github.com/baselabs/request_seal).
Pull requests execute no project code. A maintainer reviews outside contributions,
then submits the candidate commit through the landing process on a `kci/` ref.
Its hosted qualification must pass before the default branch advances.
Contributions are licensed under Apache-2.0, as section 5 of the [license](LICENSE) describes.
Report vulnerabilities as [SECURITY.md](SECURITY.md) describes, never in a public issue.

Setup commands are in [Develop RequestSeal](docs/guides/getting-started.md).
Applications install from Hex with `{:request_seal, "~> 2.0"}` in their
`mix.exs` dependency list.

Public profiles, corpus cases, notebooks, and integration examples must derive from a
cited public standard or public provider document. Proposals for nonstandard profiles
start as an issue.

Read the normative source and add meaningful positive and rejection tests.
Independent vectors, local round trips, and deployed counterpart acceptance are
distinct evidence classes. Use actual integrations.

Keep the core independent of framework processes and ambient configuration. Preserve
ordered/raw transport information, caller-owned custody, explicit profiles, and safe
results. Document each option and error at its public boundary. Add the corresponding
guide, executable example, notebook, and corpus case as capabilities are implemented.

Run `python3 scripts/check.py` before opening a pull request; qualification runs the same gate, and [testing and evidence](docs/guides/testing.md) covers focused checks.
Conformance claims require independent evidence beyond a local self-round-trip.

The public document list in mix.exs is shared by ExDoc and the Hex package. New public
guides and notebooks require deliberate inclusion. A notebook that needs credentials
must use named secrets, redact its output, and never perform a side effect simply
because a reader opened it. Keep execution plans, private
integration details, local tooling state, credentials, and review transcripts out of
public files. Follow [SECURITY.md](SECURITY.md) for sensitive reports.
