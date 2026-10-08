# ADR 0008: Separate exact development identity from proven consumer compatibility

- Status: Accepted
- Date: 2026-10-06

## Context

OBSERVED in the scaffold: Elixir 1.20.4 and Erlang/OTP 29.1.1 are exact development pins, with an OTP 29 config assertion. Required developer platforms are macOS and Linux; Windows developers use WSL2 through the Linux path. CI runs on Linux only. OBSERVED in the Hex dependency metadata recorded in the two lockfiles: root ExDoc 0.40.4 requires `earmark_parser ~> 1.4.46`, while the Livebook 0.19.10 Hex release requires `earmark_parser 1.4.44`; the notebook tool also has older exact transitives with advisories requiring inspection. These are separate dependency domains, not a reason to loosen either graph silently.

## Decision

Keep `.tool-versions`, `mix.exs`, the runtime OTP assertion, and Linux CI on one exact development identity: Elixir 1.20.4 / OTP 29.1.1. Update them atomically and purge incompatible build/PLT state when that identity changes.

Declare package consumer floors only after a compatibility matrix actually compiles, tests, installs, and runs the supported public surface on each claimed Elixir/OTP pair. Development stays latest-first; consumer support is evidence, not an inferred range.

Keep `tools/notebooks` as an isolated Mix project pinned to actual Livebook 0.19.10 importer/exporter behavior. It uses current compatible dependency overrides only where resolution, Livebook importer/exporter execution, and advisory review prove the override. It executes exported notebooks in bounded standalone `elixir` children and starts no Livebook web server. Root ExDoc remains in the root graph. Locks, licenses, advisories, package allowlist, and source provenance are verified separately for both graphs.

## Strongest alternatives

1. **One dependency graph.** It simplifies updates and lock handling. The observed `earmark_parser` constraints conflict, so one graph would force a component off its declared contract or block resolution.
2. **Loosen all tool versions to ranges.** More hosts may compile. Builds lose one reproducible development identity and consumer support remains unproved.
3. **Run CI on macOS and Windows too.** It appears to prove portability. Project policy requires Linux-only CI; developer portability is exercised separately on actual macOS/Linux paths, with WSL2 following Linux.
4. **Ignore notebook advisories because tooling is development-only.** It narrows exposure but leaves a parser/execution supply-chain path unexamined. Overrides without actual importer/exporter execution can also break the gate silently.

## Deciding evidence

The exact scaffold pins and incompatible declared parser constraints decide graph isolation. `mix deps.get` alone is insufficient: the tool gate must run Livebook's real importer/exporter, standalone child execution, and deliberate runner red proofs. Advisory entries are opened and adjudicated; a zero exit code alone is not “no findings.”

## Consequences

Two lockfiles and two audit surfaces are maintained. Development identity is unambiguous. Package metadata can eventually support more runtime pairs than development uses, but only with receipts. macOS/Linux setup commands remain the same; exercised-platform claims name the actual run.

## Acceptance

- All exact development pins move in one commit and config compares `to_string(:erlang.system_info(:otp_release))`.
- Linux CI has no macOS/Windows matrix leg; actual macOS and Linux developer receipts use the same documented commands.
- Every claimed consumer pair installs the built package in a clean consumer and runs the selected public acceptance surface.
- Root and notebook graphs resolve independently; their locks, licenses, advisories, and package contents are inspected.
- Livebook 0.19.10 importer/exporter and standalone execution run with chosen overrides; failure/omission tampering turns the gate red.

## Amendment: Library consumer range (October 8, 2026)

This amendment supersedes the root library's exact Elixir requirement and exact
OTP assertion in the Decision and Acceptance sections. Applications keep exact
pins; libraries declare a supported range so they do not block consumers on a
patch version. RequestSeal declares `elixir: "~> 1.18"` and requires OTP 27 or
newer because discovery and JOSE use the OTP `:json` module. The root config
checks that floor instead of requiring OTP 29. The Mix project also requires
`:json` to be available because dependency consumers do not load the library's
config.

The exact development identity remains Elixir 1.20.4 built for OTP 29 and
Erlang/OTP 29.1.1 in `.tool-versions`. Notebook tooling retains its exact Elixir
requirement, OTP assertion, and executable environment checks. Its isolated
dependency graph remains unchanged.

Linux CI declares two lanes: Elixir 1.18.4 / OTP 27.3.4 runs the complete
`mix test --warnings-as-errors` suite, including OpenSSH agent, Node WebCrypto,
and PostgreSQL replay checks; Elixir 1.20.4 / OTP 29.1.1 runs
`python3 scripts/check.py`, including documentation and notebook execution.
Both lanes receive the PostgreSQL service URL. CI actions remain pinned to
immutable commit SHAs. The gate validates the library range, development and
notebook pins, both lane identities, and their commands; mutation tests reject
drift in each channel. Declaring this matrix does not establish a hosted run.

Optional client requirements become `finch >= 0.23.0 and < 0.25.0` and
`req ~> 0.7.4`. They remain optional and do not start client pools. The optional
client check compiles a fresh consumer locked to Finch 0.23.0 and Req 0.7.4 and
runs the client adapter tests against real TCP listeners and an OpenSSH agent.
The separate core consumer check continues to verify operation without HTTP
clients or frameworks installed.
