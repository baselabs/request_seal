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
