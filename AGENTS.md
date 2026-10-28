# RequestSeal contributor and agent contract

Read docs/design/architecture.md, docs/design/threat-model.md,
docs/reference/glossary.md, and applicable records under the gitignored
`.kimosabe/adr/` before changing behavior.
Proposed technical contracts do not establish implemented capability.

## Scope and ownership

This is a public framework-independent Elixir library. Do not add an application server,
database, mandatory network fetch, global key store, or payment execution workflow.
Preserve covered wire bytes, caller-owned custody, explicit profiles, and safe results.
Unresolved counterpart encodings require definitive evidence before conformance claims.
Do not copy private products, business plans, customer material, or machine paths here.
Every public profile, corpus case, notebook, and integration example must derive from
a cited public standard or public provider document. Owner clearance is required before
publishing a nonstandard private signing profile, verification-to-authorization composition,
or private retry/recovery, key-purpose, or address-selection mechanism. Public sources
establish protocol requirements; private consumer implementations do not establish them.

## Workflow (owner ruling, October 28, 2026)

Process is sized to the risk of the specific change, never the repository. Each check, gate,
record or review names the failure it prevents.

- **Heavy** when the diff touches signing, verification, signature-base, structured-fields,
  digest, crypto, JOSE, custody, key-identity, replay or Plug acceptance code under
  `lib/request_seal/`, or the conformance corpus under `corpus/`. Write the failing test
  first, get one independent review and do one fix round, and run the declared local gate
  (`python3 scripts/check.py`) once before pushing. Heavy pushes need the owner's approval.
- **Light** for everything else: focused checks on the changed behavior, then push; hosted CI
  is the gate. No outcome record, gauge or review; the commit message is the record. A light
  change the owner asked for lands without a separate push approval.
- Publishing, deploying and pushes to mirrors always need the owner's approval for that action.
- A test that fails on every run is a defect: fix it, or quarantine it with a reason, in the
  change that finds it.
- Update the CHANGELOG when behavior, a dependency or a contract changes; other docs only when
  a contract changes.

## Verification

The same commands must work on macOS and Linux; Windows development uses WSL2. CI runs on
Linux only. Toolchain pins in mix.exs, config/config.exs, .tool-versions and CI move together.
New behavior needs meaningful positive and rejection tests. Use actual cryptography,
independent published vectors, and authorized real peers. Do not introduce mocks,
fake services, or generated examples presented as external conformance.
No service is required by the scaffold.
No fail-open fallback, implicit authorization, or sensitive telemetry.

## Documents

Public documentation explains usage, technical contracts, security, and maintenance.
The explicit document list in mix.exs controls ExDoc and package inclusion. Update it
deliberately when adding a public guide or notebook; execute the disclosure checks.
Keep internal work plans, review history, local tooling state, and personal workflow
out of public source, package contents, and generated documentation.
No business material, named customer/prospect/sponsor/champion assessment, pricing,
confidential design detail, machine path, or link into a private path belongs here.
Non-record Markdown carries Status, Kind, Updated, Governed by, and
Review when metadata. Architectural decision records (in `.kimosabe/adr/`)
and the changelog are records. Release summaries go in
CHANGELOG.md; durable technical decisions go in the gitignored
`.kimosabe/adr/` records. Keep this contract below 200 lines.
