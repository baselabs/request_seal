# RequestSeal contributor and agent contract

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

Publishing, deploying, and pushes to mirrors require owner approval.
Update the CHANGELOG when behavior, a dependency, or a contract changes.

Commands support macOS and Linux; Windows development uses WSL2. CI runs on Linux.
New behavior needs meaningful positive and rejection tests with actual cryptography,
independent published vectors, and authorized real peers. Do not use mocks, fake
services, or generated examples presented as external conformance.
No service is required by the scaffold; no fail-open fallback, implicit authorization, or sensitive telemetry.

## Build and test

This public repository builds and tests only in GitHub-hosted qualification on a
`kci/` ref, never on a developer's machine or the build box. Qualification runs the
covering parts of `python3 scripts/check.py`, and a change reaches the default branch
only through the landing tool. Pure Python source checks that
compile nothing may run locally with `python3 -I -B`. Pure Python unit tests whose
files have been read and do not invoke Mix may run locally with `mix` absent from
`PATH`; compilation-dependent Python tests stay hosted. Only the landing tool watches
a run; sessions do not poll GitHub. Pull requests execute no project code. Use the
exact runtimes from the unchanged shared `scripts/toolchain.sh` reader, called
directly by path, locked dependency fetches, both advisory feeds,
immutable action pins and measured job timeouts. Qualification only restores caches;
the default-branch cache warmer is their sole writer. The separate default-branch
publication and cache-warmer workflows perform only their specified work on hosted
runners; neither decides a landing.

## Documents

Public documentation explains usage, technical contracts, security, and maintenance.
The explicit document list in mix.exs controls ExDoc and package inclusion. Update it
deliberately when adding a public guide or notebook; execute the disclosure checks.
Keep internal work plans, review history, local tooling state, and personal workflow
out of public source, package contents, and generated documentation.
No business material, named customer/prospect/sponsor/champion assessment, pricing,
confidential design detail, machine path, or link into a private path belongs here.

## CI/CD and releases

Follow the CI maintainers' requirements for every product. Send workflow changes to
the CI maintainers with repository, branch and full commit for review before landing.
Land only through the landing tool;
the default-branch ruleset requires the exact `qualified` check with no bypass.
Never use classic branch protection alongside that ruleset.

Sessions never release, publish, tag, dispatch workflows or hold registry keys.
After a qualified version commit lands, send release maintainers the repository, full commit,
version, publication contents and green qualification run. They declare the `publish` environment,
obtain owner approval and dispatch `publish.yml` with `release_commit`. The owner decides first
registry publication.

CI produces the package and docs under the pinned shared Hex action, using the exact files and
requirements in `.github/hex-packages.json`. CI attests both archives, the corpus and the SBOM.
Publication stays cache-free. Performance and teardown run unkeyed on the specified commit
before upload. Only the upload job uses the `publish` environment and only its shared-action
step takes the organization API-read key for the counterpart version check. Public Hex reads
are anonymous. The shared action exchanges and revokes a package-scoped upload token when
needed. No project code runs in that job and no key appears in process arguments.

Read-back uses the same qualification run and manifest digest, requires both served archives to
match the qualified bytes and verifies the product evidence against the published commit.
Release maintainers tag that commit as `baselabs_request_seal-v<version>` and create its GitHub
release from `release-assets`. Existing `v<version>` tags stay valid. No tag starts a workflow.
This library has no deployment workflow. Mirror pushes require owner approval.
