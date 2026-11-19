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
only through `kimosabe-land --repo . --sha <full sha>`. Pure Python source checks that
compile nothing may run locally with `python3 -I -B`. Pure Python unit tests whose
files have been read and do not invoke Mix may run locally with `mix` absent from
`PATH`; compilation-dependent Python tests stay hosted. Only `kimosabe-land` watches
a run; sessions do not poll GitHub. Pull requests execute no project code. Use the
exact `.tool-versions` runtimes, locked dependency fetches, both advisory feeds,
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

Follow infra's baselabs/docs/ci.md, “What infra requires of every product”
(commit df62d12d320adc85ec5519620e78c1ca9f32f949). Send workflow changes to infra
with repository, branch and full commit for review before landing.
Land only through `kimosabe-land --repo . --sha <full sha>`;
the default-branch ruleset requires the exact `qualified` check with no bypass.
Never use classic branch protection alongside that ruleset.

Sessions never release, publish, tag, dispatch workflows or hold registry keys.
After a qualified version commit lands, send infra the repository, full commit,
version, publication contents and green qualification run. Infra declares the
`publish` environment and secrets through its declaration, obtains owner approval,
dispatches `publish.yml`, reads publication back and tags the published commit.
No tag push starts a workflow. A first registry publication belongs to the owner.
A registry key appears only in the upload step's environment; never put any
secret on a command line or list process arguments. Project code, archive builds
and inspections run without the key. The upload loads no project and only uploads
the missing inspected archives selected by an earlier anonymous Hex API check.
A repeated dispatch may finish an untagged release only when the served package's
outer SHA-256 equals the inspected archive; retired or differing versions refuse.
Existing docs are never uploaded again, and unkeyed readback compares both archives.
Consumer verification files leave publication as one `release-assets` artifact;
infra creates the GitHub release for `v<version>` from it after readback and tagging.
This library has no deploy chart or `argocd/deploy/` path.
Sessions do not publish or deploy. Mirror pushes
require the owner's explicit authorization.
