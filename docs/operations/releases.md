<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Release and maintenance runbook


## Release conditions

RequestSeal is Elixir only. The TypeScript counterpart and npm package are deferred,
not planned for the current release. Cross-language parity is outside current release acceptance.

Release acceptance must establish the advertised scope through the actual public entry points,
package artifact, documentation, and required counterpart checks. The current checkout
implements generic RFC 9421 signing, single-label and quorum verification, caller-owned
custody, discovery, nonce replay, optional Req/Finch and Plug/Phoenix adapters, Ash
scope mapping, generic compact JWS/JWE, one-level JWS-in-JWE nesting, and
source-selected Web Bot Auth protocol-00 signing and identity attribution.
Other named application profiles belong in extension packages.

1. Confirm the supported profile/runtime matrix, exact source commit, clean repository state,
   complete changelog, accepted ADRs and migration notes. Preserve old profile identities.
2. Resolve dependencies deliberately, inspect advisories and run root/tooling audits. Record
   reasons for exact tool pins and verify any overrides through their real execution path.
3. Run the full declared gate and all advertised algorithm/profile/adapter/corpus/peer checks.
   Execute each notebook from a clean environment and inspect generated docs in a real browser.
4. Release builds and publishing require Elixir 1.20 or newer. The `hex.publish`
   alias refuses publishing below 1.20 before invoking Hex; older toolchains omit
   the optional integrations from development dependencies. Run the same guard
   before building the release artifact:

   ```sh
   mix run --no-start -e 'check = Mix.Project.config()[:aliases][:"hex.publish"] |> hd(); check.([])' && mix hex.build
   ```

   Inspect `hex_metadata.config` from `mix hex.build --unpack`: both `ash_onetime`
   and `ash_hooks` must be optional requirements. The latest lane builds, checks,
   and deletes an unpacked package under `_build`.

   Inspect the tarball's file allowlist, licenses, public docs,
   corpus, notebook assets, absence of secrets/private paths, and generated application metadata.
5. Install that exact artifact into a clean consumer, exercise actual public entry points,
   and compare source/artifact identities. Run supported Linux compatibility lanes and record
   macOS developer evidence.
6. Verify a private security-reporting channel, release provenance, source links, checksums,
   compatibility/deprecation policy, package ownership, and documented rollback/retirement.
7. Publish the approved artifact with `mix hex.publish`. Confirm the registry's
   actual artifact and documentation, install it, and repeat the promised consumer journey.
8. Update the changelog and public compatibility documentation with the release evidence. Do not label local tests as
   hosted CI, provider acceptance, or registry delivery.

## Dependency updates

The root uses ExDoc for development and tests, SimpleSat for tests, and optional Ash,
Req, Finch, and Postgrex dependencies. Livebook lives in `tools/notebooks` with a
separate lockfile. It pins application dependencies that may need explicit security overrides;
each override has a reason in its Mix file and must pass the real importer/exporter checks.
Review `mix hex.outdated` in both environments and run `mix hex.audit` after any change.
Toolchain or major dependency changes invalidate task-owned build artifacts and analysis caches;
perform one clean rebuild on the final dependency set and preserve evidence.

## Incident and rollback

First stop use of the affected profile or artifact in caller policy while preserving evidence.
Record affected revisions, algorithms, identity/key scope and actual exposure. Coordinate a
patched release and necessary key revocation/replay-store response. A package retirement does
not erase cached artifacts: publish an advisory and upgrade guidance through verified channels.
Use the registry's documented retirement command only with explicit authority; do not guess
automatic rollback semantics. Changing an installed application's dependency is its owner's act.
