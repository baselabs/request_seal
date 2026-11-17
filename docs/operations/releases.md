# Release and maintenance runbook

## Release conditions

Release acceptance exercises advertised public entry points, the package artifact,
documentation, and required counterparts. Named provider profiles use extension packages.
The native TypeScript counterpart is `@request-seal/core` from `baselabs/request-seal-typescript`;
both repositories use the [conformance corpus](../reference/corpus-format.md).

1. Set `@version` in `mix.exs` to the release version. A pre-release whose first
   identifier starts with `dev` is a development snapshot: its source links use
   `main`, and publishing and release verification refuse it. Other pre-releases
   and stable releases use `v<version>` source links and can be published.
   Pre-release tags create GitHub pre-releases; stable tags create regular releases.
   Snapshot installs select the coming stable line. Stable installs use `~> X.Y.Z`
   before 1.0 and `~> MAJOR.MINOR` thereafter; other pre-releases use
   `~> MAJOR.MINOR.PATCH-<pre-release>` so Elixir matches that pre-release.
   Match `corpus/index.json`'s `elixir_release` to `v<version>`, including `-dev`
   between releases; the gate and release workflow enforce this identity.
   Update `test/support/conformance_pin.ex` whenever the index digest changes.
   In this release commit, rename `## Unreleased <version>` to
   `## <version> - YYYY-MM-DD` (substitute the version and actual release date), and
   finish the release and migration guidance beneath it. This dated, nonempty
   section becomes the GitHub release notes, with relative links pinned to the
   released tag. Both `mix hex.publish` and the release gate reject a missing,
   undated, or empty section before publishing or tagging. Publishing requires
   `python3` for this shared validation.
   Confirm the explicit public document inventory and supported profiles.
2. Use the latest Elixir/OTP pair and Node pin from `.tool-versions`.
   Run the release gate and inspect generated docs in a browser separately:
   ```sh
   python3 scripts/check.py
   ```
3. Build and publish with Elixir 1.20+ so optional integrations appear in Hex metadata:
   ```sh
   mix run --no-start -e 'check = Mix.Project.config()[:aliases][:"hex.publish"] |> hd(); check.([])' && mix hex.build
   ```
   Inspect the artifact against the explicit package file list in `mix.exs`, then delete it.
   `hex_metadata.config` must mark both `ash_onetime` and `ash_hooks` optional.

4. Before publishing, scan the full history of every branch and tag,
   including commit messages. Use a nonempty literal private-term list kept outside
   public source, referenced by `RELEASE_PRIVATE_TERMS_FILE`. Keep scan output local;
   resolve every match before proceeding. Fetch complete history first:

   ```sh
   set -eu
   set -o pipefail
   : "${RELEASE_PRIVATE_TERMS_FILE:?Set the private-term file path}"
   : "${RELEASE_SCAN_DIR:?Set a private output directory outside public source}"
   test -s "$RELEASE_PRIVATE_TERMS_FILE"
   rg --quiet --fixed-strings --ignore-case --file "$RELEASE_PRIVATE_TERMS_FILE" "$RELEASE_PRIVATE_TERMS_FILE"
   if test "$(git rev-parse --is-shallow-repository)" = true; then
     git fetch --unshallow origin
   fi
   git fetch --all --tags
   mkdir -p "$RELEASE_SCAN_DIR"
   git rev-list --all > "$RELEASE_SCAN_DIR/release-history-commits.txt"
   test -s "$RELEASE_SCAN_DIR/release-history-commits.txt"
   : > "$RELEASE_SCAN_DIR/release-history-matches.txt"
   while IFS= read -r revision; do
     if git grep --line-number --ignore-case --fixed-strings --file "$RELEASE_PRIVATE_TERMS_FILE" "$revision" >> "$RELEASE_SCAN_DIR/release-history-matches.txt"; then
       :
     else
       result=$?
       test "$result" -eq 1 || exit "$result"
     fi
   done < "$RELEASE_SCAN_DIR/release-history-commits.txt"
   if git log --all --format='%H %B' | rg --line-number --ignore-case --fixed-strings --file "$RELEASE_PRIVATE_TERMS_FILE" >> "$RELEASE_SCAN_DIR/release-history-matches.txt"; then
     :
   else
     result=$?
     test "$result" -eq 1 || exit "$result"
   fi
   test ! -s "$RELEASE_SCAN_DIR/release-history-matches.txt"
   ```

   This scans all fetched history, including deleted file contents. The term-file
   self-match is the scanner's positive control. An empty result establishes only
   that the configured terms were not found; inspect package/source disclosure too.
5. Publish to Hex. From the latest toolchain selected by `.tool-versions`, export `HEX_API_KEY` from
   your secret store into the publishing shell only; never write it to a file or
   print it. Verify the security
   reporting channel and package ownership, then run:

   ```sh
   : "${HEX_API_KEY:?Export HEX_API_KEY from your secret store for this command}"
   export VERSION=$(python3 scripts/release.py --version)
   mix hex.publish --yes
   mix hex.info request_seal "$VERSION"
   curl --fail --location --silent --show-error --output /dev/null "https://hexdocs.pm/request_seal/$VERSION/index.html"
   ```

   Confirm Hex reports that version and HexDocs serves the expected guides.
   Inspect actual registry checksums and optional metadata. Source-link targets
   are checked after the tag push in step 8.
6. Install from Hex in a clean consumer, without a path or Git override. Use an
   empty Mix install directory and verify the installed application version and
   an actual public entry point:

   ```sh
   export VERSION=$(python3 scripts/release.py --version)
   export REQUIREMENT=$(python3 scripts/release.py --install-requirement)
   consumer_dir=$(mktemp -d)
   trap 'rm -rf "$consumer_dir"' EXIT
   MIX_INSTALL_DIR="$consumer_dir" elixir -e '
   version = System.fetch_env!("VERSION")
   Mix.install([{:request_seal, System.fetch_env!("REQUIREMENT")}])
   ^version = Application.spec(:request_seal, :vsn) |> to_string()
   {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
   "GET" = message.method
   IO.puts("PASS: RequestSeal #{version} clean-consumer install and request construction")
   '
   ```
7. Push the release commit to its branch, then dispatch the `Release` workflow
   (`.github/workflows/release.yml`) on that branch, after the Hex publication above:

   ```sh
   : "${RELEASE_BRANCH:?Set the branch holding the release commit}"
   gh workflow run release.yml --ref "$RELEASE_BRANCH"
   ```

   Confirm the completed run is for that exact commit and passed. Dispatch uses
   read-only repository permissions and produces a workflow artifact for inspection;
   it creates no attestations or release assets. It refuses development snapshots,
   invalid release notes, mismatched corpus identity, or an existing version tag
   pointing at another commit.
   It rebuilds the package and compares it byte for byte with the published Hex
   tarball before attestation or publication of release assets. Inspect the
   SBOM using the scope definitions in the
   [consumer verification guide](../guides/verifying-releases.md).
   `python3 scripts/sbom.py` downloads upstream's prebuilt binary and verifies
   its platform-specific checksum before execution. The version, asset names,
   and digests live in `scripts/sbom.py`. CI's latest lane uses the same entry
   point for development tarballs; only releases compare against Hex.
   Every component, version, and scope is checked against the locked production
   closure, and filesystem paths are rejected. The timestamp is removed,
   ordering is normalized, and a UUIDv5 serial binds the package identity and bytes.
   The artifact also contains `release-notes.md` for the publishing job; that file
   is used as release notes and is not uploaded as a release asset.
8. Only after the dry run passes, push the annotated release tag from that commit:

   ```sh
   git tag -a "v$VERSION" -m "RequestSeal $VERSION"
   git push origin "v$VERSION"
   ```

   After the tag push, confirm HexDocs source links resolve to the `v<version>`
   tag (`source_ref` in `mix.exs`). Confirm the tag's `Release` run passed and its
   title and notes match the version and dated CHANGELOG section.
   Its read-only verification job repeats the dry run, including the Hex byte
   comparison. Only the tag publishing job receives release and attestation write
   permissions. On re-runs it checks existing assets before attestation; only an
   HTTP 404 means the release is absent. Other API failures stop publication.
   Follow the [consumer verification guide](../guides/verifying-releases.md)
   to check the downloaded assets, both attestations, and the Hex package bytes.

   After release, advance `@version` to the next `-dev` version and update
   documented install requirements, the corpus release identity, and its digest pin.

## Dependency updates

Root and `tools/notebooks` have separate lockfiles and advisory surfaces.
Run `mix hex.outdated` and `mix hex.audit` in both projects after dependency changes.
Security overrides require a reason and real Livebook importer/exporter checks.
Rebuild incompatible build artifacts and analysis caches when the toolchain or major dependencies change.

## Incident and rollback

First stop use of the affected profile or artifact in caller policy while preserving evidence.
Record affected revisions, algorithms, identity/key scope and actual exposure. Coordinate a
patched release and necessary key revocation/replay-store response. A package retirement does
not erase cached artifacts: publish an advisory and upgrade guidance through verified channels.
Use the registry's documented retirement command only with explicit authority; do not guess
automatic rollback semantics. Changing an installed application's dependency is its owner's act.

## Conformance release assets

Confirm `gh release view v<version>` lists the assets described in the
[consumer verification guide](../guides/verifying-releases.md), and execute its
checks before accepting a release. Existing assets must be byte-identical;
missing ones are uploaded without replacing others. The TypeScript repository
pins tag, commit and index SHA-256 together; its corpus is repository tooling
and excluded from the npm package.
