# Release and maintenance runbook

## Release conditions

Release acceptance exercises advertised public entry points, the package artifact,
documentation, and required counterparts. Named provider profiles use extension packages.
The native TypeScript counterpart is `@request-seal/core` from `baselabs/request-seal-typescript`;
both repositories use the [conformance corpus](../reference/corpus-format.md).

1. Set the package version and docs `source_ref` (`v<version>`) in `mix.exs`.
   Install requirements use `~> X.Y.Z` before 1.0 and `~> MAJOR.MINOR` thereafter.
   Match `corpus/index.json`'s `elixir_release` to the package version; the tag workflow enforces it.
   Update `test/support/conformance_pin.ex` whenever the index digest changes.
   Maintain release and migration guidance in CHANGELOG.md.
   Confirm the explicit public document inventory and supported profiles.
2. Run the release gate and inspect generated docs in a browser separately:
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
5. Publish to Hex. From the pinned Elixir 1.20 checkout, export `HEX_API_KEY` from
   your secret store into the publishing shell only; never write it to a file or
   print it. Verify the security
   reporting channel and package ownership, then run:

   ```sh
   : "${HEX_API_KEY:?Export HEX_API_KEY from your secret store for this command}"
   : "${VERSION:?Set VERSION to the version being published}"
   mix hex.publish --yes
   mix hex.info request_seal "$VERSION"
   curl --fail --location --silent --show-error --output /dev/null "https://hexdocs.pm/request_seal/$VERSION/index.html"
   ```

   Confirm Hex reports that version and
   HexDocs serves the expected guides, with source links pointing at the `v<version>`
   tag (`source_ref` in `mix.exs`). Inspect actual registry checksums and optional
   metadata.
6. Install from Hex in a clean consumer, without a path or Git override. Use an
   empty Mix install directory and verify the installed application version and
   an actual public entry point:

   ```sh
   consumer_dir=$(mktemp -d)
   trap 'rm -rf "$consumer_dir"' EXIT
   MIX_INSTALL_DIR="$consumer_dir" elixir -e '
   Mix.install([{:request_seal, "~> 1.0"}])
   "1.0.0" = Application.spec(:request_seal, :vsn) |> to_string()
   {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
   "GET" = message.method
   IO.puts("PASS: RequestSeal 1.0.0 clean-consumer install and request construction")
   '
   ```

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

Tag the verified release commit as `v<version>` after package checks. A tag must
identify the same contents as the Hex release. The tag workflow verifies
`corpus/index.json` file digests and publishes deterministic `corpus.tar.gz` and
`corpus.sha256` assets. Confirm the workflow succeeded and that
`gh release view v<version>` lists both assets, then verify them against those
digests before vendoring. The TypeScript repository pins tag, commit and index SHA-256 together;
its corpus is repository tooling and excluded from the npm package.
