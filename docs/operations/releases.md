<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Release and maintenance runbook


## Release conditions

The TypeScript implementation is published on npm as `@request-seal/core` from
`baselabs/request-seal-typescript`. Both repositories use the
[conformance corpus](../reference/corpus-format.md).

Release acceptance must establish the advertised scope through the actual public entry points,
package artifact, documentation, and required counterpart checks. The current checkout
implements generic RFC 9421 signing, single-label and quorum verification, caller-owned
custody, discovery, nonce replay with ETS, ash_onetime, and PostgreSQL stores, optional
Req/Finch and Plug/Phoenix adapters, Ash scope mapping, ash_hooks delivery signing and
ingress verification, generic compact JWS/JWE, one-level JWS-in-JWE nesting, and
source-selected Web Bot Auth protocol-00 signing and identity attribution.
Other named application profiles belong in extension packages.

1. Set the package version and the docs `source_ref` (`v<version>`) in `mix.exs`, update every install
   string (currently `{:request_seal, "~> 0.5.1"}`; the document check rejects any
   other), and set `elixir_release` in `corpus/index.json` to `v<version>`. The
   declared gate fails until `elixir_release` equals `v` plus the `mix.exs`
   version, and the corpus release workflow refuses a tag that differs from it.
   Changing `index.json` changes its digest: update the pin in
   `test/support/conformance_pin.ex` in the same commit. Record the release in
   `CHANGELOG.md` under a `## <version> - Unreleased` heading (currently
   `## 0.5.0 - Unreleased`) and replace `Unreleased` with the release date in
   `YYYY-MM-DD` form when publishing, as in `## 0.4.1 - 2026-10-10`. Documents
   mark behavior that ships in the next release with `From <version> (unreleased)`;
   when publishing, delete every ` (unreleased)` after that version in `docs/`,
   the guides, and `lib/`. The document check fails while a marker names the
   `mix.exs` version or a version other than the pending changelog section.
   Confirm the public document allowlist, supported profiles, and accepted ADRs.
2. Use Elixir 1.20.4 / OTP 29.1.1, the exact development pins. Run focused checks
   while editing, then run the declared gate once on the final source:

   ```sh
   python3 scripts/check.py
   ```

   The gate checks examples, notebooks against the real checkout, generated docs,
   dependency advisories, and optional integration metadata. Local notebook execution
   substitutes the checkout for the validated Hex install cell; it does not prove
   registry delivery. Inspect generated docs in a browser separately.
3. Release builds and publishing require Elixir 1.20 or newer. The `hex.publish`
   alias refuses publishing below 1.20 before invoking Hex; older toolchains omit
   optional integrations from development dependencies. Run the same guard before
   building the release artifact:

   ```sh
   mix run --no-start -e 'check = Mix.Project.config()[:aliases][:"hex.publish"] |> hd(); check.([])' && mix hex.build
   ```

   Inspect `contents.tar.gz` inside `request_seal-<version>.tar`. Its files must be only
   `lib/**/*.ex`, `mix.exs`, and the public documents explicitly allowlisted in
   `mix.exs`, including README, CHANGELOG, LICENSE, and NOTICE. Exclude tests,
   scripts, local credentials, internal records, and key fixtures. Record the list
   locally and delete the inspected tarball. Inspect `hex_metadata.config` from
   `mix hex.build --unpack`: both `ash_onetime` and `ash_hooks` must be optional
   requirements. The latest CI lane checks and deletes its unpacked artifact.
4. Commit the final source and push the release commit. Wait for CI on that exact
   commit to pass all three Linux lanes: floor Elixir 1.18.4 / OTP 27.3.4, mid
   Elixir 1.19.5 / OTP 28.5.0.7, and latest Elixir 1.20.4 / OTP 29.1.1. The floor
   lane checks optional client floors; latest runs the full declared gate and the
   Elixir 1.20 optional integrations.

   ```sh
   git push origin HEAD
   gh run list --workflow ci.yml --commit "$(git rev-parse HEAD)"
   gh run watch RUN_ID --exit-status
   ```

5. Before publishing, scan the full history of every branch and tag,
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
6. Publish to Hex. From the pinned Elixir 1.20 checkout, load `HEX_API_KEY` from
   the project's gitignored `.env`; refer to the key by name and never print its
   value. Verify the security reporting channel and package ownership, then run:

   ```sh
   set -a
   . ./.env
   set +a
   : "${HEX_API_KEY:?Set HEX_API_KEY in the project .env}"
   : "${VERSION:?Set VERSION to the version being published}"
   mix hex.publish --yes
   mix hex.info request_seal "$VERSION"
   curl --fail --location --silent --show-error --output /dev/null "https://hexdocs.pm/request_seal/$VERSION/index.html"
   ```

   Confirm Hex reports that version and
   HexDocs serves the expected guides, with source links pointing at the `v<version>`
   tag (`source_ref` in `mix.exs`). Inspect actual registry checksums and optional
   metadata.
7. Install from Hex in a clean consumer, without a path or Git override. Use an
   empty Mix install directory and verify the installed application version and
   an actual public entry point:

   ```sh
   consumer_dir=$(mktemp -d)
   trap 'rm -rf "$consumer_dir"' EXIT
   MIX_INSTALL_DIR="$consumer_dir" elixir -e '
   Mix.install([{:request_seal, "~> 0.5.1"}])
   "0.5.1" = Application.spec(:request_seal, :vsn) |> to_string()
   {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
   "GET" = message.method
   IO.puts("PASS: RequestSeal 0.5.1 clean-consumer install and request construction")
   '
   ```

   Repeat the documented signing/verifying journey in that consumer. Record the
   exact source commit, CI result, artifact checksum, HexDocs, and clean-consumer
   output locally. Local checks do not establish hosted CI,
   provider acceptance, or registry delivery.

## Dependency updates

The root uses ExDoc for development and tests; SimpleSat, Bandit, Phoenix, and
StreamData for tests; and optional Ash, ash_onetime, ash_hooks, Req, Finch, Plug, and
Postgrex dependencies. Livebook lives in `tools/notebooks` with a
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

## Conformance release assets

Tag the verified release commit as `v<version>` after package checks. A tag must
identify the same contents as the Hex release. The tag workflow verifies
`corpus/index.json` file digests and publishes deterministic `corpus.tar.gz` and
`corpus.sha256` assets. Confirm the workflow succeeded and that
`gh release view v<version>` lists both assets, then verify them against those
digests before vendoring. The TypeScript repository pins tag, commit and index SHA-256 together;
its corpus is repository tooling and excluded from the npm package.
