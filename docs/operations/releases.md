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
   section becomes the GitHub release notes verbatim. Finalize every documentation
   link to `https://request-seal.hexdocs.pm/<version>/<page>.html` and source or
   asset links to `https://github.com/baselabs/request_seal/blob/v<version>/<path>`
   or `https://raw.githubusercontent.com/baselabs/request_seal/v<version>/<path>`. Unreleased entries may use absolute GitHub `main`
   URLs; replace them when cutting the release. Both `mix hex.publish` and the release gate reject a missing,
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
   ```

   Confirm Hex reports that version and check each versioned page linked by its
   own release notes, not only the documentation landing page:

   ```sh
   python3 scripts/release.py --check-destinations --for-version "$VERSION" --destination-event workflow_dispatch
   ```

   Before the tag exists, this mode checks HexDocs by real HTTP GET and tagged
   source and raw-asset paths as regular files in the checked-out commit's HEAD
   tree. Step 7 checks that same commit, which step 8 will tag. No future GitHub
   tag URL is requested. The prepublication guard validates authored targets
   without requesting future URLs. Inspect registry checksums and optional metadata.
   After the tag push, use `--destination-event push` to GET every first-party
   destination. Each real HTTP GET must return 200; redirects fail immediately
   without following them. HTTP 404, 5xx and transport errors retry with 1, 2, 4,
   8, then at most 10 seconds of backoff, within one 180-second total deadline
   for the check, including request time (at most 15 seconds per request).
   Other statuses do not retry. Failure lists every failing destination and its
   last status or transport error. The workflow selects its mode explicitly by event.
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
   pointing at another commit. HexDocs URLs are checked over HTTP; tagged source
   and raw assets are checked as regular files in that commit's HEAD tree.
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
   is used verbatim as release notes and is not uploaded as a release asset.
8. Only after the dry run passes, push the annotated release tag from that commit:

   ```sh
   git tag -a "v$VERSION" -m "RequestSeal $VERSION"
   git push origin "v$VERSION"
   ```

   After the tag push, confirm HexDocs source links resolve to the `v<version>`
   tag (`source_ref` in `mix.exs`). Confirm the tag's `Release` run passed and its
   title and notes match the version and dated CHANGELOG section.
   Its read-only verification job repeats the dry run, including the Hex byte
   comparison, then checks all first-party destinations by real HTTP, including
   tagged GitHub source and raw assets. Only the tag publishing job receives release and attestation write
   permissions. On re-runs it checks existing assets before attestation; only an
   HTTP 404 means the release is absent. Other API failures stop publication.
   Follow the [consumer verification guide](../guides/verifying-releases.md)
   to check the downloaded assets, both attestations, and the Hex package bytes.

   After release, advance `@version` to the next `-dev` version and update
   documented install requirements, the corpus release identity, and its digest pin.

## CHANGELOG authoring format

Release sections start in column one with `## <version> - YYYY-MM-DD` or
`## Unreleased <version>`, preceded by a blank line. Versions are semantic versions
and dates must exist. Exactly one dated, nonempty section must match the package
version. Subheadings alone are empty. Section extraction normalizes CRLF to LF,
removes surrounding blank lines, and adds one terminal newline; all other section
bytes are published unchanged.

Fences start in column one with at least three backticks or tildes. A closing fence
uses the same character, at least as many times, with no info string, also in
column one. Every fence-like line must be an unambiguous opener or closer;
indented fences (including one to three spaces) and list or other container
fences fail even inside an open fence, naming the line. Heading-like
lines inside fences do not create sections. Unclosed fences, backticks in fence
info, indented or container-prefixed fences/release headings, missing blank lines
before release headings, and malformed release headings are errors. HTML comments
outside fences must fit on one line. This is a CHANGELOG format, not a general
Markdown parser. Raw HTML tags anywhere in the CHANGELOG are rejected because
they can make release boundaries ambiguous.

Use canonical single-line inline links and images, such as
`[guide](https://request-seal.hexdocs.pm/1.0.0/web-bot-auth.html)` or
`![asset](https://example.com/asset.png)`.
Self-contained reference definitions put the label and literal absolute URL on
the same line. Destinations may be angle-enclosed; optional quoted titles remain
on that line. HTTP(S) and `mailto` URLs are supported. Percent-encode destination
spaces and parentheses; Markdown escapes and HTML entities in destinations are
unsupported. Raw HTML tags, declarations, and processing instructions are
unsupported, even when their attributes contain absolute URLs.

The conservative lexical gate examines potential inline/image destinations,
reference definitions, autolinks `<scheme:…>`, bare `http://`, `https://` and
`www.` occurrences, and every `href`/`src` attribute everywhere, including
containers, code examples, and comments. Relative, empty, fragment-only,
query-only, protocol-relative, unclassifiable, and ambiguous destinations fail.
There are no code-block exemptions: rewrite an example to satisfy this contract.
First-party documentation and repository-file URLs must use the section's own
version; unversioned URLs, `main`, stale versions, and dot segments fail. Explicit
public advisory permalinks and external standards retain their authored URLs.
The only canonical forms are
`https://request-seal.hexdocs.pm/<version>/<page>`,
`https://github.com/baselabs/request_seal/blob/v<version>/<path>`, and
`https://raw.githubusercontent.com/baselabs/request_seal/v<version>/<path>`.
Redirecting HexDocs hosts and GitHub raw routes fail the offline gate before Hex
publication. Host, owner and repository classification is case-insensitive and
includes `www.` hosts and normalized paths; first-party links then reject
noncanonical hosts/casing, percent-encoded paths, dot segments, userinfo and ports.
Full and collapsed references must have a definition inside the released section.
A shortcut reference counts when its label has a definition anywhere in the
CHANGELOG, and also requires that definition inside this section. Labels compare
case-insensitively with whitespace collapsed. Unresolved references name their line.
Errors name the source line and destination, for example
`CHANGELOG.md:7: destination 'docs/guide.md': requires an absolute HTTP(S) or mailto URL`
or `first-party destination must use version 2.0.0`. Raw HTML and section-format
errors also name the line where available. These are authoring rules, with
intentional over-rejection and no CommonMark conformance claim. Release tooling
never selects destinations or changes Markdown syntax.

The documentation gate builds current-version docs once per check with the
project's actual ExDoc into scratch output. A page exists exactly when it is a
file there, including module pages, `api-reference.html` and extras. Published
versions use the version's documentation tarball fetched and unpacked by the
real Hex client into scratch. Historical source document inventory comes from
the shipped Hex package, without evaluating historical project code. Scratch is
removed on success, failure and handled termination. GitHub tagged source paths
use the referenced local tag tree; fetch tags before running the gate. A `main`
URL uses the working tree being checked and current `mix.exs` inventory, even
without a local or remote `main` ref. A current-version source URL uses the
working tree until its tag exists. Current-version documentation links also
retain generated-page and fragment checks during builds.

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
