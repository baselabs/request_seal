# Release and maintenance runbook

## Release conditions

Release acceptance exercises advertised public entry points, package bytes,
documentation and required counterparts. Named provider profiles use extension
packages. The native TypeScript counterpart is `@request-seal/core` from
`baselabs/request-seal-typescript`; both use the
[conformance corpus](../reference/corpus-format.md).

Prepare and qualify a version commit before advancing the protected default
branch. Release maintainers obtain owner approval and handle publication,
registry credentials and the later tag. Workflow changes require review before landing.

1. Set `@version` in `mix.exs`. Development snapshots (first pre-release identifier starts
   with `dev`) use `main` source links. Published versions use
   `baselabs_request_seal-v<version>` links. Stable installs use `~> X.Y.Z` before 1.0 and
   `~> MAJOR.MINOR` thereafter. Pre-releases use `~> MAJOR.MINOR.PATCH-<pre-release>`.
   Keep `corpus/index.json`'s `elixir_release` at `v<version>` and update
   `test/support/conformance_pin.ex` when the index digest changes.
2. Stamp `## Unreleased <version>` as `## <version> - YYYY-MM-DD`. The release
   maintainers take the notes from that section of the packaged changelog. Finalize
   versioned HexDocs, source and asset links using the forms below. Confirm the public
   inventory and disclosure checks, including the history and commit messages.
3. Qualify the version commit in one GitHub-hosted run on `kci/<full-sha>`. The
   default-branch ruleset requires the exact `qualified` check without bypass.
   The pinned shared Hex action builds and inspects the package and HTML docs on the
   exact runtime and locked dependencies. It checks the committed archive inventory
   and requirements in `.github/hex-packages.json` and compiles a consumer of the
   unpacked package. Update the declaration with changes to the shipped files or
   requirements. The qualification run keeps the exact archives and manifest for seven
   days. It also verifies documentation, audits both feeds, and attests the archives,
   deterministic corpus and production dependency SBOM. A separate attestation binds
   the CycloneDX SBOM to the package.
4. Give release maintainers the repository, full commit, version, publication contents
   and green run ID. They obtain owner approval and dispatch `publish.yml` from the
   default branch with the full `release_commit`. They can select the exact
   `qualification_run`. Each job checks the dispatch ref and both approved actors. The
   performance verdict and near-cap teardown must pass on the selected release commit
   before upload. Publication uses no runner cache.
5. Upload in environment `publish` reads the original qualified archives, checks the
   exact successful qualification, existing tags, stamped changelog, public registry
   state and counterpart version. Public and organization Hex releases of the same
   OTP application use different versions. A public release takes the next minor
   available on both lines. Public Hex reads are anonymous. Only the shared upload
   action receives the organization API-read key for the counterpart check. It
   exchanges and revokes a package-scoped upload token if an archive needs uploading.
   A missing public package name is an owner decision. Project code runs outside
   this job.
6. The read-back job has no environment and reads public Hex anonymously. It reuses
   upload's qualification run and manifest digest, requires byte equality for both
   served archives and checks the docs' root `release.json` against `release_commit`.
   It verifies the signed provenance of both archives, the corpus and the SBOM, and
   checks the release destinations. It produces `release-assets` with package, served
   docs, `SHA256SUMS`, corpus, corpus checksum and SBOM. Release maintainers compare
   the package against the registry and create `baselabs_request_seal-v<version>` on
   the published commit and its GitHub release. Existing `v<version>` tags remain valid.
   No workflow creates a tag or release and tag pushes start no workflow.

See the [consumer verification guide](../guides/verifying-releases.md) for GitHub
release download and verification. After release, advance `@version`, documented
installs, the corpus release identity and its digest pin.

### Performance gates

The publication workflow runs 24 paired rounds on fresh GitHub-hosted
`ubuntu-24.04` VMs. Download the round artifacts and the verdict from the
dispatch run to inspect the per-round medians, ratios and host conditions.
The [decision record](../adr/0031-performance-release-gates.md) defines the
workloads, admission rule and four thresholds. Failed and unmeasured gates
block publication. Each dispatch collects its fixed set of rounds once. A
separate job measures near-cap JWE teardown against the library bounds and
retains the JSON in the `jwe-teardown` artifact, including on failure.

When both relative gates pass and an absolute gate is the only failure, give
the owner the verdict and round artifacts. The owner decides whether to
change the absolute threshold or approve a dedicated benchmark host. That
decision requires updating the accepted contract and requalifying the
change before publication. Keep the recorded thresholds and do not rerun a
failed measurement to obtain a passing result.

### Finish a held publication

Hex can hold the package and docs for approval. Approve the held release, then dispatch
the default branch with the same `release_commit` and original `qualification_run`
before the version is tagged. Reusing the original run preserves both archives byte
for byte even when independent docs builds embed timestamps. The shared action
preserves matching served archives, refuses retired or differing versions and posts
only missing archives. Read-back succeeds after Hex serves both qualified archives
and the docs name the selected release commit. If the original artifact expires, a
new qualification can resume only when both of its archives match any existing
registry bytes.

The checksum definition follows Hex's
[release API rendering](https://github.com/hexpm/hexpm/blob/main/lib/hexpm_web/views/api/release_view.ex)
and [tarball implementation](https://github.com/hexpm/hex_core/blob/main/src/hex_tarball.erl).
The [repository endpoints](https://github.com/hexpm/specifications/blob/main/endpoints.md)
serve the package and documentation archives used for readback.

Before the tag exists, `scripts/release.py --check-destinations --for-version
<version> --destination-event workflow_dispatch` checks HexDocs and the Hex package
page by real HTTP GET, while future tagged source and raw paths are regular files
in the published commit's HEAD tree. No future tag URL is requested. After maintainers
create the tag, their separately authorized readback can use `--destination-event
push` to request all first-party destinations. That option describes destination
resolution; it does not enable a tag-triggered workflow.

Each real HTTP GET must return 200; redirects fail without being followed. HTTP
404, 5xx, 429 and transport failures retry within a 180-second scheduling budget,
with bounded backoff and `Retry-After`. Other 4xx failures are final. Connection
and body reads refresh their socket timeout to the smaller of 15 seconds and the
remaining budget. Slow bodies stop at the observed deadline. Standard proxy
settings are honored and proxy credentials remain in headers. DNS resolution
is not bounded by Python's socket timeout, and each resolved address can consume
its own connection timeout, so the budget is not a guaranteed wall-clock bound.
Diagnostics retain each destination's last result. The workflow selects pre-tag
resolution explicitly after upload and Hex byte comparison.

## CHANGELOG authoring format

Release sections start in column one with `## <version> - YYYY-MM-DD` or
`## Unreleased <version>`, preceded by a blank line. Versions are semantic versions
and dates must exist. Exactly one dated, nonempty section must match the package
version. Subheadings alone are empty. The authoring check normalizes CRLF to LF
and ignores surrounding blank lines. The release notes come from the packaged
changelog.

Fences start in column one with at least three backticks or tildes. A closing fence
uses the same character, at least as many times, with no info string, also in
column one. Every fence-like line must be an unambiguous opener or closer;
indented fences (including one to three spaces) and list (including task-item) or other container
fences fail even inside an open fence, naming the line. Heading-like
lines inside fences do not create sections. Unclosed fences, backticks in fence
info, indented or container-prefixed fences/release headings, missing blank lines
before release headings, and malformed release headings are errors. HTML comments
in released sections are unsupported. This is a CHANGELOG format, not a general
Markdown parser. Raw HTML tags outside code spans and code blocks in the CHANGELOG
are rejected because they can make release boundaries ambiguous.

Use canonical single-line inline links and images, such as
`[guide](https://request-seal.hexdocs.pm/1.0.0/web-bot-auth.html)` or
`![asset](https://example.com/asset.png)`.
Self-contained reference definitions put the label and literal absolute URL on
the same line. Destinations may be angle-enclosed; optional quoted titles remain
on that line. HTTP(S) and `mailto` URLs are supported. Percent-encode destination
spaces and parentheses; Markdown escapes and HTML entities in destinations are
unsupported. Raw HTML tags, declarations, and processing instructions are
unsupported, even when their attributes contain absolute URLs.

The conservative lexical gate and documentation checker share one destination
extractor and one first-party classifier. The extractor covers inline/image
links, reference definitions, autolinks `<scheme:…>`, bare `http://`, `https://`
and `www.` occurrences, and HTML `href`/`src` attributes. Code spans and code blocks
are ignored: GitHub does not link their contents. Container prose still receives
checks. Relative, empty, fragment-only, query-only,
protocol-relative, unclassifiable, and ambiguous release destinations fail.
Emphasis around links, a following em dash, and link text equal to its own URL
are accepted without changing the authored bytes. Bare destinations end according
to [GFM extended autolinks](https://github.github.com/gfm/#autolinks-extension-):
trailing `? ! . , : * _ ~`, excess closing parentheses and a trailing entity
reference are excluded, and `<` ends the URL. Third-party `www.` prose is accepted.
A bare URL consumes adjacent backticks before they can open a code span. Separate
the URL from code with whitespace, or use an angle-enclosed autolink.

First-party documentation and repository-file URLs in a dated section must use
that section's own version. Unversioned URLs, `main`, stale versions, dot segments,
and every query string fail there. Canonical forms are:

- `https://request-seal.hexdocs.pm/<version>/<page>` (including the index
  `https://request-seal.hexdocs.pm/<version>/`; omitting its final slash redirects
  and is rejected);
- `https://github.com/baselabs/request_seal/blob/baselabs_request_seal-v<version>/<path>`;
- `https://raw.githubusercontent.com/baselabs/request_seal/baselabs_request_seal-v<version>/<path>`;
- `https://github.com/baselabs/request_seal/issues/<number>` and
  `https://github.com/baselabs/request_seal/pull/<number>`, checked live in both modes;
- `https://github.com/baselabs/request_seal/compare/<base-tag>...baselabs_request_seal-v<version>`:
  dispatch verifies that the base tag exists and is an ancestor of HEAD, and
  push checks the URL live;
- `https://hex.pm/packages/request_seal/<version>`: prepublication checks validate
  this package and the version in `mix.exs` without requesting the future page;
  dispatch and push check it live, after Hex publication. Historical versions are
  always checked live.

Historical source links may use their existing `v<version>` tags. Public advisory
permalinks are also checked live. External standards retain their
authored URLs. A HexDocs fragment must name an actual HTML `id` in real ExDoc output
or the published documentation tarball (the destination check reads the real HTTP
page). GitHub source fragments allow only `#L<n>` and `#L<n>-L<m>`, within the checked
file's line count and with a forward range. Blobs rendered as markup, including
Markdown and Livebooks, reject line fragments because GitHub does not select
rendered lines that way. The extension inventory follows
[GitHub Markup's supported formats](https://github.com/github/markup#markups).
Raw assets and other first-party forms
allow no fragment. The same canonical classifier serves the documentation check;
outside dated release notes it also allows current `main` source links, package
and repository landing pages, the Security tab, and canonical unversioned HexDocs
pages, checked against the latest published documentation.

### First-party host class

The class is this repository's or package's content on GitHub and Hex, including
alternate delivery routes. Classification ignores case and recognizes `www.`,
percent-decoded and normalized paths; validation rejects noncanonical host/path
casing, encoding, dot segments, credentials, ports and queries.
Both `request-seal` and `request_seal` in identifying paths are first-party;
paths require the canonical underscore spelling. The hyphenated HexDocs subdomain
remains canonical. Quotes, backticks, non-ASCII characters, and uppercase scheme
or host spellings are rejected with the canonical form.

| Hosts and identifying routes | Outcome |
| --- | --- |
| `request-seal.hexdocs.pm`; legacy `hexdocs.pm/request_seal`; underscore alias `request_seal.hexdocs.pm` | Only the canonical package subdomain and forms above are accepted. |
| `github.com/baselabs/request_seal`; `raw.githubusercontent.com/baselabs/request_seal` | Only the canonical source, raw, issue, pull, compare, advisory and navigation forms above are accepted. |
| `raw.github.com`, `codeload.github.com`, `media.githubusercontent.com`, `api.github.com`, `uploads.github.com`, and other `*.github.com` / `*.githubusercontent.com` paths identifying `baselabs/request_seal` | Rejected with a canonical source or raw alternative; this includes API `/repos/baselabs/request_seal` and archive/LFS routes. |
| `baselabs.github.io/request_seal` | Rejected with the canonical documentation/source alternative. |
| `objects.githubusercontent.com`, `objects-origin.githubusercontent.com`, `github-releases.githubusercontent.com`, `release-assets.githubusercontent.com`, `github-cloud.githubusercontent.com`, `github-cloud.s3.amazonaws.com` | Opaque or temporary asset URLs are rejected conservatively because they cannot establish a stable repository ref. Use the canonical versioned source/raw form. |
| `hex.pm` package and API routes; `diff.hex.pm`; `preview.hex.pm`; `repo.hex.pm` package registry, tarball and docs routes for `request_seal` (including query identifiers) | Only `hex.pm/packages/request_seal/<version>` is accepted in dated notes. Other routes name that canonical alternative. |

This inventory follows GitHub's [repository content API](https://docs.github.com/en/rest/repos/contents),
[runner endpoint inventory](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[legacy raw hostname notice](https://github.blog/news-insights/disabling-old-ip-addresses/),
and [project Pages URL rules](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages),
and Hex's [API and repository endpoints](https://github.com/hexpm/specifications/blob/main/endpoints.md),
[package subdomain migration](https://hex.pm/blog/hexdocs-per-package-subdomains),
and [Hex 2.6 file browser and diff migration](https://hex.pm/blog/hex-v26-released).
The host inventory is an authoring policy; a new delivery host does not silently
become an allowed release form.

### References and diagnostics

Full and collapsed references must have a definition inside the released section.
A definition counts only outside code, at the start of a block: after a blank
line, at the start of the section, immediately after an ATX or setext heading,
or immediately after another link reference definition.
A definition-shaped line in paragraph continuation is rejected with its line.
Definitions inside fences or indented code cannot resolve visible uses.
Multiline titles and backticks in link reference definitions are rejected.
A shortcut reference counts when its label has a definition anywhere in the
CHANGELOG, and also requires that definition inside this section. Full references
have no whitespace between text and label: `[a][b]` needs a definition for `b`.
Whitespace, including a newline, makes `[a] [b]` two shortcut references. Each
resolves independently when defined and otherwise remains literal text, so
undefined `[RFC 9421] [section 2]` is accepted. Labels compare
case-insensitively with whitespace collapsed. Unresolved references name their line.
`[a][b](url)` is accepted only when `b` has no definition anywhere in the
CHANGELOG; otherwise its reference/inline-link precedence is rejected. This
prevents a definition outside the released section from changing its rendering.
GitHub footnotes use `[^label]` and need a unique `[^label]: …` definition in the
same released section; unresolved uses and duplicate definitions fail. A one-line
footnote definition may interrupt a paragraph or follow a table directly. Its
body opens a paragraph: a following reference-shaped line is continuation text,
not a link definition. Multiline footnote bodies, continuations, and nested
blocks in footnote definitions are rejected. Unused link and footnote definitions
are rejected because they do not produce rendered destinations. Labels spanning
lines are rejected as multiline reference labels. Code spans pair equal-length
backtick runs within a paragraph, list-item paragraph, or
heading. A backslash escapes only the first backtick in a run; remaining backticks
can open a span. Unmatched runs remain literal text. Code spans, scheme and email
autolinks, and inline HTML take precedence by starting position. Backtick fences
with backticks in their info string are rejected in every Markdown scan.
Only active, unescaped opening brackets can form links. A successful link
deactivates earlier link openers, and brackets never cross table cells. Literal
closers return their remaining text to the bare-URL scan. Unclosed brackets
suppress extended autolinks until the inline context ends. A `www.` autolink
requires a preceding space, `*`, `_`, `~`, `(`, or the start of its inline context.
An escaped `<` is literal text. An unmatched `<` before a `www.` candidate is
rejected as a literal-angle ambiguity; it does not establish a rendered link.
Uppercase `WWW.` candidates are also rejected. Unmatched angles leave bare
HTTP(S) URLs visible. Simple ASCII email addresses in unmatched angle text
produce `mailto:` destinations; complex email tokens are rejected by name.
Autolink destinations requiring href encoding are rejected by construct name
rather than shortened or rewritten.
Top-level tables parse each cell and row separately, with equally many header
and delimiter cells and at most three spaces before the delimiter. Four spaces
or a tab do not form a table delimiter. Excess body cells, indented code directly
after a table, tables or setext headings in containers, lazy block-quote
continuations, container reference definitions or fences, and indented block-quote
code are rejected with the construct's name. Ordinary list paragraphs, block quotes, top-level
headings, thematic breaks, and top-level fenced and indented code are supported.
Errors name the source line and destination, for example
`CHANGELOG.md:7: destination 'docs/guide.md': requires an absolute HTTP(S) or mailto URL`
or `first-party destination must use version 2.0.0`. Raw HTML and section-format
errors also name the line where available. These are authoring rules, with
intentional over-rejection and no CommonMark conformance claim. Release tooling
never selects destinations or changes Markdown syntax.

The synthetic Markdown reference cases record GitHub's rendered destinations.
To record missing public reference results, run
`python3 -B scripts/record_markdown.py --combinatorial` with an authenticated GitHub
CLI. Ordered construct pairs cover adjacency and overlap, rotating through
paragraphs, lists, block quotes, table cells and footnote definitions. Escape
pairs include every delimiter. Only synthetic samples are submitted. Recording
saves each response, pauses between requests, and checks the shared core rate
limit before starting and between batches. It stops before fewer than 1,500
requests would remain. Rerun the command to resume; recorded samples are skipped.

The documentation gate builds current-version docs once per check with the
project's actual ExDoc into scratch output. `scripts/check.py` owns that build
and passes `--docs-output DIR` to `scripts/check_docs.py`; standalone use builds
its own output. A page exists exactly when it is a
file there, including module pages, `api-reference.html` and extras. Published
versions use the version's documentation tarball fetched and unpacked by the
real Hex client into scratch. A failed fetch is cached per version for the run;
the real Hex API distinguishes "version not published on Hex" from "Hex unreachable."
Historical source document inventory comes from
the shipped Hex package, without evaluating historical project code. Scratch is
removed on success, failure and handled termination. GitHub tagged source paths
use the referenced local tag tree; fetch tags before running the gate. A `main`
URL uses the working tree being checked and current `mix.exs` inventory, even
without a local or remote `main` ref. A current-version source URL uses the
working tree until its tag exists. Current-version documentation links also
retain generated-page and fragment checks during builds. First-party scanning
covers the package `files` and documentation `extras` evaluated from `mix.exs`,
all tracked `livebooks/` and `corpus/` files, tracked Markdown outside `test/` and
`scripts/`, and `.github/` workflows and templates. Newly authored, unignored files
in those categories are checked before staging too. Test/script fixtures and
other nonpublication files are excluded unless explicitly shipped or documented;
binary files are excluded. This uses the same extractor and classifier as release
notes. Markdown bare URLs end at ASCII whitespace or `<`, then lose GFM trailing
punctuation, unbalanced closing parentheses and trailing entity references.

## Dependency updates

Root, `tools/notebooks` and `scripts/jose_libraries` have separate lockfiles and
advisory surfaces. Hosted qualification fetches each with `--check-locked` and
runs both `mix hex.audit` and `mix deps.audit`. Fresh consumers install the
inspected packed archive without a seed lock. Only a separate default-branch
scheduled or dispatched drift report may otherwise resolve fresh; it has no
secret, environment, cache or qualification verdict. An advisory without a fixed
release needs a reasoned `hex: [ignore_advisories: [...]]` project entry.
Security overrides require a reason and real Livebook importer/exporter checks.
Exact cache keys turn over when the toolchain, Mix configuration or lockfile changes.
The default-branch warmer builds and saves new entries for the affected lanes.

## Incident and rollback

First stop use of the affected profile or artifact in caller policy while preserving evidence.
Record affected revisions, algorithms, identity/key scope and actual exposure. Coordinate a
patched release and necessary key revocation/replay-store response. A package retirement does
not erase cached artifacts: publish an advisory and upgrade guidance through verified channels.
Use the registry's documented retirement command only with explicit authority; do not guess
automatic rollback semantics. Changing an installed application's dependency is its owner's act.

## Conformance release assets

Download the GitHub release for `baselabs_request_seal-v<version>` and follow the
[consumer verification guide](../guides/verifying-releases.md). Maintainers create that
release from the publication's `release-assets` artifact after tagging; no
workflow attaches assets. The TypeScript repository pins tag, commit
and index SHA-256 together; its corpus is tooling, excluded from the npm package.
