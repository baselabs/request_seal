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

1. Set `@version` in `mix.exs`. Development snapshots (first pre-release identifier
   starts with `dev`) use `main` source links and cannot publish. Other releases
   use `v<version>` source links. Stable installs use `~> X.Y.Z` before 1.0 and
   `~> MAJOR.MINOR` thereafter; pre-releases use `~> MAJOR.MINOR.PATCH-<pre-release>`.
   Match `corpus/index.json`'s `elixir_release` to `v<version>` and update
   `test/support/conformance_pin.ex` when its index digest changes.
2. Stamp `## Unreleased <version>` as `## <version> - YYYY-MM-DD`. Its dated,
   nonempty section becomes `release-notes.md` verbatim. Finalize documentation
   links to `https://request-seal.hexdocs.pm/<version>/<page>` and source/asset
   links to the `v<version>` GitHub blob or raw form below. The shared release
   gate and publishing guard reject invalid notes. Confirm explicit public
   document inventory, supported profiles, package/source disclosure and complete
   history, including deleted content and commit messages, before accepting a cut.
3. Submit the candidate through the protected landing process. The candidate
   qualifies in one GitHub-hosted run on a `kci/` ref. Every runtime lane,
   mutation and teardown proof must pass.
   The final check is `qualified`; the default-branch ruleset requires it without
   bypass. Only the landing process watches the run.
4. Give release maintainers the repository, full commit, version, publication
   contents and green qualification run. They declare the `publish` environment
   and its registry key through the secret declaration and obtain owner approval.
   Publication is only a no-input dispatch of `.github/workflows/publish.yml` on the default
   branch. Every job requires both initiating actors to be approved owners and
   refuses any other ref as its first step. It trusts the default-branch ruleset
   without re-checking `qualified`. A package name absent from Hex is refused;
   first publication is the owner's decision.
5. The unkeyed publication steps install the exact latest `.tool-versions` pair,
   refuse differing installed releases, fetch `--check-locked`, audit both feeds,
   verify the corpus pin and build deterministic corpus assets. They validate
   version, cut notes and absence of the version tag. They build ExDoc and the
   Hex archive, run disclosure and link checks, compare the
   archive's checksum, metadata, explicit inventory and every source byte, and
   build and inspect the docs archive. An anonymous Hex API read then decides
   exactly which archives to upload. No cache is read or written.
6. The same unkeyed steps generate and verify CycloneDX 1.6 against the production
   dependency closure, including optional integrations. `scripts/sbom.py` verifies
   the platform-specific digest of upstream's prebuilt tool before execution.
   SBOM paths are refused, timestamps removed, ordering normalized and a UUIDv5
   serial binds package identity and bytes. Build provenance covers package,
   docs, corpus and SBOM; a second attestation binds the SBOM to the package.
   The job hands those four files, the corpus checksum and `release-notes.md` to
   release maintainers as one workflow artifact named `release-assets`.
7. Only the upload step receives the registry key in its environment. It runs
   `scripts/publish_hex.exs` with `mix run --no-mix-exs --no-start` from a scratch
   directory with no `mix.exs`; it loads no project and uploads only the missing
   inspected archives selected by the preceding unkeyed step. Package upload
   explicitly disables replacement. The key never appears on a command line or
   in another step. If nothing is missing, the keyed step is skipped. Unkeyed
   readback requires a nonretired release with docs, compares both served archives
   byte for byte and checks the first-party destinations in its own release notes.
8. Release maintainers read publication back and create `v<version>` on that exact
   published commit. They compare the package archive in `release-assets` with the
   registry's bytes and create the GitHub release for `v<version>` from that
   artifact. No workflow creates a tag or a release, and a tag push starts no
   workflow. Consumers download from the GitHub release, never the workflow
   artifact, which expires; the
   [consumer verification guide](../guides/verifying-releases.md) covers
   download, attestation and Hex-byte checks. After release, advance
   `@version` to the next development version and update documented installs,
   corpus release identity and its digest pin.

### Finish a held publication

Hex may hold either upload for approval. Approve the held upload, then dispatch
the same default-branch commit again before it is tagged. Each dispatch rebuilds
and inspects the archives without a key, then anonymously reads the public
package inventory and release's `checksum`, `retirement` and `has_docs` fields:

- An absent package name refuses; only the owner makes a first publication.
- An absent version uploads the inspected package and docs without replacement.
- An existing nonretired version must have the same outer SHA-256 as the inspected
  `.tar`. This is Hex's release API `checksum`, distinct from the archive's inner
  `CHECKSUM` member. Differing or malformed state refuses.
- Identical package bytes skip package upload. Missing docs upload alone;
  existing docs skip all uploads. A retired version always refuses.
- Readback must return both inspected archives byte for byte. Held or unavailable
  files keep the run unsuccessful; approve the held files and dispatch again.
  Existing files are never replaced to make readback pass. A tagged version refuses.

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
version. Subheadings alone are empty. Section extraction normalizes CRLF to LF,
removes surrounding blank lines, and adds one terminal newline; all other section
bytes are published unchanged.

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
- `https://github.com/baselabs/request_seal/blob/v<version>/<path>`;
- `https://raw.githubusercontent.com/baselabs/request_seal/v<version>/<path>`;
- `https://github.com/baselabs/request_seal/issues/<number>` and
  `https://github.com/baselabs/request_seal/pull/<number>`, checked live in both modes;
- `https://github.com/baselabs/request_seal/compare/v<base>...v<version>`:
  dispatch verifies that the base tag exists and is an ancestor of HEAD, and
  push checks the URL live;
- `https://hex.pm/packages/request_seal/<version>`: prepublication checks validate
  this package and the version in `mix.exs` without requesting the future page;
  dispatch and push check it live, after Hex publication. Historical versions are
  always checked live.

Public advisory permalinks are also checked live. External standards retain their
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
Rebuild incompatible build artifacts and analysis caches when the toolchain or major dependencies change.

## Incident and rollback

First stop use of the affected profile or artifact in caller policy while preserving evidence.
Record affected revisions, algorithms, identity/key scope and actual exposure. Coordinate a
patched release and necessary key revocation/replay-store response. A package retirement does
not erase cached artifacts: publish an advisory and upgrade guidance through verified channels.
Use the registry's documented retirement command only with explicit authority; do not guess
automatic rollback semantics. Changing an installed application's dependency is its owner's act.

## Conformance release assets

Download the GitHub release for `v<version>` and follow the
[consumer verification guide](../guides/verifying-releases.md). Maintainers create that
release from the publication's `release-assets` artifact after tagging; no
workflow attaches assets. The TypeScript repository pins tag, commit
and index SHA-256 together; its corpus is tooling, excluded from the npm package.
