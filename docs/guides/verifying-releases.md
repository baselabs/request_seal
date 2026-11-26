# Verifying releases

Starting with 2.0, the GitHub release for each `baselabs_request_seal-v<version>` tag carries:

- `request_seal-<version>.tar`: the Hex package, compared byte for byte with Hex
  before the GitHub release is created.
- `request_seal-<version>-docs.tar.gz`: the documentation archive Hex serves,
  downloaded and inspected at publication readback. Its `release.json` names the
  package, version and the commit that built it, which is the tagged commit.
- `corpus.tar.gz`: the deterministic public conformance corpus archive.
- `corpus.sha256`: the SHA-256 checksum of that archive.
- `sbom.cdx.json`: a CycloneDX 1.6 software bill of materials for the package's
  locked production dependency closure, including optional integrations.
- `SHA256SUMS`: the SHA-256 checksums of the package and served docs.

The GitHub release notes come from the version section of the packaged changelog.

The package tarball, docs archive, corpus archive, and SBOM have GitHub build-provenance
attestations. The package tarball also has a CycloneDX SBOM attestation binding
it to the dependency inventory. The qualification run produces and attests these files
on the release commit. The dispatch-only `Publish` workflow runs the near-cap JWE
teardown and paired performance gates on that commit before uploading the original
qualified archives. Read-back compares both served archives byte for byte and checks
that the docs' `release.json` names the release commit. The maintainers tag that
commit and create the GitHub release. An approval retry reuses the original qualification
so both archives keep their original bytes. No workflow runs on a tag.

The 1.0.0 release predates this pipeline: it carries the corpus archive and
checksum under the historical `v1.0.0` tag. It predates package, SBOM and
attestation assets.

## Download and check the corpus

Set `VERSION` to the published version you intend to verify, without the leading
`v`. Run the following commands in the same shell. They require the GitHub CLI,
Mix with Hex, and either GNU `sha256sum` or macOS `shasum`. The temporary directory
and downloads are removed when the shell exits. `SOURCE_COMMIT` is the commit the
release tag names; the attestation checks below require it.

```sh
: "${VERSION:?Set VERSION to the published version to verify}"
assets_dir=$(mktemp -d)
trap 'rm -rf "$assets_dir"' EXIT
TAG="baselabs_request_seal-v$VERSION"
if [ "$VERSION" = 1.0.0 ]; then
  TAG="v$VERSION"
fi
SOURCE_COMMIT=$(gh api "repos/baselabs/request_seal/commits/$TAG" --jq .sha)
gh release view "$TAG" --repo baselabs/request_seal --json assets --jq '.assets[].name'
gh release download "$TAG" --repo baselabs/request_seal --dir "$assets_dir"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$assets_dir" && sha256sum --check corpus.sha256)
else
  (cd "$assets_dir" && shasum -a 256 --check corpus.sha256)
fi
```

For releases with package and docs assets, also check `SHA256SUMS` from the asset directory.
The corpus checksum detects changed bytes; provenance verification below also
checks their attested origin. The archive contains `index.json`, public sources,
and cases described in the [corpus format](../reference/corpus-format.md).

## Verify both attestation types

Check build provenance for all four subjects, and then verify the SBOM predicate
on the package tarball. Keep the predicate URLs exactly as shown:

```sh
for file in "request_seal-$VERSION.tar" "request_seal-$VERSION-docs.tar.gz" corpus.tar.gz sbom.cdx.json; do
  gh attestation verify "$assets_dir/$file" --repo baselabs/request_seal --predicate-type https://slsa.dev/provenance/v1 \
    --signer-workflow baselabs/request_seal/.github/workflows/ci.yml \
    --source-ref "refs/heads/kci/$SOURCE_COMMIT" --source-digest "$SOURCE_COMMIT" --deny-self-hosted-runners
done
gh attestation verify "$assets_dir/request_seal-$VERSION.tar" --repo baselabs/request_seal --predicate-type https://cyclonedx.org/bom \
  --signer-workflow baselabs/request_seal/.github/workflows/ci.yml \
  --source-ref "refs/heads/kci/$SOURCE_COMMIT" --source-digest "$SOURCE_COMMIT" --deny-self-hosted-runners
```

Each command must succeed. These flags require the signer workflow
`baselabs/request_seal/.github/workflows/ci.yml`, the exact qualification branch
as the source ref, the full published commit as source digest, and a GitHub-hosted runner. See GitHub's [attestation verification documentation](https://cli.github.com/manual/gh_attestation_verify)
for the verifier's trust policy and output. These checks establish artifact
origin and the attested dependency inventory; callers still choose which
release and dependencies they trust.

## Compare the package with Hex

Fetch the same version directly from Hex into a separate directory and compare
the complete tarball bytes, using Hex's [package fetch command](https://hexdocs.pm/hex/Mix.Tasks.Hex.Package.html):

```sh
mkdir "$assets_dir/hex"
mix hex.package fetch request_seal "$VERSION" --output "$assets_dir/hex"
cmp "$assets_dir/request_seal-$VERSION.tar" "$assets_dir/hex/request_seal-$VERSION.tar"
```

`cmp` exits successfully only when both package files are byte-identical. The
same comparison is enforced by publication readback after upload. Attestations
bind inspected build bytes; byte comparison separately proves registry identity.
For 1.0.0, the Hex fetch can be exercised, but its release has no package tarball
to compare.

The release's docs archive is the one Hex serves, downloaded at readback. To repeat
that check, fetch Hex's
[documentation tarball endpoint](https://github.com/hexpm/specifications/blob/main/endpoints.md),
compare it with the GitHub release asset and read the commit its `release.json` names:

```sh
curl --fail --location --output "$assets_dir/hex/request_seal-$VERSION-docs.tar.gz" \
  "https://repo.hex.pm/docs/request_seal-$VERSION.tar.gz"
cmp "$assets_dir/request_seal-$VERSION-docs.tar.gz" "$assets_dir/hex/request_seal-$VERSION-docs.tar.gz"
tar -xzOf "$assets_dir/hex/request_seal-$VERSION-docs.tar.gz" release.json
```

The printed commit is the commit tagged `baselabs_request_seal-v<version>`.

## Interpret SBOM scope

`required` means a dependency is reachable through a required production
dependency path. RequestSeal's required dependency is telemetry. `optional`
means it is reachable only through optional integrations, including Ash,
ash_hooks, ash_onetime, Plug, Req, Finch, and Postgrex, or through their required
transitive dependencies. If any required path reaches a shared dependency, its
scope is `required` even when an optional integration also uses it.

The inventory excludes development and test tools. It records the versions
resolved for that release, rather than claiming every consumer installs every
optional integration. Your application's lockfile determines its actual
dependency versions and enabled integrations.
