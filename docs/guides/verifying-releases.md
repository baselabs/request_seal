# Verifying releases

Starting with 2.0, each RequestSeal GitHub release carries these assets:

- `request_seal-<version>.tar`: the Hex package, compared byte for byte with Hex
  before GitHub publication.
- `corpus.tar.gz`: the deterministic public conformance corpus archive.
- `corpus.sha256`: the SHA-256 checksum of that archive.
- `sbom.cdx.json`: a CycloneDX 1.6 software bill of materials for the package's
  locked production dependency closure, including optional integrations.

The package tarball, corpus archive, and SBOM have GitHub build-provenance
attestations. The package tarball also has a CycloneDX SBOM attestation binding
it to the dependency inventory. The release notes come from its dated CHANGELOG
section, with documentation links pinned to the release tag. Pre-release tags
create GitHub pre-releases.

The 1.0.0 release predates this pipeline: it carries the corpus archive and
checksum, but no package tarball, SBOM, or attestations. A missing attestation
provides no provenance verification; it is not a successful verification.

## Download and check the corpus

Set `VERSION` to the published version you intend to verify, without the leading
`v`. Run the following commands in the same shell. They require the GitHub CLI,
Mix with Hex, and either GNU `sha256sum` or macOS `shasum`. The temporary directory
and downloads are removed when the shell exits.

```sh
: "${VERSION:?Set VERSION to the published version to verify}"
assets_dir=$(mktemp -d)
trap 'rm -rf "$assets_dir"' EXIT
gh release view "v$VERSION" --repo baselabs/request_seal --json assets --jq '.assets[].name'
gh release download "v$VERSION" --repo baselabs/request_seal --dir "$assets_dir"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$assets_dir" && sha256sum --check corpus.sha256)
else
  (cd "$assets_dir" && shasum -a 256 --check corpus.sha256)
fi
```

The checksum detects changed corpus bytes; provenance verification below also
checks their attested origin. The archive contains `index.json`, public sources,
and cases described in the [corpus format](../reference/corpus-format.md).

## Verify both attestation types

Check build provenance for all three subjects, and then verify the SBOM predicate
on the package tarball. Keep the predicate URLs exactly as shown:

```sh
for file in "request_seal-$VERSION.tar" corpus.tar.gz sbom.cdx.json; do
  gh attestation verify "$assets_dir/$file" --repo baselabs/request_seal --predicate-type https://slsa.dev/provenance/v1
done
gh attestation verify "$assets_dir/request_seal-$VERSION.tar" --repo baselabs/request_seal --predicate-type https://cyclonedx.org/bom
```

Each command must succeed. Inspect the verified signer and workflow identity;
the expected workflow is `.github/workflows/release.yml` in
`baselabs/request_seal`. See GitHub's [attestation verification documentation](https://cli.github.com/manual/gh_attestation_verify)
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
same comparison is enforced before the release pipeline creates attestations.
For 1.0.0, the Hex fetch can be exercised, but there is no GitHub package asset
to compare.

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
