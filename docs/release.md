# Release process

REE publishes signed, checksummed archives from annotated `v*` tags on `main`. The release workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml); archive, checksum, SBOM, and signing configuration is in [`.goreleaser.yaml`](../.goreleaser.yaml).

## Versioning

- Tags use `vMAJOR.MINOR.PATCH`, for example `v0.0.1`.
- Prereleases use a suffix such as `v0.1.0-rc.1`; GoReleaser marks them as prereleases automatically.
- Before `1.0.0`, a minor release may include breaking changes. Patch releases must not.
- Never move or re-create a published tag. Go module proxies cache versions by tag.

## Before tagging

1. `main` is green and branch protection is satisfied.
2. `CHANGELOG.md` has a dated section for the version and no pending entries that belong to it.
3. `ROADMAP.md` marks the phase complete.
4. The release configuration and a snapshot build pass locally:

   ```bash
   goreleaser check
   goreleaser release --snapshot --clean --skip=sign
   tar -tzf dist/ree_*_linux_amd64.tar.gz
   ```

5. Repository settings are still hardened:

   ```bash
   gh api repos/mrsandipmandal/reverse-engineer-everything/branches/main/protection
   gh api repos/mrsandipmandal/reverse-engineer-everything --jq '{delete_branch_on_merge, security_and_analysis}'
   ```

   Expected: required checks, linear history, admin enforcement, no force pushes or deletions, conversation resolution, and `delete_branch_on_merge: true`. Secret scanning and push protection are enabled. Non-provider patterns and validity checks are enabled when the account supports them; the API accepts the request but keeps them disabled on accounts without that feature.

## Tagging

```bash
git switch main
git pull --ff-only
git tag -a v0.0.1 -m "REE v0.0.1"
git push origin v0.0.1
```

The tag push starts the release workflow. It verifies the module, runs vet and tests with and without the race detector, installs pinned cosign, syft, and GoReleaser, validates the configuration, and publishes the release.

Watch it with:

```bash
gh run watch --repo mrsandipmandal/reverse-engineer-everything
```

## Published artifacts

For each release GoReleaser publishes:

- six archives: linux, darwin, and windows on amd64 and arm64 (tar.gz, zip for Windows);
- `checksums.txt` with SHA-256 digests;
- `checksums.txt.sigstore.json`, a keyless cosign bundle for the checksum file;
- one `.sbom.json` per archive.

Every archive contains the `ree` binary (or `ree.exe`), `LICENSE`, `NOTICE`, `README.md`, and `THIRD_PARTY_NOTICES.md`.

## Version identity

Release archives embed the tag without the leading `v`: tag `v0.0.2` reports version `0.0.2`, the short tag commit, and the build time.

Builds installed with `go install ...@v0.0.2` report the same bare version from Go module metadata, but `commit` and `built` are `unknown` because module builds do not carry VCS metadata. This is expected and is not a release defect.

`ree version`, `ree version --json`, and the MCP `ree_version` tool all use the same identity.

## Post-release verification

Run the verification script against the published tag:

```bash
scripts/verify-release.sh v0.0.1
```

Environment:

- `REE_REPO` overrides the repository, default `mrsandipmandal/reverse-engineer-everything`.
- `REE_KEEP=1` keeps the downloaded artifacts and prints the directory.

Requirements: `gh` (authenticated), `cosign`, `tar`, `python3`, and `unzip` for the Windows archives.

The script checks that:

- the release is published and not a prerelease;
- all six archives, six SBOMs, checksums, and the cosign bundle are present;
- `checksums.txt` verifies every downloaded file;
- the cosign bundle matches the release workflow identity for the tag and the GitHub Actions OIDC issuer;
- archive contents match the expected file set;
- the `linux/amd64` binary reports the release version, tag commit, `linux`, and `amd64`;
- `ree mcp` initializes at protocol version `2025-11-25`, reports server name `ree`, the release version, and names its surface version in the instructions;
- the tool list matches that surface: `ree_version` and `ree_doctor` for `0.1`, plus `ree_analyze` for `0.2` and later;
- for `0.2` and later, `ree_analyze` on the downloaded `linux/amd64` binary returns a summary whose `sha256` and `size` match the file on disk.

Record the result in `docs/releases/<tag>.md` using the checklist:

```markdown
# v0.0.1 verification

- Date:
- Release URL:
- `scripts/verify-release.sh v0.0.1`: pass
- Checksums: pass
- Cosign identity: pass
- Archive contents: pass
- Binary identity: pass
- MCP surface: pass
- Notes:
```

Or run the script through Make:

```bash
make verify-release TAG=v0.0.1
```

### Manual checks

```bash
gh release download v0.0.1 --dir /tmp/ree-v0.0.1
cd /tmp/ree-v0.0.1
sha256sum -c checksums.txt
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/mrsandipmandal/reverse-engineer-everything/.github/workflows/release.yml@refs/tags/v0.0.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

## Rollback

- If the workflow fails before publishing, delete the tag locally and remotely, fix the problem, and tag again:

  ```bash
  git tag -d v0.0.1
  git push origin :refs/tags/v0.0.1
  ```

- If the release is published but unusable, prefer a patch release. To hide it while investigating, edit it back to a draft:

  ```bash
  gh release edit v0.0.1 --draft
  ```

- Do not rewrite a published tag or replace published artifacts. Published versions stay immutable so checksums, signatures, and module checksums remain meaningful.
- For a compromised release, follow [SECURITY.md](../SECURITY.md), withdraw the release, and publish an advisory.
