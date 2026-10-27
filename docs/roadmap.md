# Roadmap

Each phase is a separate pull request or small series of pull requests. A phase starts only after its acceptance criteria and tests are defined.

## Phase 0a: foundation

Scope:

- Go module and repository layout.
- `ree version` and `ree help`.
- Build metadata from linker flags and VCS settings.
- CI, CodeQL, dependency review, actionlint.
- Apache-2.0 license and community files.

Acceptance criteria:

- Builds for linux, darwin, and windows on amd64 and arm64.
- `go build`, `go test`, `go test -race`, `go vet`, and `gofmt` pass.
- `golangci-lint` and `govulncheck` pass.
- `ree version` reports name, version, commit, build time, Go version, OS, and architecture.
- `ree version --json` emits stable JSON.
- No network access at runtime.
- No analysis features.
- CI is green.

## Phase 0b: MCP and diagnostics

Scope:

- MCP server over stdio using the official Go SDK.
- Versioned REE-native tool surface with only `ree_version` and `ree_doctor`.
- `ree doctor` for tool and environment detection.
- Release workflow, GoReleaser configuration, checksums, SBOM, and keyless signing.
- Security policy automation and dependency updates.

Acceptance criteria:

- The module uses Go 1.26.10 and MCP SDK `v1.8.0`; CI tests Go 1.26.10 and 1.27.x.
- `ree mcp` serves MCP over stdin/stdout with no arguments and no analysis tools.
- MCP discovery or initialization reports server name `ree`, the build version, and instructions containing surface version `0.1`.
- MCP tool listing returns exactly `ree_version` and `ree_doctor`; both are read-only, closed-world, and non-destructive.
- `ree_version` returns the same identity as `ree version --json`.
- `ree_doctor` returns structured environment diagnostics and reports missing tools without failing the process.
- Required tools are `go` and `git`; optional tools are `make`, `golangci-lint`, `govulncheck`, `actionlint`, `goreleaser`, `cosign`, and `syft`.
- Tool probes use fixed argv, a two-second timeout, and bounded output; they never use a shell.
- Missing or broken optional tools do not set `ok` to false; missing or broken required tools do.
- `ree doctor` and `ree doctor --json` exit 0 when tools are missing, and use exit code 2 only for invalid usage.
- MCP over stdio emits protocol messages on stdout only; diagnostics and failures use stderr.
- Tests cover modern and legacy protocol initialization, exact tool listing, tool annotations, version output, injected doctor diagnostics, CLI dispatch, and help/usage behavior.
- `go test -race ./...`, `go vet ./...`, `gofmt`, `golangci-lint`, `govulncheck`, and `actionlint` pass; `govulncheck` reports no called or required-module vulnerabilities.
- The release workflow runs only for `v*` tags, verifies the module and tests first, and uses least-privilege permissions with `contents: write` and `id-token: write` only for the release job.
- Release actions are pinned to full commit SHAs.
- GoReleaser builds linux, darwin, and windows on amd64 and arm64, creates tar.gz archives except zip for Windows, and publishes checksums.
- Release archives include `LICENSE`, `NOTICE`, `README.md`, and `THIRD_PARTY_NOTICES.md`.
- Release artifacts include SBOMs and a keyless cosign signature bundle for the checksum file.
- `goreleaser check` and a snapshot build are validated locally.
- Documentation records the MCP SDK version, license, protocol support, and dependency decision in an ADR.
- No artifact analysis, external engine execution, runtime observation, or compatibility MCP profile is present.

Out of scope for this phase:

- the `v0.0.1` release and post-release verification;
- external engine detection beyond doctor reporting;
- any tool that reads or analyzes an artifact.

## Phase 0c: first release

Scope:

- `v0.0.1` release.
- Repository hardening, branch protection verification, and release notes.
- Post-release verification of downloaded artifacts.

Acceptance criteria:

- `main` is protected by required CI checks, linear history, no force pushes or deletions, and enforcement for admins; merged branches are deleted automatically.
- `CHANGELOG.md` records `0.0.1` with its release date before tagging, and `ROADMAP.md` marks Phase 0b complete.
- An annotated `v0.0.1` tag exists on `main` and the release workflow succeeds from that tag.
- The GitHub release `v0.0.1` is published, not a draft, and links the changelog.
- The release publishes archives for linux, darwin, and windows on amd64 and arm64, plus `checksums.txt`, `checksums.txt.sigstore.json`, and one SBOM per archive.
- Every archive contains `ree` or `ree.exe`, `LICENSE`, `NOTICE`, `README.md`, and `THIRD_PARTY_NOTICES.md`.
- `checksums.txt` verifies for every downloaded archive and SBOM.
- The cosign bundle verifies against the release workflow identity for the tag and the GitHub Actions OIDC issuer.
- The downloaded `linux/amd64` binary reports version `0.0.1`, the tag commit, `linux`, and `amd64` from `ree version --json`.
- `ree mcp` from the downloaded binary initializes at protocol version `2025-11-25`, reports server name `ree`, version `0.0.1`, and surface instructions containing `0.1`, and lists exactly `ree_version` and `ree_doctor`.
- `scripts/verify-release.sh v0.0.1` performs these checks and exits 0.
- Post-release results are recorded in `docs/releases/v0.0.1.md`.
- `docs/release.md` documents tagging, verification, and rollback.
- No analysis features are added in this phase.

Out of scope for this phase:

- package-manager distribution and installers;
- a documentation site;
- any Phase 1 evidence work.

## Phase 1: evidence core

Scope:

- Evidence schema.
- Canonical JSON (RFC 8785).
- Content addressing.
- Deterministic bundle export and import.
- Schema validation and golden tests.

Acceptance criteria:

- Identical observations produce identical bytes.
- Tampered bundles fail import.
- Missing or partial coverage is explicit.
- Fuzz tests cover decoders.

## Phase 2: ELF

Status: complete. Implemented in PRs #16, #17, #18, and #19 with ADR 0004 to
ADR 0007.

Scope:

- Read-only ELF32/ELF64 reader.
- Sections, segments, symbols, relocations, notes, and build metadata.
- Bounds and malformed-input handling.
- A `ree.payload.elf/1` evidence adapter.

Acceptance criteria:

- ELF32 and ELF64, little- and big-endian, with validated identifiers, file headers, and extended numbering.
- Bounded section and program header tables with explicit truncation and limitation reporting.
- Bounded section names, section and segment contents, notes, GNU build-id, and `.comment` entries.
- Bounded symbol and relocation decoding with per-table provenance, extended section indexes, and explicit versus stored addends.
- A deterministic `ree.payload.elf/1` projection into `ree.evidence/1` with content digests, payload and hashing budgets, and explicit coverage, limitations, and unknowns.
- Crafted fixtures, malformed-input and limit tests, differential symbol checks against `debug/elf` in tests only, and fuzz targets.
- No execution, decompression, mapping, or writing of artifact content, and no production dependency on `debug/elf`.

Out of scope for this phase:

- PE, Mach-O, archives, APK, ASAR, and plist readers;
- DWARF, decompilation, and disassembly;
- symbol versioning, dynamic entries, implicit relocation addends, and compressed section decoding;
- CLI and MCP surfaces, runtime analysis, and a release tag.

## Phase 3: PE

Scope:

- Read-only PE32/PE32+ reader.
- Headers, sections, imports, exports, resources, and certificates.

## Phase 4: Mach-O

Scope:

- Read-only Mach-O and universal binary reader.
- Load commands, segments, symbols, dylibs, and code signing metadata.

## Phase 5: archives and application packages

Scope:

- ZIP, tar, gzip, APK, ASAR, and plist readers.
- Safe extraction and inventory.
- Path traversal, symlink, and archive-bomb defenses.

## Phase 6: analysis surface

Scope:

- Inventory, search, read, compare, and paginated views.
- Evidence-backed findings.
- Session and bundle management.

## Phase 7: external providers

Scope:

- Versioned provider protocol.
- Ghidra adapter first.
- Explicit authorization, isolation, timeouts, and output caps.
- No bundled third-party engines.

## Phase 8: JavaScript and web artifacts

Scope:

- Static JavaScript and web bundle analysis.
- Source-map handling.
- No page execution without explicit authorization.

## Phase 9: runtime analysis

Scope:

- Opt-in runtime observation.
- Strong isolation and authorization.
- Explicit distinction between static and runtime evidence.

## Non-goals for v0.1

- Decompilation.
- Browser, mobile, and runtime analysis.
- Full parity with any other tool.
- Binary patching or live debugging.
- Mandatory external engines.
