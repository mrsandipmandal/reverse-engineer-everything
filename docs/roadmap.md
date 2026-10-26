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

- MCP server over stdio.
- Versioned REE-native tool surface.
- `ree doctor` for tool and environment detection.
- Release workflow, GoReleaser configuration, checksums, SBOM, and keyless signing.
- Security policy automation and dependency updates.

Acceptance criteria:

- MCP initialize and tool listing are tested.
- `ree doctor` reports missing tools without failing hard.
- Release workflow is gated by tests and produces verifiable artifacts.
- No analysis tool is exposed before its phase.

## Phase 0c: first release

Scope:

- `v0.0.1` release.
- Repository hardening, branch protection verification, and release notes.
- Post-release verification of downloaded artifacts.

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

Scope:

- Read-only ELF32/ELF64 reader.
- Sections, segments, symbols, relocations, notes, and build metadata.
- Bounds and malformed-input handling.

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
