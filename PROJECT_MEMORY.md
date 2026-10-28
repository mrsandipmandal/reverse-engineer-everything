# Project memory

Last updated: 2026-10-28 · Phase 5 closeout, code verified at `67a0b9f` · latest release `v0.0.2`

This file is a short, verified snapshot for continuity. The roadmap, changelog, ADRs, and release records remain authoritative for their own content.

## Current status

- Phase 0a, 0b, 0c, Phase 1 (evidence core), Phase 2 (ELF), Phase 3 (PE), Phase 4 (analysis surface), and Phase 5 (Mach-O) are complete.
- Phase 2 adds `internal/formats/elf` and `internal/providers/elf`; Phase 3 adds `internal/formats/pe` and `internal/providers/pe`; Phase 4 adds `internal/usecase/analyze`, the `ree analyze` command, and the `ree_analyze` MCP tool, raising the MCP surface to `0.2`; Phase 5 adds `internal/formats/macho` and `internal/providers/macho` and wires `builtin.macho` into both analysis surfaces.
- `v0.0.1` and `v0.0.2` are published and verified; no Phase 2, Phase 3, Phase 4, or Phase 5 release was cut.
- `main` is clean and protected; CI, CodeQL, and Actionlint are green on `67a0b9f`.

## Completed milestones

| Phase | Scope | Evidence |
|---|---|---|
| 0a | Go module, `ree version`, CI baseline, open-source files | PR #1, `545207d` |
| 0b | `ree mcp`, `ree_version`, `ree_doctor`, release automation | PR #2, `4b12947` |
| 0c | `v0.0.1` release and repository hardening | PRs #4, #5; release and `docs/releases/v0.0.1.md` |
| 1 | RFC 8785 canonical JSON, `ree.evidence/1`, `ree.bundle/1` | PRs #9, #10, #12; ADR 0003; `docs/evidence.md`, `docs/bundle.md` |
| 2 | Bounded ELF32/ELF64 reader and `ree.payload.elf/1` evidence provider | PRs #16–#19; `680f455`, `81a151b`, `efc014e`, `86a7bbf`; ADR 0004–0007; `docs/payload-elf.md` |
| 3 | Bounded PE32/PE32+ reader and `ree.payload.pe/1` evidence provider | PRs #22–#25; `fe774e0`, `bf4646c`, `e6176e5`, `c070b94`; ADR 0008–0011; `docs/payload-pe.md` |
| 4 | Analysis surface: `internal/usecase/analyze`, `ree analyze`, `ree_analyze`, MCP surface `0.2` | PRs #27–#29; `8b7901d`, `f86823b`, `379f441`; ADR 0012; `docs/analyze.md` |
| 5 | Bounded Mach-O and universal binary reader, `ree.payload.macho/1` provider, Mach-O in both analysis surfaces | PRs #31–#34; `6a163de`, `ba51ee3`, `2b1885e`, `67a0b9f`; ADR 0013–0015; `docs/payload-macho.md` |

## Architecture decisions

- ADR 0001: Go baseline, Apache-2.0, package layout, read-only-first scope.
- ADR 0002: official MCP Go SDK `v1.8.0`, surface `0.1`, protocol range.
- ADR 0003: canonical JSON through `github.com/gowebpki/jcs` `v1.0.2`, SHA-256 content addressing, strict `ree.evidence/1`, deterministic `ree.bundle/1`, and the Phase 1 limits.
- ADR 0004: bounded ELF header and table reader over `io.ReaderAt` plus explicit size; structural defects fail, physical or count truncation yields partial tables with limitations.
- ADR 0005: on-demand ELF content reads, all-or-nothing section and segment data, partially decoded notes, and UTF-8 name and comment rules.
- ADR 0006: ELF symbols and relocations with the null symbol, per-table index spaces, `SHN_XINDEX`, and explicit versus stored addends.
- ADR 0007: `ree.payload.elf/1` evidence projection with decimal-string `uint64` fields, content digests, payload and hashing budgets, and coverage derived from limitations and unknowns.
- ADR 0008: bounded PE32/PE32+ foundation over `io.ReaderAt` plus explicit size, little-endian only, declared versus loaded counts, deterministic RVA mapping, overlay bounds, and `debug/pe` as a test-only oracle.
- ADR 0009: on-demand PE import and export decoding with a single containment helper, module, thunk, export, and string budgets, and forwarders reported as stored strings.
- ADR 0010: iterative resource traversal with depth, entry, and string budgets, strict UTF-16 names, leaf data range checking, and `WIN_CERTIFICATE` headers that make no trust claim.
- ADR 0011: `ree.payload.pe/1` evidence projection with `null` directory members for absent or unusable directories, decimal-string `uint64` fields, section content digests, payload and hashing budgets, and unknowns for out-of-scope structures.
- ADR 0012: the analysis use case owns format selection, artifact bounds, provider invocation, record sealing, and a path-free summary; the CLI and the MCP tool are thin surfaces over it, the MCP surface becomes `0.2`, and Mach-O moves to Phase 5 ahead of the remaining readers.
- ADR 0013: bounded Mach-O and universal binary foundation over `io.ReaderAt` plus explicit size, both thin byte orders, `FAT_MAGIC` and `FAT_MAGIC_64` slice tables, a validated load command chain, strict fixed-width names, per-slice failures that keep good slices, and no retained command table.
- ADR 0014: on-demand Mach-O metadata for dylibs, `LC_UUID`, `LC_BUILD_VERSION` and legacy version-min commands, `LC_MAIN`, `LC_SYMTAB` symbols, and `LC_CODE_SIGNATURE` superblob and blob headers, with `ErrNotFound` for absence, aggregated limitations for enumerable defects, and no signature validation.
- ADR 0015: `ree.payload.macho/1` with one record per artifact and every universal slice listed, per-slice status, equal per-slice payload shares, null-for-absent members, artifact-wide section content hashing, and unknowns for out-of-scope structures.

## Verification

- PR #19 checks (`40477930884`): test matrix on Ubuntu, macOS, and Windows with Go 1.26.10 and 1.27.x, race, lint, vet and formatting, vulnerability check, dependency review, CodeQL, actionlint, and cross-builds all pass.
- PR #25 checks (`40638461187`, CodeQL `40638461228`): the same matrix plus the PE provider tests, all 21 checks pass.
- PR #27 checks (`40646671588`, CodeQL `40646671556`), PR #28 checks (`40647967640`, CodeQL `40647967635`), and PR #29 checks (`40648892636`, CodeQL `40648892486`): all 21 checks pass on each pull request.
- PR #31 checks (`40655288448`, CodeQL `40655288471`), PR #32 checks (`40656558688`, CodeQL `40656558698`), PR #33 checks (`40658115378`, CodeQL `40658115643`), and PR #34 checks (`40658702345`, CodeQL `40658702309`): all 21 checks pass on each pull request, and Actionlint passes on each merged commit (`40655288543`, `40656558667`, `40658115311`, `40658702504`).
- Local `gofmt`, `go vet`, `go test ./...`, `go test -race ./...`, `golangci-lint`, `govulncheck`, and `actionlint`: pass at the PR #25 and Phase 4 heads; the merged trees at `c070b94`, `8b7901d`, `f86823b`, and `379f441` are identical to the verified heads.
- Local `GOARCH=386` tests for `internal/formats/pe`, `internal/providers/pe`, `internal/formats/macho`, `internal/providers/macho`, `internal/usecase/analyze`, `internal/cli`, and `internal/mcp`: pass.
- Local fuzz runs: `FuzzObserve` (ELF) 30s (~11k execs), `FuzzObserve` (PE) 30s (19,259 execs), `FuzzParse` 30s (~1.82M execs), `FuzzMetadata` (Mach-O) 25s (2,160,406 execs), and `FuzzObserve` (Mach-O) 12s (27,450 execs); all pass. `FuzzMetadata` found one real defect, a 16-byte dylib command that reached the name decoder; it is fixed and the input is kept as a regression seed.
- Package coverage: `internal/providers/elf` 97.8%, `internal/formats/elf` 96.1%, `internal/providers/pe` 93.5%, `internal/formats/macho` 92.6%, `internal/providers/macho` 92.9%, `internal/usecase/analyze` 95.4%, `internal/cli` 88.4%, `internal/mcp` 97.4%.
- Smoke run against an 11.8 MB system binary: 2.5 MB record, partial coverage with one payload-budget limitation and two unknowns, no panic.
- CLI smoke on `/bin/ls`: `ree analyze` reports `elf`, `builtin.elf/default`, 11,807,104 bytes, 34 sections, 15 segments, and 306 symbols; `--json` is valid and `--out` writes a 2,519,443-byte record with mode 0644 that refuses to overwrite without `--force`.
- MCP probe rehearsal with the new `scripts/verify-release.sh` logic: `MCP ok: 0.2 2025-11-25 ree_analyze, ree_doctor, ree_version`; the `ree_analyze` summary for the built binary matches its `sha256` and size.
- Release workflow `v0.0.2`: pass (`40463183950`); `scripts/verify-release.sh v0.0.2`: pass.

## Known issues and limitations

- ELF, PE, and Mach-O are the formats reachable from the CLI and MCP surfaces. Archives, application packages, JavaScript, external engines, and runtime analysis remain unimplemented.
- The ELF provider does not decode symbol versioning, `SHT_DYNAMIC`, needed libraries, compressed sections, or implicit `SHT_REL` addends; these are recorded as unknowns.
- ELF evidence tables may be prefixes of the artifact's tables when the payload budget is exhausted; `coverage: partial` and an omission limitation describe the gap.
- `uint64` ELF fields, relocation addends, PE image bases, and PE file offsets are decimal strings in the payload because JSON numbers lose precision above 2^53.
- The PE provider does not decode COFF symbols, base relocations, TLS, debug or PDB data, CLR metadata, bound or delay-load imports, or the Rich header; these are recorded as unknowns when present.
- PE directory members are `null` when the directory is absent or unusable, and the limitation text distinguishes the two cases; PE resource and certificate bytes are neither read nor hashed.
- The PE certificate table is not a trust signal: record presence and raw revision and type are reported, and signature validation is recorded as an unknown.
- The Mach-O reader does not decode export tries, chained fixups, relocations, Objective-C metadata, `LC_UNIXTHREAD` entry points, entitlements, or certificate contents, and it does not validate a signature; these are recorded as unknowns when the structure is present.
- A Mach-O code signature is reported as the `LC_CODE_SIGNATURE` range, the superblob header, the blob index, and each blob header only. Presence is not a trust signal.
- A Mach-O slice that cannot be parsed keeps its own status and limitation, so one broken architecture never hides the others; a universal binary's counts are the sum over the slices the payload carries.
- Mach-O section names, dylib names, and symbol names are never repaired: a name is reported through `name_available` with the raw fixed-width field as `name_hex`.
- `0xcafebabe` is both the Mach-O universal magic and the Java class-file magic, so a class file is reported as a Mach-O artifact whose universal header does not parse rather than as an unsupported format.
- Bundles are canonical JSON only: uncompressed, unencrypted, and unsigned. Digests prove byte integrity, not trust or authenticity.
- Module builds from `go install` report `commit` and `built` as `unknown`; this is expected because Go does not embed VCS metadata there.
- Secret scanning and push protection are enabled; non-provider patterns and validity checks remain disabled because the account does not support them.
- `scripts/verify-release.sh` requires `gh`, `cosign`, `tar`, `python3`, and `unzip` for full coverage.
- The MCP tool reads any regular file the server user can read. It bounds size and response size but is not a sandbox, and its error messages disclose whether a path exists and what it is.
- `ree_analyze` returns the sealed record only up to 1 MiB; larger records carry `record_omitted` and must be exported with `ree analyze --out`.
- `ree analyze --out` writes canonical record bytes without a trailing newline because `evidence.Decode` accepts canonical input only.
- The MCP surface is `0.2`; older releases verify as `0.1` with two tools, so a consumer must read the surface version before assuming `ree_analyze` exists.

## Pending work and next action

1. Propose Phase 6 (archives, application packages, and inventory) with scope, acceptance criteria, and a verification plan; wait for approval before implementation.
2. Keep the analysis surfaces limited to ELF, PE, and Mach-O until another provider merges.
3. Cut a release only with explicit approval and after recording verification evidence.

## Update rules

- Update this file after a merged PR or release, or when a known issue changes.
- Keep it short; link to `ROADMAP.md`, `CHANGELOG.md`, ADRs, and `docs/releases/` instead of copying them.
- Never record planned or unverified work as completed.
- Do not store secrets, credentials, personal data, or unnecessary source copies.
