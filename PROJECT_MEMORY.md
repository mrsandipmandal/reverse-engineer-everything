# Project memory

Last updated: 2026-10-27 · `main@86a7bbf` · latest release `v0.0.2`

This file is a short, verified snapshot for continuity. The roadmap, changelog, ADRs, and release records remain authoritative for their own content.

## Current status

- Phase 0a, 0b, 0c, Phase 1 (evidence core), and Phase 2 (ELF) are complete.
- Phase 2 adds pure library packages under `internal/formats/elf` and `internal/providers/elf`; CLI and MCP surfaces are unchanged.
- `v0.0.1` and `v0.0.2` are published and verified; no Phase 2 release was cut.
- `main` is clean and protected; CI, CodeQL, and Actionlint are green on `86a7bbf`.

## Completed milestones

| Phase | Scope | Evidence |
|---|---|---|
| 0a | Go module, `ree version`, CI baseline, open-source files | PR #1, `545207d` |
| 0b | `ree mcp`, `ree_version`, `ree_doctor`, release automation | PR #2, `4b12947` |
| 0c | `v0.0.1` release and repository hardening | PRs #4, #5; release and `docs/releases/v0.0.1.md` |
| 1 | RFC 8785 canonical JSON, `ree.evidence/1`, `ree.bundle/1` | PRs #9, #10, #12; ADR 0003; `docs/evidence.md`, `docs/bundle.md` |
| 2 | Bounded ELF32/ELF64 reader and `ree.payload.elf/1` evidence provider | PRs #16–#19; `680f455`, `81a151b`, `efc014e`, `86a7bbf`; ADR 0004–0007; `docs/payload-elf.md` |

## Architecture decisions

- ADR 0001: Go baseline, Apache-2.0, package layout, read-only-first scope.
- ADR 0002: official MCP Go SDK `v1.8.0`, surface `0.1`, protocol range.
- ADR 0003: canonical JSON through `github.com/gowebpki/jcs` `v1.0.2`, SHA-256 content addressing, strict `ree.evidence/1`, deterministic `ree.bundle/1`, and the Phase 1 limits.
- ADR 0004: bounded ELF header and table reader over `io.ReaderAt` plus explicit size; structural defects fail, physical or count truncation yields partial tables with limitations.
- ADR 0005: on-demand ELF content reads, all-or-nothing section and segment data, partially decoded notes, and UTF-8 name and comment rules.
- ADR 0006: ELF symbols and relocations with the null symbol, per-table index spaces, `SHN_XINDEX`, and explicit versus stored addends.
- ADR 0007: `ree.payload.elf/1` evidence projection with decimal-string `uint64` fields, content digests, payload and hashing budgets, and coverage derived from limitations and unknowns.

## Verification

- PR #19 checks (`40477930884`): test matrix on Ubuntu, macOS, and Windows with Go 1.26.10 and 1.27.x, race, lint, vet and formatting, vulnerability check, dependency review, CodeQL, actionlint, and cross-builds all pass.
- Local `gofmt`, `go vet`, `go test ./...`, `go test -race ./...`, `golangci-lint`, `govulncheck`, and `actionlint`: pass at the PR #19 head; the merged tree at `86a7bbf` is identical.
- Local fuzz runs: `FuzzParse` 30s (~1.82M execs) and `FuzzObserve` 30s (~11k execs); all pass.
- `internal/providers/elf` package coverage: 97.8%; `internal/formats/elf`: 96.1%.
- Smoke run against an 11.8 MB system binary: 2.5 MB record, partial coverage with one payload-budget limitation and two unknowns, no panic.
- Release workflow `v0.0.2`: pass (`40463183950`); `scripts/verify-release.sh v0.0.2`: pass.

## Known issues and limitations

- Phase 1 and Phase 2 packages are not consumed by the CLI or MCP surface yet; that arrives with the Phase 6 analysis surface after providers exist.
- The ELF provider does not decode symbol versioning, `SHT_DYNAMIC`, needed libraries, compressed sections, or implicit `SHT_REL` addends; these are recorded as unknowns.
- ELF evidence tables may be prefixes of the artifact's tables when the payload budget is exhausted; `coverage: partial` and an omission limitation describe the gap.
- `uint64` ELF fields and relocation addends are decimal strings in the payload because JSON numbers lose precision above 2^53.
- Bundles are canonical JSON only: uncompressed, unencrypted, and unsigned. Digests prove byte integrity, not trust or authenticity.
- Module builds from `go install` report `commit` and `built` as `unknown`; this is expected because Go does not embed VCS metadata there.
- Secret scanning and push protection are enabled; non-provider patterns and validity checks remain disabled because the account does not support them.
- `scripts/verify-release.sh` requires `gh`, `cosign`, `tar`, `python3`, and `unzip` for full coverage.

## Pending work and next action

1. Propose Phase 3 (read-only PE provider) with scope, acceptance criteria, and a verification plan; wait for approval before implementation.
2. Keep CLI and MCP surfaces unchanged until a provider is wired into a use case.
3. Cut a release only with explicit approval and after recording verification evidence.

## Update rules

- Update this file after a merged PR or release, or when a known issue changes.
- Keep it short; link to `ROADMAP.md`, `CHANGELOG.md`, ADRs, and `docs/releases/` instead of copying them.
- Never record planned or unverified work as completed.
- Do not store secrets, credentials, personal data, or unnecessary source copies.
