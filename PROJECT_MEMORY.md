# Project memory

Last updated: 2026-10-27 · `main@a720af2` · latest release `v0.0.2`

This file is a short, verified snapshot for continuity. The roadmap, changelog, ADRs, and release records remain authoritative for their own content.

## Current status

- Phase 0a, 0b, 0c, and Phase 1 (evidence core) are complete.
- Phase 1 adds pure library packages; CLI and MCP surfaces are unchanged.
- `v0.0.1` and `v0.0.2` are published and verified.
- `main` is clean and protected; CI, CodeQL, and Actionlint are green on `a720af2`.

## Completed milestones

| Phase | Scope | Evidence |
|---|---|---|
| 0a | Go module, `ree version`, CI baseline, open-source files | PR #1, `545207d` |
| 0b | `ree mcp`, `ree_version`, `ree_doctor`, release automation | PR #2, `4b12947` |
| 0c | `v0.0.1` release and repository hardening | PRs #4, #5; release and `docs/releases/v0.0.1.md` |
| 1 | RFC 8785 canonical JSON, `ree.evidence/1`, `ree.bundle/1` | PRs #9, #10, #12; ADR 0003; `docs/evidence.md`, `docs/bundle.md` |

## Architecture decisions

- ADR 0001: Go baseline, Apache-2.0, package layout, read-only-first scope.
- ADR 0002: official MCP Go SDK `v1.8.0`, surface `0.1`, protocol range.
- ADR 0003: canonical JSON through `github.com/gowebpki/jcs` `v1.0.2`, SHA-256 content addressing, strict `ree.evidence/1`, deterministic `ree.bundle/1`, and the Phase 1 limits.

## Verification

- Local `gofmt`, `go vet`, `go test`, `go test -race`, `golangci-lint`, `govulncheck`, and `actionlint`: pass at `a720af2`.
- Main CI, CodeQL, and Actionlint: pass on `a720af2`.
- Local fuzz runs: canonical 21s (~1.14M execs), evidence decode 30s (~1.65M execs), bundle import 30s (~1.44M execs); all pass.
- Release workflow `v0.0.2`: pass (`40463183950`).
- `scripts/verify-release.sh v0.0.2`: pass (checksums, cosign identity, archive contents, binary identity, MCP surface).
- `go install ...@v0.0.2`: pass; reports version `0.0.2` with `commit`/`built` `unknown`.
- `scripts/verify-release.sh v0.0.1`: pass at the previous release.

## Known issues and limitations

- Phase 1 packages are not consumed by the CLI or MCP surface yet; that arrives with the Phase 6 analysis surface after providers exist.
- Bundles are canonical JSON only: uncompressed, unencrypted, and unsigned. Digests prove byte integrity, not trust or authenticity.
- Validation is hand-written in Go; no JSON Schema validator is used in Phase 1.
- JSON numbers follow ECMAScript double serialization, so payload integers beyond 2^53 lose precision.
- Module builds from `go install` report `commit` and `built` as `unknown`; this is expected because Go does not embed VCS metadata there.
- Secret scanning and push protection are enabled; non-provider patterns and validity checks remain disabled because the account does not support them.
- `scripts/verify-release.sh` requires `gh`, `cosign`, `tar`, `python3`, and `unzip` for full coverage.

## Pending work and next action

1. Propose Phase 2 (read-only ELF provider) with scope, acceptance criteria, and verification plan; wait for approval before implementation.
2. Keep CLI and MCP surfaces unchanged until a provider and use case exist.
3. Cut a release only with explicit approval and after recording verification evidence.

## Update rules

- Update this file after a merged PR or release, or when a known issue changes.
- Keep it short; link to `ROADMAP.md`, `CHANGELOG.md`, ADRs, and `docs/releases/` instead of copying them.
- Never record planned or unverified work as completed.
- Do not store secrets, credentials, personal data, or unnecessary source copies.
