# Project memory

Last updated: 2026-10-27 · `main@df69301` · latest release `v0.0.2`

This file is a short, verified snapshot for continuity. The roadmap, changelog, ADRs, and release records remain authoritative for their own content.

## Current status

- Phase 0a, 0b, and 0c are complete.
- Phase 1 (evidence core) is not started; design and scope are approved.
- `v0.0.1` and `v0.0.2` are published and verified.
- `main` is clean and protected; CI, CodeQL, and Actionlint are green on `df69301`.

## Completed milestones

| Phase | Scope | Evidence |
|---|---|---|
| 0a | Go module, `ree version`, CI baseline, open-source files | PR #1, `545207d` |
| 0b | `ree mcp`, `ree_version`, `ree_doctor`, release automation | PR #2, `4b12947` |
| 0c | `v0.0.1` release and repository hardening | PRs #4, #5; release and `docs/releases/v0.0.1.md` |

## Architecture decisions

- ADR 0001: Go baseline, Apache-2.0, package layout, read-only-first scope.
- ADR 0002: official MCP Go SDK `v1.8.0`, surface `0.1`, protocol range.
- ADR 0003: pending; will record evidence-core decisions.

## Verification

- Local `gofmt`, `go vet`, `go test`, `go test -race`, `golangci-lint`, and `govulncheck`: pass at `df69301`.
- Main CI, CodeQL, and Actionlint: pass on `df69301`.
- Release workflow `v0.0.2`: pass (`40463183950`).
- `scripts/verify-release.sh v0.0.2`: pass (checksums, cosign identity, archive contents, binary identity, MCP surface).
- `go install ...@v0.0.2`: pass; reports version `0.0.2` with `commit`/`built` `unknown`.
- `scripts/verify-release.sh v0.0.1`: pass at the previous release.

## Known issues and limitations

- Module builds from `go install` report `commit` and `built` as `unknown`; this is expected because Go does not embed VCS metadata there.
- Secret scanning and push protection are enabled; non-provider patterns and validity checks remain disabled because the account does not support them.
- `scripts/verify-release.sh` requires `gh`, `cosign`, `tar`, `python3`, and `unzip` for full coverage.

## Pending work and next action

1. Implement Phase 1 in three reviewable PRs:
   - RFC 8785 canonical JSON with `github.com/gowebpki/jcs` and conformance/fuzz tests;
   - evidence schema `ree.evidence/1` with strict encode/decode and golden tests;
   - deterministic `ree.bundle/1` export/import with limits, integrity, and fuzz tests.
2. Keep CLI and MCP surfaces unchanged during Phase 1.
3. Record decisions in ADR 0003 and update dependency and threat-model documentation.

## Update rules

- Update this file after a merged PR or release, or when a known issue changes.
- Keep it short; link to `ROADMAP.md`, `CHANGELOG.md`, ADRs, and `docs/releases/` instead of copying them.
- Never record planned or unverified work as completed.
- Do not store secrets, credentials, personal data, or unnecessary source copies.
