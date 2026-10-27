# Project memory

Last updated: 2026-10-27 · `main@72f1dde` · latest release `v0.0.1`

This file is a short, verified snapshot for continuity. The roadmap, changelog, ADRs, and release records remain authoritative for their own content.

## Current status

- Phase 0a, 0b, and 0c are complete.
- Phase 1 (evidence core) is not started; the proposal is approved but implementation has not begun.
- `v0.0.1` is published and verified.
- `main` is clean and protected; CI, CodeQL, and Actionlint are green on `72f1dde`.

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

- Local `make check`: pass at `084576a` (fmt, vet, test, race, golangci-lint, govulncheck, actionlint).
- Main CI, CodeQL, Actionlint: pass on `72f1dde`.
- Release workflow: pass (`40457479932`).
- `scripts/verify-release.sh v0.0.1`: pass (checksums, cosign identity, archive contents, binary identity, MCP surface).
- Release assets: 14; six archives, six SBOMs, checksums, cosign bundle.

## Known issues and limitations

- Version identity is inconsistent across install paths: release archives report `0.0.1`, `go install ...@v0.0.1` reports `v0.0.1` with `commit`/`built` unknown. An approved normalization patch is pending.
- Secret scanning and push protection are enabled; non-provider patterns and validity checks remain disabled because the account does not support them.
- `scripts/verify-release.sh` requires `gh`, `cosign`, `tar`, `python3`, and `unzip` for full coverage.

## Pending work and next action

1. Add a version-normalization patch and, if approved, a `v0.0.2` release.
2. Implement Phase 1 in three reviewable PRs:
   - RFC 8785 canonical JSON with `github.com/gowebpki/jcs` and conformance/fuzz tests;
   - evidence schema `ree.evidence/1` with strict encode/decode and golden tests;
   - deterministic `ree.bundle/1` export/import with limits, integrity, and fuzz tests.
3. Keep CLI and MCP surfaces unchanged during Phase 1.

## Update rules

- Update this file after a merged PR or release, or when a known issue changes.
- Keep it short; link to `ROADMAP.md`, `CHANGELOG.md`, ADRs, and `docs/releases/` instead of copying them.
- Never record planned or unverified work as completed.
- Do not store secrets, credentials, personal data, or unnecessary source copies.
