# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- RFC 8785 canonical JSON package with byte and depth limits, SHA-256 digests, conformance tests, and a fuzz target.

## [0.0.2] - 2026-10-27

### Fixed

- `ree version` and `ree_version` report the same bare version string for release archives and `go install` builds. Module builds still report `unknown` for commit and build time because they carry no VCS metadata.

## [0.0.1] - 2026-10-27

### Added

- Initial Go module and `ree version` command.
- Repository baseline, Apache-2.0 license, and contribution policies.
- CI, CodeQL, dependency review, and actionlint workflows.
- `ree doctor` and `ree doctor --json` for bounded local tool and environment diagnostics.
- `ree mcp`, a stdio MCP server with surface version `0.1`.
- `ree_version` and `ree_doctor` MCP tools.
- Official MCP Go SDK dependency, version `v1.8.0`.
- Go 1.26.10 baseline with patched standard-library dependencies.
- Third-party license notices for runtime dependencies.
- Tag-driven GoReleaser workflow with archives, checksums, SBOMs, and keyless cosign signing.
- `scripts/verify-release.sh` for post-release artifact, signature, binary, and MCP verification.

[Unreleased]: https://github.com/mrsandipmandal/reverse-engineer-everything/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/mrsandipmandal/reverse-engineer-everything/releases/tag/v0.0.2
[0.0.1]: https://github.com/mrsandipmandal/reverse-engineer-everything/releases/tag/v0.0.1
