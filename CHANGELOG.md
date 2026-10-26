# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
