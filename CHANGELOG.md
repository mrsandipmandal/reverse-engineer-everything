# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- RFC 8785 canonical JSON package with byte and depth limits, SHA-256 digests, conformance tests, and a fuzz target.
- `ree.evidence/1` schema with strict canonical-only decoding, payload integrity digests, explicit coverage and unknowns, size and count limits, golden tests, and a fuzz target.
- `ree.bundle/1` deterministic export and in-memory import with record-digest ordering, duplicate and order rejection, a bundle digest, tamper tests, and a fuzz target.
- Bounded ELF32/ELF64 header and raw table reader with extended numbering, explicit truncation limitations, crafted 32/64-bit little/big-endian fixtures, a fuzz target, and differential tests against `debug/elf`.
- Bounded ELF section names, section and segment contents, `SHT_NOTE` scanning, GNU build-id extraction, and `.comment` entries with distinct absent, unavailable, malformed, and limit errors.
- Bounded ELF symbol and relocation decoding with the null symbol, per-table index provenance, UTF-8 name resolution, `SHN_XINDEX` support, explicit or stored addend semantics, and differential symbol checks against `debug/elf`.
- `internal/providers/elf`, the first evidence provider: a bounded `ree.payload.elf/1` projection of ELF headers, sections, segments, symbols, relocations, notes, build-id, and `.comment` entries into a sealed `ree.evidence/1` record, with content digests, payload and hashing budgets, and explicit coverage, limitations, and unknowns.
- Bounded PE32/PE32+ header, optional header, data directory, and section table reader with declared-count tracking, deterministic truncation limitations, section content reads, RVA mapping, overlay bounds, crafted PE32/PE32+ fixtures, a fuzz target, and differential tests against `debug/pe`.
- Bounded PE import and export decoding: import descriptors, original-thunk and IAT thunk arrays, named and ordinal thunks, export address, name, and ordinal tables, unnamed exports, forwarder strings, per-string and per-call string budgets, aggregated name limitations, and an imported-symbol differential test against `debug/pe`.

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
