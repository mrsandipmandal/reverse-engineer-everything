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
- Bounded PE resource tree and attribute certificate table decoding: depth-first named and integer identifiers, strict UTF-16 names, shared entry and string budgets, cycle and depth limits, leaf data range checking, `WIN_CERTIFICATE` headers with eight-byte alignment, count and size limits, and an explicit certificate blob accessor that makes no trust claim.
- `internal/providers/pe`, the second evidence provider: a bounded `ree.payload.pe/1` projection of PE32 and PE32+ headers, optional headers, data directories, section headers with content digests, overlay bounds, imports, exports, resource leaves, and certificate record headers into a sealed `ree.evidence/1` record, with null directory members, payload and hashing budgets, and explicit coverage, limitations, and unknowns.
- `internal/usecase/analyze`, the analysis use case: bounded magic detection, ELF and PE provider selection, sealed `ree.evidence/1` bytes, and a path-free summary with coverage, limitations, unknowns, and table counts.
- `ree_analyze` and MCP surface `0.2`: the first MCP analysis tool, with explicit or magic-based ELF and PE selection, a bounded path-free summary, an optional 1 MiB sealed record, and a `record_omitted` notice for larger records.
- `ree analyze <path>`, the first artifact analysis command: explicit or magic-based ELF and PE selection, text and JSON summary output, canonical record export that refuses to overwrite without `--force`, and exit codes that separate usage errors from operational failures.
- Bounded Mach-O and universal binary reader foundation: thin 32-bit and 64-bit headers in both byte orders, `FAT_MAGIC` and `FAT_MAGIC_64` slice tables, a validated load command chain, segment and section tables with strict fixed-width names, per-slice failures that do not hide other architectures, section content reads, crafted fixtures, a fuzz target, and ADR 0013.
- Bounded Mach-O metadata: dylib install and dependency commands, `LC_UUID`, `LC_BUILD_VERSION` and legacy version-min commands, `LC_MAIN`, `LC_SYMTAB` symbols and string tables, and `LC_CODE_SIGNATURE` superblob and blob headers with no signature validation, plus crafted fixtures, a second fuzz target, and ADR 0014.
- `ree.payload.macho/1` evidence adapter: one record per artifact with every universal slice listed, per-slice status, segments, sections with content digests, dylib and build metadata, entry point, symbols, code signature headers, payload and content budgets, coverage limitations and unknowns, a fuzz target, and ADR 0015.
- `ree analyze` and `ree_analyze` Mach-O support: `--format macho`, thin and universal magic detection, `builtin.macho` provider selection, and Mach-O counts summed across slices.
- Bounded ZIP, tar, and gzip reader foundation: central directory and end-record validation including ZIP64, ustar, PAX, and GNU long names, gzip headers and header CRC, unsafe-path detection, explicit count and byte limits, on-demand content reads with CRC verification, crafted fixtures, a fuzz target, and ADR 0016.
- `ree.payload.archive/1` evidence provider: one `ree.evidence/1` record per archive with every entry projected, prefix-based nested container detection bounded by depth, member count, and decoded bytes, deterministic payload budgets, and ADR 0017.

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
