# Architecture

## Principles

REE is evidence-first and read-only by default.

1. Observe before inferring. Every finding identifies its source.
2. Preserve uncertainty. Unknowns are recorded, not hidden.
3. Keep analysis reproducible. Inputs are content-addressed and evidence is deterministic.
4. Bound every resource. Parsers enforce size, count, depth, time, and output limits.
5. Do not execute untrusted artifacts. Runtime analysis is a separate, explicit phase.
6. Keep the public contract stable and versioned.

## Layers

```text
cmd/ree                 CLI entry point
internal/cli            command parsing and presentation
internal/app            use cases and orchestration
internal/contracts      versioned public schemas and canonical encoding
internal/domain         provider-neutral evidence and analysis types
internal/providers      provider implementations and registry
internal/formats        format readers and parsers
internal/process        bounded subprocess execution
internal/platform       OS and architecture integration
internal/setup          tool detection and environment diagnostics
internal/views          paginated projections of retained evidence
internal/mcp            MCP server surface
pkg/sdk                 importable client and provider SDK
docs/adr                architecture decision records
```

## Boundaries

### Provider

A provider identifies one analysis engine or built-in reader and declares its capabilities, version, and limitations.

### Reader

A reader parses one artifact family behind a bounded, context-aware interface. Readers never execute target code.

### Comparator

A comparator relates two authenticated observations and reports changes with explicit coverage.

### Store

A store retains evidence and supports deterministic export and import. The first implementation is in-memory with offline bundles.

### Runner

A runner executes an allowlisted external tool under explicit authorization, isolation, and resource limits. It is not part of the Phase 0b surface.

### MCP surface

The MCP server is a versioned projection over REE-native operations, not a compatibility layer for another tool. In Phase 0b it exposes build identity and local diagnostics only. Tool names, input schemas, output schemas, and annotations are part of the public contract. Stdout carries protocol messages; diagnostics go to stderr.

## Evidence model

Evidence is the core contract.

- Subject: exact input identity, including SHA-256 and byte length.
- Schema: explicit schema name and version.
- Provider: identifier, version, and analysis profile.
- Authority: `observed`, `derived`, or `inferred`.
- Coverage: `complete`, `partial`, or `unknown`.
- Limitations and unknowns: first-class records.
- Payload: canonical JSON using RFC 8785.
- Integrity: digest of the canonical payload.
- Reproducibility: no wall-clock timestamps or host-specific paths in hashed content.

Evidence bundles are offline, versioned, and deterministic. Import validates every digest and schema before merging.

## Security posture

- Inputs are untrusted.
- Parsers are streaming where practical and always bounded.
- Archive handling rejects traversal, symlink escapes, and decompression bombs.
- Subprocesses use argv only, sanitized environments, isolated temporary directories, rlimits where available, process-group termination, and output caps.
- External tools are detected, not bundled.
- No hidden network access.
- Runtime analysis requires explicit user authorization.

See [threat-model.md](threat-model.md).

## Compatibility

The MCP surface is REE-native and versioned. A compatibility profile for other tools may be added later; it is not part of the initial contract.

## Phase 0a

Phase 0a contains the CLI foundation:

- `ree version` and `ree help`;
- deterministic build metadata;
- CI, CodeQL, dependency review, and workflow linting;
- open-source repository files.

## Phase 0b

Phase 0b adds the first public protocol surface and release automation:

- `ree mcp`, a stdio MCP server with surface version `0.1`;
- `ree_version` and `ree_doctor` as the only MCP tools;
- `ree doctor` with text and JSON reports for local tooling;
- GoReleaser archives, checksums, SBOMs, and keyless signing for tagged releases;
- Dependabot and SHA-pinned release actions.

The doctor reads tool metadata through fixed argv probes with timeouts and output caps. It does not accept artifact paths, parse artifacts, or execute analysis engines. No artifact parsing or analysis tool is exposed in this phase.

## Phase 1

Phase 1 adds the evidence core as pure library packages:

- `internal/contracts/canonical` implements RFC 8785 canonical JSON with byte, depth, and I-JSON validation, plus SHA-256 digests;
- `internal/contracts/evidence` defines schema `ree.evidence/1`, strict encode/decode, and digest verification;
- `internal/contracts/bundle` defines the deterministic `ree.bundle/1` document with export and in-memory import.

No CLI or MCP surface consumes these packages yet. That arrives with the Phase 4 analysis surface, after providers exist. See [ADR 0003](adr/0003-evidence-core.md) for decisions and limits, [evidence.md](evidence.md) for the record wire format, and [bundle.md](bundle.md) for the bundle format.

## Phase 2

Phase 2 adds a read-only ELF reader in `internal/formats/elf`:

- validated ELF32 and ELF64 identifiers and file headers for little-endian and big-endian artifacts;
- extended numbering for section and program counts and the section name index;
- raw section and program header tables with declared-count versus loaded-count semantics;
- explicit `Truncated` and `Limitations` reporting for physical truncation and configured count limits;
- bounded section names and section and segment contents, read on demand;
- bounded `SHT_NOTE` scanning, GNU build-id extraction, and NUL-separated `.comment` entries;
- bounded `SHT_SYMTAB` and `SHT_DYNSYM` decoding, including the null symbol, per-table index provenance, UTF-8 name resolution, and `SHN_XINDEX` resolution through `SHT_SYMTAB_SHNDX`;
- bounded `SHT_REL` and `SHT_RELA` decoding with raw `r_info`, decoded symbol and type fields, and explicit versus stored addends;
- explicit `ErrOutOfRange`, `ErrUnavailable`, and `ErrNotFound` so callers can distinguish absent metadata from uncovered or malformed metadata.

The reader never executes, decompresses, or maps the artifact. Content is returned as stored bytes. See [ADR 0004](adr/0004-elf-reader.md) for the header and table decisions, [ADR 0005](adr/0005-elf-metadata.md) for the content and metadata limits, error semantics, and note and comment decoding rules, and [ADR 0006](adr/0006-elf-symbols-relocations.md) for symbol and relocation decoding, names, extended indexes, and addend semantics.

Phase 2 also adds the first evidence provider, `internal/providers/elf`:

- `Observe` hashes the artifact, parses it with the reader, and returns an `ree.evidence/1` record with a `ree.payload.elf/1` payload;
- the payload carries the validated header, section and segment tables with content digests, symbols, relocations, notes, GNU build-id, and `.comment` entries;
- the payload budget and content-hash budget bound every table, and trimming is a prefix in artifact order with an explicit limitation;
- coverage is `complete` only when no limitation or unknown was recorded, and unreadable artifacts produce an error instead of evidence.

The provider does not execute, decompress, or write content and does not depend on `debug/elf`. See [ADR 0007](adr/0007-elf-evidence-adapter.md) for the projection decisions and [payload-elf.md](payload-elf.md) for the wire format. No CLI or MCP surface calls the provider yet.

## Phase 3

Phase 3 adds a read-only PE reader in `internal/formats/pe`. The first increment provides:

- validated DOS, PE, and COFF headers with `e_lfanew` overlapping the DOS header rejected as structural;
- separate PE32 and PE32+ optional header decoding, including the 64-bit image base and stack and heap sizes that only PE32+ carries;
- up to sixteen data directory entries with the declared count kept separate from the loaded count;
- up to 96 section headers, decoded UTF-8 names, raw name bytes, and on-demand section content reads;
- declared-count versus loaded-count semantics with explicit `Truncated` and `Limitations` reporting for a physically short section table or a configured count limit;
- deterministic RVA mapping across the headers region and the section table, with an `Ambiguous` flag for overlapping sections and no file offset for virtual-only tails;
- overlay bounds derived from `SizeOfHeaders` and section raw ends, omitted rather than guessed when a raw range extends beyond the artifact;
- explicit `ErrInvalid`, `ErrTruncated`, `ErrLimit`, `ErrRead`, `ErrOutOfRange`, and `ErrUnavailable` sentinels.

The imports and exports increment adds on-demand directory decoders:

- `File.Imports` scans import descriptors up to an all-zero terminator and decodes module names, original-thunk or IAT thunk arrays, named thunks with their hint, and ordinal thunks with the magic-specific high-bit flag;
- `File.Exports` decodes the export directory, the function address table, the name and ordinal tables, unnamed slots, and forwarders recognized by a function RVA inside the export directory range;
- both share a containment helper that resolves one RVA to a contiguous file-backed range inside the headers region or one section, so a structure cannot be assembled across sections;
- import and export name work is bounded by a per-string limit and by a separate per-call string budget, with distinct `ErrNotFound`, `ErrUnavailable`, `ErrInvalid`, and `ErrLimit` results for the directory, containment, and limit cases.

The resources and certificates increment adds the two remaining directories:

- `File.Resources` walks the self-relative resource tree iteratively in depth-first on-disk order, with named and integer identifiers, strict UTF-16 names, a shared entry budget, a depth limit, and leaf data ranges reported as declared and checked for file backing without reading the bytes;
- `File.Certificates` decodes the security directory, which stores a file offset rather than an RVA, and returns the `WIN_CERTIFICATE` headers with their record bounds, eight-byte alignment, count limit, and trailing padding handling;
- `File.CertificateData` returns one certificate blob as stored; nothing is parsed as PKCS#7, chained, or trusted.

The reader never executes, decompresses, maps, or writes artifact content. Section content is returned as stored bytes, forwarders are reported as stored strings rather than followed, and certificate records make no signature or trust claim. See [ADR 0008](adr/0008-pe-reader.md) for the foundation decisions, [ADR 0009](adr/0009-pe-imports-exports.md) for the import and export decisions, and [ADR 0010](adr/0010-pe-resources-certificates.md) for the resource and certificate decisions.

Phase 3 also adds the second evidence provider, `internal/providers/pe`:

- `Observe` hashes the artifact, parses it with the reader, and returns an `ree.evidence/1` record with a `ree.payload.pe/1` payload;
- the payload carries the validated header and optional header, data directories, section headers with content digests, overlay bounds, import modules and thunks, export slots, resource leaves, and `WIN_CERTIFICATE` record headers;
- a directory member is `null` when the directory is absent or the reader could not return it, and a limitation distinguishes the two cases;
- the payload budget and content-hash budget bound every table, and trimming is a prefix in artifact order with an explicit limitation and a `truncated` flag;
- coverage is `complete` only when no limitation or unknown was recorded, and unreadable artifacts produce an error instead of evidence.

The provider does not execute, unpack, or write content, does not hash resource or certificate bytes, and does not depend on `debug/pe`. See [ADR 0011](adr/0011-pe-evidence-adapter.md) for the projection decisions and [payload-pe.md](payload-pe.md) for the wire format. No CLI or MCP surface calls the PE reader or provider yet.
