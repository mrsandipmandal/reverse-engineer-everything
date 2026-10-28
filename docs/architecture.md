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
- `ree_version` and `ree_doctor` as the only MCP tools in that surface;
- `ree doctor` with text and JSON reports for local tooling;
- GoReleaser archives, checksums, SBOMs, and keyless signing for tagged releases;
- Dependabot and SHA-pinned release actions.

The doctor reads tool metadata through fixed argv probes with timeouts and output caps. It does not accept artifact paths, parse artifacts, or execute analysis engines. No artifact parsing or analysis tool is exposed in this phase; `ree_analyze` arrives with the Phase 4 analysis surface.

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

The provider does not execute, unpack, or write content, does not hash resource or certificate bytes, and does not depend on `debug/pe`. See [ADR 0011](adr/0011-pe-evidence-adapter.md) for the projection decisions and [payload-pe.md](payload-pe.md) for the wire format. The Phase 4 analysis surface calls the provider through `internal/usecase/analyze`; no surface calls the reader directly.

## Phase 4

Phase 4 makes the readers usable without adding a new one:

- `internal/usecase/analyze` selects the built-in provider from artifact magic or an explicit format, enforces the artifact size cap, requires a regular file, and returns a summary, the decoded record, and the exact canonical bytes;
- `ree analyze` prints that summary as text or JSON, writes the sealed record with `--out`, refuses to overwrite without `--force`, and separates usage errors from operational failures;
- `ree_analyze` exposes the same summary to MCP clients with an explicit format, an optional size cap, and an optional record carried only while it fits a 1 MiB tool limit;
- the MCP surface moves to `0.2`; a `0.1` server still lists only `ree_version` and `ree_doctor`.

The summary is path-free: it names the format, provider identity, size, subject and record digests, coverage, limitations, unknowns, and table counts. Neither the summary nor the record contains the artifact path or name, and the CLI text form prints only the base name. Analysis never executes, maps, decompresses, or writes artifact content; the only write the surface performs is the record requested with `--out`. See [ADR 0012](adr/0012-analysis-surface.md) and [analyze.md](analyze.md).

## Phase 5

Phase 5 adds a read-only Mach-O reader in `internal/formats/macho` and the third evidence provider, `internal/providers/macho`:

- the reader validates thin 32-bit and 64-bit headers in both byte orders, `FAT_MAGIC` and `FAT_MAGIC_64` slice tables, and a load command chain in which every command must fit inside the declared command bytes;
- segments and sections are decoded with strict fixed-width names, and section content is read on demand as stored bytes;
- dylib commands, `LC_UUID`, `LC_BUILD_VERSION` and legacy version-min commands, `LC_MAIN`, `LC_SYMTAB` symbols, and `LC_CODE_SIGNATURE` superblob and blob headers are decoded on demand, each under its own count and byte limit;
- a slice that cannot be parsed keeps its status and limitation, so one broken architecture never hides the others, and only a reader failure fails the observation;
- code signature bytes are reported as headers only: no signature, certificate chain, or entitlement is parsed or validated.

`Observe` returns one `ree.evidence/1` record per artifact with a `ree.payload.macho/1` payload. The subject digest covers the whole file, so a universal binary is one record whose `slices` list every architecture. The payload budget charges the artifact envelope first, then gives every slice an equal share, and inside a slice apportions segments 20, sections 30, dylibs 20, symbols 20, and signature blobs 10 percent of what remains. A table that does not fit is a prefix with `truncated` set and one limitation naming the omitted count.

The provider does not execute, map, decompress, or write content and does not depend on `debug/macho`. See [ADR 0013](adr/0013-macho-reader.md), [ADR 0014](adr/0014-macho-metadata.md), and [ADR 0015](adr/0015-macho-evidence-adapter.md) for the decisions, and [payload-macho.md](payload-macho.md) for the wire format.

The analysis surface selects the provider by magic — `0xfeedface`, `0xfeedfacf`, `0xcefaedfe`, `0xcffaedfe`, `0xcafebabe`, `0xcafebabf`, and their byte-swapped forms — or by `--format macho`. Because `0xcafebabe` is also the Java class-file magic, a class file is reported as a Mach-O artifact whose universal header does not parse rather than as an unknown format.


## Phase 6

Phase 6 adds archives, application packages, and inventory. The first two
increments add a read-only container reader and its evidence provider:

- `internal/formats/archive` validates the ZIP end record, central directory, and central-versus-local name match, including ZIP64 and data descriptors; walks ustar, PAX, and GNU tar header chains with signed or unsigned checksums, base-256 numbers, long names, and sparse detection; and parses the first gzip member header with `FHCRC` verification;
- entry names are decoded as UTF-8 and never repaired; an absolute path, drive letter, backslash separator, NUL byte, or parent-directory segment is inventoried with the raw bytes and its content is never read;
- entry content is returned in memory on demand under a content limit, with CRC-32 verified only on a full read; nothing is extracted, linked, mapped, or written;
- `internal/providers/archive` returns one `ree.evidence/1` record per artifact with a `ree.payload.archive/1` payload; the artifact and every entry are projected, and a member that holds another container is described as a nested subtree.

Nested detection reads a 263-byte prefix before it decodes a member, so an ordinary large file is never decompressed. It is bounded by depth (one level by default, two at most), parsed member count, and an aggregate decoded-byte budget shared across levels. A member that cannot be read keeps its status and one record limitation instead of hiding the other members. The payload budget charges the artifact envelope first and then splits what remains between entries and nested containers.

The provider does not execute, link, map, decompress outside a bounded read, or write content. See [ADR 0016](adr/0016-archive-reader.md) and [ADR 0017](adr/0017-archive-evidence-adapter.md) for the decisions, and [payload-archive.md](payload-archive.md) for the wire format. Wiring the provider into the analysis surface, archive inventory commands, and the APK, ASAR, and plist readers is deferred to later Phase 6 increments.
