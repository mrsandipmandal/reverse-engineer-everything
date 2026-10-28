# ADR 0011: PE evidence adapter and payload schema

- Status: accepted
- Date: 2026-10-28

## Context

ADR 0008 to ADR 0010 established a bounded, read-only PE32 and PE32+ reader in `internal/formats/pe`: headers, optional header, data directories, sections, section content, overlay bounds, imports, exports, resources, certificate record headers, and certificate blobs.

Phase 3 needs the projection between that reader and the Phase 1 evidence core (`ree.evidence/1`), so a PE observation becomes a canonical record with a subject digest, a fixed provider identity, authority, coverage, limitations, unknowns, and a payload with its own integrity digest. ADR 0007 defines the same projection for ELF; the PE adapter follows it so consumers meet one pattern, but the PE structures differ enough that the shares, unknowns, and null semantics need their own decision.

The adapter must not turn an unavailable directory into an empty one, must not present a trimmed table as complete, must not read resource or certificate bytes it does not report a digest for, and must stay read-only.

## Decisions

### Package and provider identity

The adapter lives in `internal/providers/pe` and exposes `Observe(io.ReaderAt, size, Options)`.

- `provider.id` is `builtin.pe` and `provider.profile` is `default`. Both are fixed constants that identify the built-in reader and its only analysis profile.
- `provider.version` is required as `Options.ProviderVersion`. The library does not import the CLI version package, so a caller records the build that produced the evidence without coupling the provider to one release path.
- Authority is always `observed`. The adapter reports structures it read; it does not infer behaviour and does not classify the artifact as malicious.
- A missing `ProviderVersion` fails with `ErrOptions` instead of emitting an unversioned record.

### Payload schema

The payload is `ree.payload.pe/1`, documented in [payload-pe.md](../payload-pe.md).

- The fixed members `header`, `data_directories`, and `sections` are always present. The directory-derived members `imports`, `exports`, `resources`, and `certificates` are `null` when the artifact declares no such directory or the directory could not be used.
- A present table uses an empty array when it decoded nothing, so "present and empty" stays distinguishable from "absent or unusable".
- Directory trimming caused by a reader limit also yields `null`, with the reader's limitation carried into the record. A record limitation therefore separates "the artifact does not have it" from "the reader could not return it".
- Fixed-width fields that JSON represents exactly (`uint8`, `uint16`, `uint32`) stay JSON numbers.
- `uint64` values are decimal strings: `image_base`, the stack and heap sizes, file offsets, and overlay and certificate bounds. Values above 2^53 would otherwise lose precision in a JSON consumer that uses doubles.
- Digests and raw section name fields are lowercase hexadecimal.
- Raw values are preserved. `machine`, `characteristics`, `subsystem`, `dll_characteristics`, directory indexes, and certificate revision and type are not mapped to names; naming is a presentation concern and mappings drift between toolchains.
- `header.loaded_data_directory_count` and `header.loaded_section_count` are the rows actually loaded, held next to the declared COFF values.

### Section identity

Each section with a nonzero `SizeOfRawData` carries `data_sha256`, the SHA-256 of exactly the declared raw range.

- A zero raw size carries no digest. Absence is explicit, never the digest of empty bytes.
- The eight-byte name field is always emitted as `name_hex`, even when the decoded name is unavailable, so the raw field survives an undecodable name.
- `name_available` is false for an empty or invalid name; the empty `name` must not be read as "unnamed".
- Digests are cached by file range. Overlapping sections that declare the same range reuse one read.
- The whole-artifact subject digest is computed in a separate bounded pass after parsing, so it covers exactly the caller-declared size.
- Content hashing is bounded by `Options.ContentBytes`: 128 MiB by default, clamped to `MaxContentBytes` (`MaxArtifactBytes`). The reader's per-section limit still applies first.
- A section above the remaining hash budget is skipped and counted, never partially hashed. Per-entry failures are aggregated into one limitation with a count and the first reason.

### Overlay

`overlay` is `null` when the reader found no overlay. Otherwise `offset` and `size` are decimal strings for the byte range after the headers and the last section raw data.

- The adapter does not describe certificate records as overlay content; the security directory is reported under `certificates` even though the table usually lies in the overlay range.
- An overlay the reader could not bound is omitted with the reader's limitation.

### Imports and exports

Import and export tables are projected field for field, including the declared and loaded counts, per-entry `name_available`, the thunk source (`original_first_thunk` or `first_thunk`), hint and ordinal values, and forwarder availability.

- A forwarder is reported as the stored target string. The adapter never resolves or follows it.
- Ordinal thunks keep `hint` zero and an empty name with `name_available` false. A named thunk keeps its ordinal field zero and `by_ordinal` false.
- An export slot without a name keeps `name_available` false and an empty `name`; a slot with a zero RVA is still an observed slot.
- Reader limitations for unavailable, invalid, and over-limit names are copied into the record.

### Resources

The resource tree is reported as a flat list of leaves in the reader's depth-first on-disk order. Each leaf carries its full path from the type level, the declared `data_rva`, `data_size`, `code_page`, and `data_available`.

- Resource bytes are never read and never hashed. The adapter reports the declared range and whether it is file-backed.
- A path level that is a name keeps `is_name` true and `name_available` false when the UTF-16 name could not be decoded, with `id` zero. An integer level keeps `is_name` false and an empty name.
- A resolved leaf makes the record carry the unknown "resource data is not interpreted", because the schema reports bounds, not content.

### Certificates

The certificate member reports the security directory `offset` and `size` and the `WIN_CERTIFICATE` record headers: `offset`, `length`, `revision`, `type`, `data_offset`, and `data_size`.

- Certificate blobs are never read and never hashed in this schema.
- Revision and type are raw values. A non-empty table makes the record carry the unknown "certificate signatures are not validated"; presence of a record is not evidence of a valid signature, a chain, or a timestamp.
- The security directory is an RVA-shaped slot that stores a file offset. The adapter keeps the reader's interpretation and does not re-map it.

### Output bounds

| Budget | Default | Bounds |
|---|---:|---|
| variable payload bytes | 3.5 MB | 4 KiB to `MaxPayloadBytes - 64 KiB` |
| hashed content bytes | 128 MiB | `MaxArtifactBytes` |

The fixed part is charged first: the header, the data directory array, and the overlay when present. The remaining payload budget is divided by share over the tables, in this order: sections 30%, imports 30%, exports 20%, resources 10%, certificates 10%. A share is applied to the budget still unspent, so a table that uses less leaves the remainder for later tables.

When an entry does not fit, the table stops at that entry and the limitation names how many entries were omitted. Tables are prefixes in artifact order; the adapter never samples or reorders.

Import trimming is the one nested case: a module that does not fit stops the module list, and a module whose base fits but whose thunks do not keeps the thunks that fit, sets `truncated` on the module, and stops the module list. Observable omissions are counted separately as omitted modules and omitted thunks.

Every trim sets `truncated` on the affected member, and the record limitation carries the reason. `evidence.Encode` remains the final check and fails closed if a record nevertheless exceeds a limit.

### Coverage, limitations, and unknowns

Coverage is `complete` only when no limitation and no unknown was recorded. Otherwise it is `partial`. The adapter never claims `unknown`; a parse, digest, or reader failure returns an error and no evidence.

Limitations are deduplicated and come from four sources:

- the reader's header, directory, and section limitations;
- the reader's per-table limitations for imports, exports, resources, and certificates;
- the reader's truncation flags, summarized as partial coverage for the affected table;
- adapter omissions: payload trimming, the content hash budget, and unavailable or failed section digests.

A directory that returns `repe.ErrRead` aborts the observation. `repe.ErrNotFound` is silent and leaves the member `null`. Any other reader error becomes a `"<label> directory unavailable: ..."` limitation with the member left `null`.

Unknowns record structures that were observed but deliberately not decoded:

- COFF symbols, when `PointerToSymbolTable` and `NumberOfSymbols` are both nonzero;
- base relocations, debug and PDB references, TLS callbacks, bound imports, delay-load imports, and CLR metadata, each only when the corresponding data directory is non-empty;
- certificate signatures, when a certificate record is reported;
- resource data, when a resource leaf is reported.

Limitations are capped at 128 and unknowns at 32, each with a final `additional ... omitted` entry, so a malformed artifact cannot inflate the record past the evidence limits.

### Failure semantics

- Parse errors propagate with the reader sentinel intact, wrapped as `pe provider: parse`.
- A reader failure during the subject digest, payload build, or any directory read propagates with `repe.ErrRead`.
- No partial evidence is returned for an unreadable artifact.
- Payload and record failures are wrapped as `pe provider: payload` and `pe provider: record`.
- The adapter never executes, maps, unpacks, or writes artifact content, and does not depend on `debug/pe` at runtime. `debug/pe` remains a test-only differential oracle for the reader.

### Out of scope

COFF symbols, relocations, TLS, debug and PDB data, CLR metadata, bound and delay-load imports, the Rich header, Authenticode validation, unpacking, and execution are not decoded. Each is either an unknown or simply outside the schema; none is presented as an empty table.

## Testing

- A crafted one-section PE32 fixture containing imports from two modules, three export slots including a forwarder and an unnamed slot, a three-level resource tree, two certificate records, and an overlay.
- A PE32+ variant that checks the 64-bit image base, the machine value, and ordinal thunk decoding in a 64-bit thunk array.
- Tests for provider identity, subject digest, deterministic re-encoding, evidence round-trip, and `evidence.Encode` acceptance.
- Tests for absent directories (coverage `complete`), an unusable import directory that leaves exports intact, a truncated section table, a section whose name is invalid UTF-8, the content hash budget, the payload budget with import and export trimming, and the directory count limit.
- Tests for reader failures on the subject digest, an import directory, a certificate record, and section content.
- Tests for the unknown set: COFF symbols and each out-of-scope directory.
- Unit tests for budget arithmetic, collector deduplication and caps, unknown collection, digest caching, and failure aggregation.
- A fuzz target that calls `Observe` under low limits and asserts that any returned record encodes.
- Package coverage is 93.5%; the remainder is unreachable error plumbing and reader sentinels that a crafted fixture cannot reach without also failing parse.

## Consequences

- Consumers must parse `uint64` fields as decimal strings and must treat a `null` directory member as "absent or unusable", then read the limitation to know which.
- A payload may be a prefix of a reader table. `coverage: partial` plus the omission limitation is the contract, not the array length alone.
- Resource and certificate content digests are not available from this schema. A consumer that needs them must read the artifact range itself.
- Certificate presence is not a trust signal, and the schema deliberately gives no place to record one.
- CLI and MCP surfaces still do not call the adapter. A later increment wires it into a use case.
- The budget shares, the null-versus-empty rule, and the payload schema version are the contract to revisit before adding symbol, relocation, or trust views.

## Alternatives considered

- Emitting the reader's Go structs directly: rejected because it couples the wire format to internal types and their future changes.
- Empty arrays for absent directories: rejected because it makes an unreadable table look like a table the artifact does not have.
- A single `directories` member keyed by index: rejected because typed members keep per-table fields and truncation flags explicit.
- Hashing resource and certificate bytes: rejected because the reader deliberately does not read them, and hashing would add a large read for content the schema does not otherwise describe.
- Reporting certificate `revision` and `type` as named enums: rejected for the same reason as other raw values; names are presentation and can imply a trust level.
- Failing the whole observation on every directory defect: rejected because auxiliary metadata should be described, while genuine read failures still fail closed.
- Treating an unusable directory as complete: rejected because absence of evidence must not look like evidence of absence.

## See also

- [ADR 0008](0008-pe-reader.md), [ADR 0009](0009-pe-imports-exports.md), [ADR 0010](0010-pe-resources-certificates.md) for the reader.
- [ADR 0007](0007-elf-evidence-adapter.md) for the equivalent ELF projection.
- [payload-pe.md](../payload-pe.md) for the wire format.
