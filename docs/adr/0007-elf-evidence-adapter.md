# ADR 0007: ELF evidence adapter and payload schema

- Status: accepted
- Date: 2026-10-27

## Context

ADR 0004 to ADR 0006 established a bounded, read-only ELF reader in `internal/formats/elf`. The evidence core from Phase 1 (`ree.evidence/1`) records an observation as a subject digest, a provider identity, authority, coverage, limitations, unknowns, and a canonical JSON payload with its own integrity digest.

Phase 2 needs the projection between them: a deterministic payload for an ELF observation, and an honest mapping from reader truncation, limitations, and out-of-scope structures into evidence coverage. The adapter must not turn an unavailable value into an empty one, must not exceed the evidence record limits, and must stay read-only.

## Decisions

### Package and provider identity

The adapter lives in `internal/providers/elf` and exposes `Observe(io.ReaderAt, size, Options)`.

- `provider.id` is `builtin.elf` and `provider.profile` is `default`. Both are fixed constants: they identify the built-in reader and its only analysis profile, not the artifact.
- `provider.version` is required from the caller as `Options.ProviderVersion`. The library does not import the CLI version package, so a caller can record the build that produced the evidence without coupling the provider to one release path.
- Authority is always `observed`. The adapter reports structures it read; it does not infer behaviour.
- A missing `ProviderVersion` fails with `ErrOptions` instead of emitting an unversioned record.

### Payload schema

The payload is `ree.payload.elf/1`, documented in [payload-elf.md](../payload-elf.md).

- Every table member is always present, using an empty array when the artifact has no such structure. `build_id` is present as `null` when there is no build-id.
- Fixed-width ELF fields that JSON represents exactly (`uint8`, `uint16`, `uint32`, and program header flags) stay JSON numbers.
- `uint64` ELF fields are decimal strings. Values above 2^53 would otherwise lose precision in a JSON consumer that uses doubles, and a digest or address that silently changes is worse than a string.
- The signed `r_addend` is a signed decimal string for the same reason.
- Digest fields, note descriptors, and the build-id are lowercase hexadecimal.
- Raw numeric values are preserved. The adapter does not map `e_type`, `e_machine`, section types, or relocation types to names, because names are a presentation concern and mappings drift between toolchains.

### Content identity

Each section and segment with file bytes carries `data_sha256`, the SHA-256 of exactly the declared range.

- `SHT_NOBITS` sections and zero-length ranges carry no digest. Absence is explicit, never the digest of empty bytes.
- Digests are cached by file range. A loadable segment that covers the same bytes as a section reuses one digest instead of reading the artifact twice.
- The whole-artifact subject digest is computed in a separate sequential pass after parsing, so it covers exactly the caller-declared size even when the reader only touched part of the artifact.
- Content hashing is bounded by `Options.ContentBytes`: 128 MiB by default, clamped to `MaxContentBytes` (`MaxArtifactBytes`). The reader's per-section and per-segment limits still apply first.
- A range above the remaining hash budget is skipped and counted, not partially hashed. Per-entry failures are aggregated into one limitation with a count and the first reason.

### Notes and build-id

- A note carries its descriptor size, the descriptor's SHA-256, and its hexadecimal bytes only when the descriptor is at most 4 KiB. One large note therefore cannot exceed the evidence string limit.
- The GNU build-id is a separate `build_id` member. It is `null` when the artifact has none, and a limitation is recorded when the reader cannot prove absence.
- A build-id above the reader limit is not emitted; the limitation from the reader is carried into the record.

### Output bounds

Evidence limits are enforced by `ree.evidence/1`, so the adapter bounds the payload before handing it over.

| Budget | Default | Bounds |
|---|---:|---|
| variable payload bytes | 3.5 MB | 4 KiB to `MaxPayloadBytes - 64 KiB` |
| hashed content bytes | 128 MiB | `MaxArtifactBytes` |

The fixed header is charged first. The remaining payload budget is divided by share over the tables, in this order: sections 25%, segments 10%, symbols 30%, relocations 25%, notes 5%, comments 5%. A share is applied to the budget still unspent, so a table that uses less leaves the remainder for later tables.

When an entry does not fit, the table stops at that entry and the limitation names how many entries were omitted. Tables are prefixes in artifact order; the adapter never samples or reorders. `evidence.Encode` remains the final check and fails closed if a record nevertheless exceeds a limit.

### Coverage, limitations, and unknowns

Coverage is `complete` only when no limitation and no unknown was recorded. Otherwise it is `partial`. The adapter never claims `unknown`; a parse, digest, or reader failure returns an error and no evidence.

Limitations come from three sources and are deduplicated:

- the reader's table and metadata limitations;
- adapter omissions: payload trimming, content budget, unavailable or failed digests, unreadable names, and unavailable build-id or `.comment` data;
- the reader's own truncation flags, summarized as partial coverage for the affected table.

Unknowns record structures that were observed but deliberately not decoded:

- symbol versioning sections (`SHT_GNU_versym`, `SHT_GNU_verneed`, `SHT_GNU_verdef`);
- `SHT_DYNAMIC` entries and needed libraries;
- compressed sections, whose contents are returned as stored bytes;
- relocations without an explicit addend, whose value lives at the relocated location.

Limitations are capped at 128 and unknowns at 32, each with a final `additional ... omitted` entry. Per-entry failures are aggregated before that cap so a malformed artifact cannot flood the record.

### Failure semantics

- Parse errors propagate with the reader sentinel intact, wrapped as `elf provider: parse`.
- A reader failure during the subject digest, payload build, or any table read propagates with `reeelf.ErrRead`.
- No partial evidence is returned for an unreadable artifact. A partially readable artifact still produces evidence only when every required read completed and the omission is described by a limitation.
- The adapter never executes, maps, decompresses, or writes artifact content, and does not depend on `debug/elf`.

## Testing

- A crafted ELF64 little-endian fixture with a loadable segment, `.text`, a build-id note, two `.comment` entries, a symbol table, and an explicit-addend relocation section.
- Tests for the complete payload shape, provider identity, subject digest, deterministic re-encoding, evidence round-trip, and the shared section and segment digest.
- Tests for the stored-addend relocation layout and its unknown, content-budget omission, payload-budget prefix trimming, oversized note descriptors, truncated section tables, an unreadable per-table read, an unreadable subject digest, a non-ELF artifact, and a missing provider version.
- Unit tests for budget arithmetic, collector deduplication and caps, unknown collection, failure aggregation, and exhausted-budget table building.
- A fuzz target that calls `Observe` under low limits and asserts that any returned record encodes.
- Package coverage is 97.8%; the remainder is unreachable error plumbing and an unrepresentable JSON marshal failure.

## Consequences

- Consumers must parse `uint64` fields and addends as decimal strings, and must treat a missing `data_sha256` as "not hashed", not as empty content.
- A payload may be a prefix of the reader's tables. `coverage: partial` and the omission limitation are the contract, not the array length alone.
- Dynamic entries, needed libraries, symbol versions, and `SHT_REL` addends are not available from this schema. Phase 2 evidence can name the reference but not resolve it.
- The schema does not expose per-table omission counts directly; the limitation text carries them.
- CLI and MCP surfaces still do not call the adapter. A later phase wires it into a use case.
- The budget shares and the payload schema version are the contract to revisit before adding dynamic, versioning, or relocation-target views.

## Alternatives considered

- Emitting the reader's Go structs directly: rejected because it couples the wire format to internal types, their field names, and their future changes.
- Base64 section contents: rejected because it would multiply the record size for data a consumer can read from the artifact by range.
- JSON numbers for `uint64` fields: rejected because a consumer using IEEE-754 doubles silently changes large addresses, flags, and info words.
- Dropping a whole table when it does not fit: rejected because a prefix in artifact order is more useful and easier to reason about than an all-or-nothing table.
- Treating an unavailable digest or name as an empty value: rejected for the same reason as ADR 0005: absence of evidence must not look like evidence of absence.
- Failing the whole observation on every per-entry defect: rejected because auxiliary metadata should be described, not hidden, while genuine read failures still fail closed.
