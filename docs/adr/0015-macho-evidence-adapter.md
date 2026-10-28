# ADR 0015: Mach-O evidence adapter

- Status: accepted
- Date: 2026-10-28

## Context

ADR 0013 and ADR 0014 gave `internal/formats/macho` a bounded read of thin Mach-O and universal binaries: validated headers, load commands, segments and sections, dylibs, build metadata, entry points, symbols, and code signature headers. Phase 5 still needs the step that turns that read into project evidence: a deterministic `ree.payload.macho/1` payload inside a `ree.evidence/1` record, with explicit coverage, limitations, and unknowns.

The PE adapter in `internal/providers/pe` and ADR 0011 set the pattern: one record per artifact, a subject digest over the artifact bytes, a payload budget with fair shares, absence signalled by null rather than by an empty list, and unknowns for every structure the adapter observes but does not decode.

Mach-O adds one property PE does not have: a universal binary may carry several images, each with its own header, byte order, and architecture. The adapter has to decide whether that is one record or several before it can define a subject digest, a payload shape, or a budget.

The artifact is untrusted. A crafted universal header, dylib name, symbol table, or signature superblob must not inflate the record, exhaust memory, or make the payload claim more than the reader proved.

## Decisions

### One record per artifact, slices inside the payload

`Observe` takes an `io.ReaderAt` and a size and returns one evidence record. `subject.sha256` covers exactly those bytes, including a universal header and every slice it contains.

A universal binary is therefore one record whose `slices` list has one entry per architecture. Each slice carries its own status, header, segments, sections, dylibs, build metadata, entry point, symbols, signature headers, and limitations.

- A per-slice record would need a composite subject digest that no consumer could recompute from the file, and it would break the analysis surface's one-artifact-one-record contract.
- Reporting only the first slice would hide the other architectures, which is exactly the material a reverse engineer needs in order to see what a universal binary contains.
- A thin artifact is represented as one slice at offset zero, so a consumer never branches on thin versus universal at the top level.

### Slice status and per-slice failures

Every slice reports `status`: `parsed`, or the sentinel that stopped parsing (`invalid`, `truncated`, `limit`, `unavailable`, `read`).

A slice that cannot be parsed keeps its entry, records the reader error text in its own `limitations`, and adds one deduplicated record limitation. The record still succeeds as long as the artifact header parsed and the subject digest could be read.

Only a reader failure (`ErrRead`) fails the observation. A read failure means the record would understate the artifact without saying so, so it is not converted into a limitation.

### Budget

The payload budget defaults to 3,500,000 bytes, is clamped to at least 4 KiB, and stops 64 KiB below `evidence.MaxPayloadBytes` so the record envelope and canonicalization still fit.

The artifact envelope is charged first. Each slice then receives an equal share of what remains, and inside a slice the tables take shares of the slice allowance: segments 20, sections 30, dylibs 20, symbols 20, signature blobs 10.

- Equal shares across slices keep one heavy architecture from consuming the whole budget and leaving the others with a header only.
- Inside a slice, sections and symbols are the largest and most variable tables, so they receive the largest shares.
- A table that does not fit stops at the last entry that does, sets its own `truncated` flag, and adds one limitation naming the omitted count. A consumer can therefore distinguish a short table from a complete one.
- Fixed members (artifact, header, build, entry) are reserved rather than shared, because dropping them would make the slice unreadable.

### Absence, unusability, and emptiness

A payload member is null only when the artifact does not declare it. `dylibs`, `build`, `entry`, `symbols`, and `code_signature` are null when the corresponding load command is absent, and `install_name` is absent when there is no `LC_ID_DYLIB`.

Absence is not a limitation: an object file with no dylib command is complete, not truncated. A malformed command is a limitation, and a reader failure is an error.

Lists that are present but empty are emitted as empty arrays, never null, so a consumer does not have to distinguish "no data" from "no table".

### Naming

`magic_name`, `byte_order`, `file_type_name`, `command_name`, `kind`,
`platform_name`, and `tool_name` are short lowercase or canonical strings derived from the reader's raw values. Unknown values map to an empty string and keep the raw number, so a new platform or command still appears in the payload without a schema change.

Text comes only from reader-validated UTF-8 names. A name that is not available is reported through its `name_available` flag, with the raw fixed-width field available as `name_hex`. Nothing is repaired, trimmed, or guessed.

### Code signature

Only the signature range, the `CSMAGIC_EMBEDDED_SIGNATURE` superblob header, the blob index, and each blob header are projected.

No signature, certificate chain, or entitlement is validated or decoded, and the adapter adds `code signatures are not validated` and `entitlements are not decoded` to the unknowns whenever a signature is present. This mirrors the PE certificate decision in ADR 0010 and ADR 0011: presence is a fact about the file, not a trust signal.

### Section content

`data_sha256` is computed from the stored bytes of the section, bounded by a content budget that defaults to 128 MiB.

- A zero-length section has no digest.
- Sections that describe the same file range share one digest and one budget charge.
- The digest is computed only for an entry that already fits the payload budget, so a dropped entry never spends content budget.
- An over-budget or unavailable range is counted and reported in one aggregated limitation; a reader failure fails the observation.
- Nothing is decompressed, relocated, or interpreted.

### Limitations and unknowns

Record limitations are deduplicated, ordered by first occurrence, and capped at 128 entries with `additional limitations omitted` as the last entry. Unknowns are capped at 32 with `additional unknowns omitted`.

Unknowns name what the adapter observes but deliberately does not decode: dyld info and export tries, chained fixups, section relocations, Objective-C metadata, ARM64e pointer authentication, signature validation, and entitlements. Each is added only when the artifact actually contains the structure.

`coverage` is `complete` only when the finished record has no limitation and no unknown; otherwise it is `partial`.

### Limits

| Limit | Default | Scope |
|---|---:|---|
| payload bytes | 3,500,000 | variable payload, clamped to [4 KiB, 4 MiB − 64 KiB] |
| content bytes | 128 MiB | section bytes hashed for digests |
| record limitations | 128 | one record |
| record unknowns | 32 | one record |

Reader limits are unchanged and remain caller-configurable through `Options.Limits`; the adapter does not raise them.

### Validation

The adapter validates its own output with `evidence.Encode` before returning, so a payload that would fail the contract is an error rather than a malformed record.

## Testing

- A thin 64-bit dylib with a segment, two sections with content, and no metadata commands: header, segment, section, and digest projection.
- A thin image with every projected command: dylibs with install name, build version with tools, entry point, symbols, and a two-blob signature, plus the signature and entitlement unknowns.
- A legacy `LC_VERSION_MIN_MACOSX` image: `platform_available` false and an empty platform name.
- A universal binary with one good and one unparsable slice: statuses, loaded slice count, slice limitation, record limitation, and partial coverage.
- Absent metadata: every optional member null and coverage complete.
- Budget cases: payload trimming with an omission limitation, content-budget omission, per-table omission for segments, sections, dylibs, symbols, and signature blobs, and a build-tool count limit.
- Option clamping, missing provider version, invalid artifact, nil reader, and reader failure.
- Determinism: two observations of the same bytes produce identical payloads and identical sealed records.
- Unit tests for the budget arithmetic, the collector caps, the naming tables, and the table-error policy.
- `FuzzObserve` with lowered reader, payload, and content limits asserts that no input panics, every record seals, the payload decodes, the slice count matches the artifact, and the loaded slice count matches the parsed headers. Coverage is 92.9%.

## Consequences

- Consumers get one record per file, so a bundle of records is a bundle of artifacts, not a bundle of architectures.
- A universally-built binary reports every architecture in one place, and a broken slice is visible instead of silent.
- A null optional member means "not declared"; an empty array means "declared, empty"; a `truncated` flag and a limitation mean "declared, not all loaded". Three distinct facts stay distinct.
- Names are never repaired. A consumer that needs a name must check `name_available` and may fall back to `name_hex`.
- Code signature presence cannot be read as trust, and entitlements need a later increment and an explicit decision.
- The payload is bounded independently of the artifact size, so a large binary yields a partial but honest view rather than an oversized record.

## Alternatives considered

- One record per slice: rejected because the subject digest would no longer be recomputable from the artifact and because the analysis surface is defined per artifact.
- Reporting only the first slice: rejected because it hides the other architectures.
- Failing the whole record on one broken slice: rejected because it discards good evidence from the remaining architectures.
- Converting a reader failure into a limitation: rejected because the record would then claim a partial view of bytes it could not read at all.
- A flat payload with architecture-prefixed members: rejected because it loses the per-slice header, limitations, and status that a universal binary needs.
- Sharing the payload budget equally across tables instead of per slice: rejected because one heavy architecture could take the entire budget.
- Hashing every section before the payload budget is applied: rejected because a dropped entry would still spend content budget.
- Reporting a digest for an empty section: rejected because an empty range has no content and a digest would suggest it does.
- Naming every Mach-O command, platform, and file type with upstream constants: rejected for now; raw values are stable, and an empty name plus the raw number is honest about a value the adapter does not know.
- Treating a signature as a trust or validity signal: rejected; that is a separate decision with its own evidence and its own false-positive risk.
