# ADR 0005: ELF metadata and content reads

- Status: accepted
- Date: 2026-10-27

## Context

ADR 0004 established the bounded ELF header and raw table reader. Phase 2 still needs the observations analysts actually use: section names, section and segment contents, notes, the GNU build-id, and `.comment` producer strings.

Those reads move bytes out of the artifact into caller-visible slices and strings. That changes the threat profile: a header can be small while a declared section size or note descriptor is enormous. A reader must therefore bound every read by bytes actually available and by an explicit per-observation limit, and it must distinguish "absent" from "not covered" and "malformed".

## Decisions

### Read on demand, keep the artifact position

`File` retains the `io.ReaderAt`, the declared artifact size, and the effective limits from `Parse`. Content is read per call instead of being copied eagerly during `Parse`.

Rationale:

- an artifact may contain a 64 MiB section that most callers never request;
- eager loading would multiply the header-limit budget and reduce headroom for notes;
- the reader stays usable after `Parse` without a second lifetime contract beyond the existing `io.ReaderAt` concurrency rule.

Each call returns a fresh copy. Callers may mutate what they receive without corrupting later reads.

### Content limits

| Limit | Value |
|---|---:|
| one section's data | 64 MiB |
| one segment's file data | 64 MiB |
| section string table or `.comment` section | 8 MiB |
| one section or note name | 4 KiB |
| notes across all `SHT_NOTE` sections | 4,096 |
| total note section bytes read | 4 MiB |
| one GNU build-id descriptor | 4 KiB |
| `.comment` entries | 4,096 |

Limits are fields on `Limits`, so tests and future callers can lower them. Values above the package maximum are clamped. A zero or negative field selects the default.

`Limits` is a value type. Adding fields is source-compatible for callers that use `DefaultLimits()` or a field-named composite literal; it would break unkeyed literals, which Go vet already discourages for external packages.

### Error semantics

The package keeps the four foundation sentinels and adds three content sentinels:

- `ErrOutOfRange`: the index is outside the declared table; the caller asked for something that does not exist;
- `ErrUnavailable`: the index exists but the bytes are not available, because the table is truncated, the section has no file data (`SHT_NOBITS`), or the declared range lies outside the artifact size;
- `ErrNotFound`: the metadata is absent from complete coverage, such as no `.comment` section or no GNU build-id note.

Existing sentinels are reused where they already carry the right meaning:

- `ErrLimit` for a declared length above the configured content limit;
- `ErrInvalid` for structurally invalid metadata, such as a name offset outside its string table, an unterminated name, invalid UTF-8, a wrong-typed name table, a conflicting build-id, or an empty build-id descriptor;
- `ErrRead` when the underlying reader fails.

Requesting content is all-or-nothing for sections and segments. A section whose declared range is partly outside the artifact returns `ErrUnavailable` instead of a short slice. Notes are the deliberate exception: a scan returns the notes it could decode plus `NoteSet.Truncated` and `NoteSet.Limitations`.

### Section names

`SectionName` resolves names through `Header.SectionNameIndex`. Section 0 may legitimately have an empty name. With no name table, section 0 returns `""` and other sections return `ErrUnavailable`.

Names are read only up to `NameBytes`; a NUL must appear within that window. The reader rejects invalid UTF-8 rather than substituting replacement characters, because evidence must preserve exact bytes or fail.

### Sections and segments

`SectionData` and `SegmentData` validate the declared length against the limit first, then against the artifact bounds, then read. `SHT_NOBITS` returns `ErrUnavailable` regardless of size, because there are no file bytes.

No decompression is performed. `SHF_COMPRESSED` and GNU `SHT_COMPRESSED` sections are returned as stored raw bytes. Decompression is out of scope for Phase 2 and would need its own limits and ADR.

### Notes

`Notes` scans loaded `SHT_NOTE` sections in section order and decodes entries using the artifact byte order, with 4-byte name and descriptor alignment.

- A malformed, oversized, or non-UTF-8 entry becomes a limitation and is skipped; scanning continues at the aligned next entry.
- An incomplete entry, or fewer than 12 trailing bytes, ends the section with a limitation.
- The total note section bytes read is bounded, and a section is read as a prefix of at most the remaining budget. Partial note sections are reported as truncated.
- The note count is bounded; reaching it stops the scan with a limitation.
- An incomplete section header table adds a coverage limitation before any section is read.
- Reader failures return `ErrRead` together with the notes collected so far.

`Limitations` is bounded at 64 entries; the last entry states that further limitations were omitted. This keeps malformed artifacts from producing unbounded diagnostic output.

Note descriptors are copied, so `NoteSet` does not alias artifact-backed buffers.

### GNU build-id

`BuildID` scans notes for name `GNU` and type `3`.

- Identical duplicate notes are accepted.
- A conflicting descriptor, an empty descriptor, or a descriptor above the limit is an error.
- If no build-id is found and the note scan was partial, `BuildID` returns `ErrUnavailable`, not `ErrNotFound`. Absence is only claimed under complete coverage.

This mirrors the project rule that uncertainty is recorded rather than hidden.

### `.comment`

`Comment` collects NUL-separated entries from every loaded section named `.comment`, in section and entry order. Empty entries are ignored. Entries must be valid UTF-8 and within the name limit; the total entry count is bounded.

An incomplete section table with no `.comment` found returns `ErrUnavailable` instead of `ErrNotFound`.

### Testing

- Crafted ELF32/ELF64, little-endian/big-endian metadata fixtures covering names, contents, notes, build-id, `.comment`, and `SHT_NOBITS`.
- Limit, range, reader-failure, malformed-note, invalid-UTF-8, and truncation cases.
- `FuzzParse` now also calls every content method under low content limits, asserting no panic.
- A differential fixture is added to the `debug/elf` comparison for names and section/segment classification.
- `debug/elf` does not resolve notes or build-id the way REE does, so those expectations are constructed rather than differential.

## Consequences

- Callers must check `ErrUnavailable` and `NoteSet.Truncated` before claiming an artifact lacks metadata.
- Content reads can fail after `Parse` succeeds; evidence emission must treat a failed read as an explicit limitation, not as empty data.
- The limits table is now the contract to revisit before adding decompression, symbols, or relocations.
- Note and `.comment` decoding reject invalid UTF-8. A later requirement to carry arbitrary bytes needs a byte-oriented API rather than relaxing this one.

## Alternatives considered

- Eager loading of section, segment, note, and comment data during `Parse`: rejected because it front-loads allocation and couples unrelated failure modes to header parsing.
- Returning short slices for out-of-range sections and segments: rejected because a short slice is easy to mistake for complete data.
- Treating every malformed note as a fatal error: rejected because notes are auxiliary metadata and a single bad entry should not hide the rest.
- Using `debug/elf` note and symbol helpers: rejected for the same reasons as ADR 0004; parsing policy and error identity must stay under REE control.
- Decompressing compressed sections now: rejected as out of scope; it needs its own bounds and failure semantics.
