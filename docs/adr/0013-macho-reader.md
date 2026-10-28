# ADR 0013: Mach-O reader foundation

- Status: accepted
- Date: 2026-10-28

## Context

Phase 5 adds the third artifact reader: read-only Mach-O and universal binary support. Later increments add dylibs, build metadata, symbols, code signing headers, and the `ree.payload.macho/1` evidence adapter. All of them need one validated thin header, one validated universal header, a bounded load command table, and a bounded segment and section table.

Mach-O headers come from untrusted artifacts. A crafted magic, command count, command size, section count, or fat slice offset must not cause unbounded allocation, integer overflow, or a panic. The reader must also distinguish a structurally invalid header from one that is merely truncated or capped by a configured limit, and it must not let one broken architecture in a universal binary hide the others.

The Go standard library has no Mach-O reader, so there is no differential oracle to follow. `debug/macho` does not exist; the `macho` package that ships with Go covers only the formats the toolchain consumes and does not expose the load command stream. REE therefore owns the policy entirely.

## Decisions

### Package boundary and API

The reader lives in `internal/formats/macho` and exposes:

- `Parse(io.ReaderAt, size)` and `ParseWithLimits(io.ReaderAt, size, Limits)`;
- `Artifact` for a whole artifact and `Slice` for one image inside it;
- `File` for one parsed image, with `Header`, `Commands`, `Segments`, and `Sections`;
- `SectionData(index)` for a bounded on-demand read.

A thin artifact is represented as an `Artifact` with exactly one `Slice` at offset zero, so a caller never branches on thin versus universal at the top level. `Artifact.Fat` and `Artifact.Magic` still report which header was found.

### Magic and byte order

Every Mach-O variant is accepted and normalized: the 32-bit and 64-bit magics in both byte orders, the 32-bit and 64-bit universal (`FAT_MAGIC`, `FAT_MAGIC_64`) headers in both byte orders. `Header.Magic` reports the canonical `Magic32` or `Magic64`, and `Header.Data` reports the byte order, so a consumer never has to re-derive either from raw bytes.

Reported magic values are canonical. A little-endian image stores the bytes `0xce 0xfa 0xed 0xfe`, which are reported as `Magic32`; the raw swap values stay unexported.

A universal header declares the byte order of the header itself, not of the images it lists. Each image is parsed with its own magic, so a universal binary may mix byte orders and architectures.

### Header validation

The 32-bit header is 28 bytes and the 64-bit header is 32 bytes; the extra 64-bit field is reported as `Header.Reserved`. A header shorter than its fixed size is `ErrTruncated`.

`NumberOfCommands * 8` must not exceed `SizeOfCommands`. A load command is at least eight bytes, so a header that contradicts that rule is structurally invalid (`ErrInvalid`) and yields no artifact. A `SizeOfCommands` that extends beyond the image end is truncation, not invalidity: the table is read to the image end and the file records a limitation.

### Load command walk

The load command table is read into one buffer of at most `Limits.LoadCommandBytes` and walked in order.

- A command size below eight bytes, not a multiple of four, or extending beyond the table stops the walk and records a truncation limitation. The commands already loaded remain available.
- An unknown command is preserved as `LoadCommand{Command, Size}`. The reader never fails on a command it does not decode; naming and semantics are a later layer's concern.
- After the walk, declared-but-unreached commands and unclaimed trailing bytes each produce a truncation limitation, so a table that does not add up never looks complete.
- Only `LC_SEGMENT` and `LC_SEGMENT_64` are decoded in this increment. Every other command is reported raw and left to the increment that owns it.

Decoding a command that a later increment owns would freeze its field interpretation before that decision is made, and would make the foundation increment larger than its review can justify.

### Segments and sections

`LC_SEGMENT` and `LC_SEGMENT_64` carry the segment name, the VM range, the file range, protections, flags, and a section list. The reader copies every field and records both the declared section count and the records actually loaded.

- The segment and section name fields are fixed sixteen bytes, NUL padded. A name is decoded only when the bytes before the first NUL are non-empty and valid UTF-8. `NameAvailable` reports that, and the raw field stays in `NameBytes`.
- An empty name is reported as unavailable without a limitation: many sections are legitimately unnamed. Invalid UTF-8 increments one counter and produces one aggregated limitation, so a crafted image cannot inflate the list past its table size.
- A section whose declared range escapes the slice, or a segment whose file range does, is counted and reported as one aggregated limitation. The range is preserved as declared; the reader does not repair it.
- A segment command shorter than its fixed header is a limitation on that command, and its sections are not decoded.
- Section records are numbered across the whole image, so `Section.Index` is a stable handle for `SectionData`. `Segment.FirstSection` and `Segment.SectionCount` describe each segment's window into that list.

### Section content

`SectionData` returns the stored bytes of one loaded section.

- A zero-length section returns an empty slice without a read.
- A section above `Limits.SectionDataBytes` returns `ErrLimit`.
- A range outside the slice returns `ErrUnavailable`; it is never clamped or partially read.
- The bytes are returned as stored. Nothing is decompressed, relocated, decrypted, or applied. Mach-O has no section-level compression, but fat slices and code signing can describe content the reader does not touch, and the contract says so explicitly.

### Universal binaries

A universal header is eight bytes followed by one entry per architecture: 20 bytes for `FAT_MAGIC`, 32 bytes for `FAT_MAGIC_64`. Each entry carries a CPU type and subtype, a file offset, a length, and an alignment exponent.

- A zero slice count is `ErrInvalid`.
- A slice count above `Limits.FatSlices` is `ErrLimit`. A universal header may legitimately list a handful of architectures, never dozens; a large count is a malformed file, not a table to trim.
- An architecture table that extends beyond the artifact is `ErrTruncated`; without the table there is no artifact to describe.
- An entry with a zero length is `ErrInvalid`; an entry whose range escapes the artifact is `ErrTruncated`.
- A slice that fails validation or parsing is kept as a `Slice` with a nil `File` and a sentinel-wrapped `Err`, and the artifact gains one limitation naming the slice. The remaining slices still parse. An artifact with no parsable slice returns `ErrInvalid`.

Silently dropping a broken slice would let a universal binary look like the architectures that happened to parse. Failing the whole artifact on one slice would hide good evidence from the other architectures. The per-slice error keeps both facts.

### Limits

| Limit | Default | Scope |
|---|---:|---|
| artifact bytes | 2 GiB | whole artifact |
| fat slices | 32 | universal header |
| load commands | 4,096 | one image |
| load command bytes | 4 MiB | one image |
| segments | 256 | one image |
| sections | 4,096 | one image |
| section content | 64 MiB | one `SectionData` call |

`Limits.withDefaults` replaces a non-positive field with the package default and clamps a higher value to the package maximum. A caller can lower a bound but cannot raise it. The values follow the PE reader so that an operator meets one size vocabulary across formats.

Count limits produce a truncation limitation and stop loading that table; they never present a capped table as complete. Only one limitation is recorded per table even when several commands would exceed the same limit.

### Coverage contract

`File.Truncated` reports an incomplete load command or section table. `File.Limitations` reports, in deterministic order, every reason the loaded view is incomplete: table truncation, count limits, declarations that do not fit, unusable names, and out-of-slice ranges. A clean image has `Truncated` false and no limitations.

`Artifact.Truncated` and `Artifact.Limitations` describe universal-header defects and slices that could not be parsed. A universal artifact is not truncated merely because one slice failed; that is an availability limitation, not a missing table.

### Out of scope

This increment does not decode dylibs, `LC_UUID`, build versions, entry points, symbols, relocations, exports tries, chained fixups, code signing blobs, Objective-C metadata, entitlements, dyld shared caches, or ARM64e pointer authentication. It does not execute, map, decompress, or write artifact content, and it does not depend on any third-party parser.

## Testing

- Crafted 64-bit and 32-bit images with one segment, two sections with content, and one unknown load command.
- A big-endian 32-bit image, a header-only image with no commands, and a command table made only of unknown commands.
- Universal binaries with 32-bit and 64-bit headers, both byte orders, one and two slices, a bad slice beside a good one, and an all-bad artifact.
- Table defects: zero and unaligned command sizes, a command beyond the table, trailing bytes, a declared table larger than the artifact, and load command, segment, and section count limits.
- Name cases: invalid UTF-8, empty, and a full sixteen-byte name; range cases: a section and a segment that escape the slice.
- `SectionData` cases: normal content, zero length, over-limit length, out-of-slice range, negative and large indexes, and a nil receiver.
- `readAt` bounds, short-read, and reader-failure cases.
- Limit defaulting and clamping.
- A fuzz target with lowered limits that asserts any returned artifact is self-consistent: every slice range inside the artifact, file size equal to the slice size, truncation paired with a limitation, count limits respected, and no panic on `SectionData`. 20 seconds of fuzzing executed 1,374,989 inputs.
- Package coverage is 94.4%.

## Consequences

- Consumers parse `Header.Magic` and `Header.Data` instead of guessing from raw bytes, and treat an empty `Name` as "not decoded" unless `NameAvailable` is set.
- A trimmed table is visible through `Truncated` and a limitation; a consumer that reads only the array length can still understate the artifact.
- A universal binary is one artifact with several images. The evidence adapter must decide payload shares across slices rather than treating each slice as a separate record.
- `SectionData` on a slice-bounded reader cannot escape the slice, so a caller does not need to re-check offsets.
- The package is unused by the CLI and MCP surface until the provider and the analysis wiring land.

## Alternatives considered

- A separate `ParseFat` returning a different type: rejected because every caller would branch on thin versus universal, and the analysis surface must produce one record per artifact either way.
- Failing the whole universal artifact on one broken slice: rejected because it hides good evidence.
- Trimming a fat architecture table above the limit: rejected because a large slice count is malformed rather than merely large, and trimming it would present a partial multi-architecture view as the whole.
- Decoding every load command in the foundation increment: rejected because it moves later decisions into an earlier review and inflates the increment.
- Reproducing `debug/macho`-style named constants for every CPU type and file type: rejected for now; raw values are stable, and naming is presentation.
- Treating a name field without a NUL as invalid: rejected because macOS stores full sixteen-byte names, and those are decodable.
- Reading segment content instead of section content: rejected because sections are the stable unit the provider can describe and hash, and a segment range includes padding.
