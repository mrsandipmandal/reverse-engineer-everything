# ADR 0008: PE reader foundation

- Status: accepted
- Date: 2026-10-27

## Context

Phase 3 adds the second artifact reader: read-only PE32 and PE32+ support. Later increments add imports, exports, resources, certificates, and the `ree.payload.pe/1` evidence adapter. All of them need one validated DOS header, PE signature, COFF file header, optional header, data directory table, and section table.

PE headers come from untrusted artifacts. A crafted `e_lfanew`, optional header size, directory count, section count, section offset, or raw size must not cause unbounded allocation, integer overflow, or a panic. The reader must also distinguish a structurally invalid file from one that is merely truncated or capped by a configured limit.

`debug/pe` is part of the Go standard library and is useful as a reference, but its parsing policy and error surface are not controlled by REE. It also does not expose the resource directory or certificate table, which later Phase 3 increments need.

## Decisions

### Custom parser, little-endian only

REE implements its own bounded reader in `internal/formats/pe` over `io.ReaderAt` plus an explicit artifact size. `debug/pe` is used only in tests as a differential oracle.

PE artifacts are little-endian on every supported platform; there is no byte-order field to honor. The parser never maps, executes, decompresses, or writes artifact content. It reads the DOS header, the PE signature, the COFF header, the optional header, the data directories, and the complete entries of the section table. It does not follow section contents during Parse.

Rationale:

- REE needs explicit limits, sentinel errors, and deterministic partial-result semantics;
- evidence will name raw values, so silently normalized or synthesized fields would be harmful;
- differential tests still catch ordinary decoding mistakes without making `debug/pe` a runtime dependency.

### Accepted inputs

- DOS signature `MZ` at offset zero.
- `e_lfanew` at least 0x40, so the PE header cannot overlap the DOS header; a smaller value is a structural error.
- PE signature `PE\0\0` at `e_lfanew`.
- A 20-byte COFF file header.
- Optional header magic `0x10b` (PE32) or `0x20b` (PE32+).
- `SizeOfOptionalHeader` of at least the fixed PE32 size (96 bytes) or PE32+ size (112 bytes), and fully present in the artifact. A larger size is accepted and any bytes past the fixed fields are treated as data directories.
- `NumberOfRvaAndSizes` of zero or more. At most sixteen directory slots are loaded.
- `NumberOfSections` of zero or more. At most 96 section headers are loaded.
- Empty, NUL-padded, and non-empty section names. Names are UTF-8 and are truncated at the first NUL.

The parser does not require the standard optional header sizes of 224 or 240 bytes, and it does not require a nonzero section count. Object-like files with a short optional header remain readable; the declared counts simply exceed what was loaded and are reported as limitations.

Machines, characteristics, timestamps, subsystem values, alignments, and addresses are preserved as raw numeric values. This layer does not assign names to them.

### Errors and partial results

Structural defects return a nil `File` and an error:

- `ErrInvalid`: bad DOS magic, `e_lfanew` inside the DOS header, missing PE signature, optional header too small for its magic, an unsupported magic, or a nil reader or negative artifact size;
- `ErrTruncated`: the DOS header, PE signature, COFF header, optional header, or a required fixed field extends beyond the artifact end;
- `ErrLimit`: the artifact exceeds the byte limit, or a requested section read exceeds the section data limit;
- `ErrRead`: the supplied reader fails or returns fewer bytes than declared.

A section table that extends beyond the artifact end, or whose declared count exceeds the configured limit, is not an error. The parser returns the complete entries that fit, sets `File.Truncated`, and appends a deterministic limitation string. `Header.NumberOfSections` remains the declared count, so callers can distinguish "the file says 65535" from "96 entries were loaded".

A data directory count above the sixteen supported slots, above the entries physically present in the optional header, or above the configured directory limit is also not an error. The loaded directories are capped and a limitation records which bound was hit. The declaration and the loaded length stay separate. `File.Truncated` describes the section table only; directory trimming is reported through `Limitations`.

### Section names

Section names are decoded during Parse. An empty, all-NUL name yields `NameAvailable=false` with no limitation, because empty names occur in real artifacts. A name that is not valid UTF-8 also yields `NameAvailable=false`, and the parser aggregates all such entries into one limitation instead of returning replacement text. Names are never read from a string table; the eight-byte field is the whole identity.

### Section data

`SectionData` reads one section's raw bytes on demand and returns a copy. The read is all-or-nothing:

- `SizeOfRawData == 0` returns an empty slice, not an error, because a section such as `.bss` has no file bytes;
- a raw size above the section data limit returns `ErrLimit`;
- a raw range outside the artifact returns `ErrUnavailable`, so a short or missing range cannot be mistaken for complete content;
- a reader failure returns `ErrRead`;
- an index beyond the loaded table returns `ErrUnavailable` when the section was declared but not loaded, and `ErrOutOfRange` when it was never declared.

This mirrors the ELF reader's content semantics.

### RVA mapping

`MapRVA` resolves a relative virtual address through the headers region and the section table:

- an address below `SizeOfHeaders` maps to the same file offset and wins over any section match;
- otherwise the first matching section in table order wins;
- a section covers `VirtualAddress` through `VirtualAddress + max(VirtualSize, SizeOfRawData)`;
- an address in the virtual-only tail beyond `SizeOfRawData` has `FileBacked=false` and offset zero;
- a second match sets `Ambiguous` but does not change the winning mapping;
- an address outside every region returns `SectionIndex=-1` and `FileBacked=false`.

Overlapping sections are common in packed or malformed artifacts. A deterministic first-match rule keeps evidence reproducible, while `Ambiguous` preserves the uncertainty instead of hiding it.

### Overlay

The overlay is the byte range after `max(SizeOfHeaders, every section's raw end)`. It is omitted with zero offset and size, plus a limitation, when `SizeOfHeaders` exceeds the artifact or when any section with a nonzero raw size has a raw range beyond the artifact end. An overlay that cannot be bounded is not guessed.

### Limits

| Limit | Value |
|---|---:|
| artifact bytes | 2 GiB |
| section headers | 96 |
| data directories | 16 |
| one section read | 64 MiB |

`Limits` may lower each value for a caller or test. Values above the package maximum are clamped, so a caller cannot accidentally remove the allocation ceiling. Zero or negative fields select the default.

The section limit matches the Windows loader's practical ceiling. The directory limit matches the sixteen defined slots. The artifact and section read limits bound the largest allocation the reader will make for content; header allocations are bounded by the 16-bit optional header size and the section limit.

Counts are compared and clamped before multiplication or conversion to `int`. In particular, a declared directory count near `2^32` is reduced to the loaded bound before any platform-sized conversion, so 32-bit builds cannot overflow into a negative capacity.

### Public API

```go
func Parse(r io.ReaderAt, size int64) (*File, error)
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*File, error)

func (f *File) Size() int64
func (f *File) SectionData(index int) ([]byte, error)
func (f *File) DataDirectory(index int) (DataDirectory, error)
func (f *File) MapRVA(rva uint32) RVAMapping

type File struct {
    Header          Header
    DataDirectories []DataDirectory
    Sections        []SectionHeader
    OverlayOffset   uint64
    OverlaySize     uint64
    Truncated       bool
    Limitations     []string
}
```

`Header` contains the validated DOS and COFF fields plus the decoded `OptionalHeader`. `OptionalHeader` holds both PE32 and PE32+ layouts in one struct; fields absent from PE32+, such as `BaseOfData`, keep their zero value. `SectionHeader` preserves the on-disk fields plus its table index, decoded name, and raw name bytes. `DataDirectory` preserves the index, address, and size.

The artifact size is required because `io.ReaderAt` has no length. It is also the bound used for every range check.

### Testing

- Programmatically built PE32 and PE32+ fixtures with known headers, three sections, and an overlay.
- Table-driven malformed-header, bad-magic, overlap, and contradictory-size cases.
- Physical truncation, section count limit, directory count limit, and section data limit cases.
- Invalid, empty, and oversized section names; out-of-range raw section ranges.
- RVA mapping inside headers, inside raw data, inside a virtual-only tail, outside every region, and across overlapping sections.
- Reader failure and short-read cases.
- `FuzzParse`, which asserts no panic and checks declared-count, loaded-count, truncation, index, and read-length invariants.
- A differential test against `debug/pe` over the crafted fixtures, comparing the COFF header, optional header, data directories, section headers, and section data.

Resource directory and certificate fixtures are deferred to the increments that decode them. Fixtures are generated in test code; no proprietary binary is committed.

## Consequences

- Phase 3 can add imports, exports, resources, certificates, and the PE evidence adapter on top of one validated table representation.
- `File.Truncated`, `File.Limitations`, and `RVAMapping.Ambiguous` become part of the adapter's coverage and limitation reporting.
- The reader is not a sandbox. It bounds its own work, but it cannot make a malformed artifact safe for a later consumer that ignores the declared limits or lengths.
- Every new PE substructure added in later increments must follow the same declared-count versus loaded-count distinction and must treat the section table as potentially incomplete.
- A future change to accepted optional header sizes or strictness is an observable contract change and needs an ADR update.

## Alternatives considered

- Using `debug/pe` in production: rejected because parsing policy, partial-result behavior, error identity, and resource and certificate coverage would be outside REE's control.
- Memory-mapping the artifact: rejected for this phase because it complicates lifetime, portable bounds, and untrusted-input handling without a measured need.
- Loading section contents eagerly: rejected because most sections are never needed by header-level consumers and the artifact limit is much larger than the section limit.
- Requiring the standard 224/240-byte optional header: rejected because short optional headers occur in object-like artifacts and the directory count can be bounded explicitly.
- Rejecting overlapping sections: rejected because overlap is a real property of some artifacts and a deterministic mapping with an ambiguity flag preserves it better than an error.
- Inferring the overlay when a section raw range exceeds the artifact: rejected because the true end is unknown and an inferred value would be misleading.
