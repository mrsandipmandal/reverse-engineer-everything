# ADR 0004: ELF reader foundation

- Status: accepted
- Date: 2026-10-27

## Context

Phase 2 starts the first artifact reader: read-only ELF32 and ELF64 support. Later increments add sections, segments, symbols, relocations, notes, and build metadata. All of them need the same validated file header, endianness, word size, extended-numbering resolution, and bounded access to the raw section and program header tables.

ELF headers come from untrusted artifacts. A crafted count, offset, or entry size must not cause unbounded allocation, integer overflow, or a panic. The reader also has to be explicit about partial results: an artifact can be truncated, and the project intentionally caps the number of table entries it will load.

`debug/elf` is part of the Go standard library and is useful as a reference, but its parsing policy and error surface are not controlled by REE and are not a stable basis for evidence semantics.

## Decisions

### Custom parser

REE implements its own bounded reader in `internal/formats/elf` over `io.ReaderAt` plus an explicit artifact size. The standard library `debug/elf` is used only in tests as a differential oracle.

The parser never maps, executes, or writes artifact content. It reads the identifier, the fixed file header, and the complete entries of the raw section and program header tables. It does not follow section or segment contents.

Rationale:

- REE needs explicit limits, sentinel errors, and deterministic partial-result semantics;
- evidence will name raw values, so silently normalized or synthesized fields would be harmful;
- differential tests still catch ordinary decoding mistakes without making `debug/elf` a runtime dependency.

### Accepted inputs

- ELF32 and ELF64.
- Little-endian and big-endian.
- `e_ident[EI_VERSION]` and `e_version` equal to `EV_CURRENT` (1).
- `e_ehsize`, `e_shentsize`, and `e_phentsize` equal to the size implied by the class whenever the corresponding table is present.
- Section and program counts of zero, ordinary counts, and the extended forms:
  - `e_shnum == 0` with the real count in section header 0 `sh_size`;
  - `e_phnum == PN_XNUM` with the real count in section header 0 `sh_info`;
  - `e_shstrndx == SHN_XINDEX` with the real index in section header 0 `sh_link`.
- A zero section header offset with zero section count and no section name index.
- A section header table offset of zero is rejected when any section count or section name index is nonzero.

Program and section types, machines, flags, addresses, and names are preserved as raw numeric values. This layer does not assign names to them.

### Errors and partial results

Structural defects return a nil `File` and an error:

- `ErrInvalid`: bad magic, unsupported class or data encoding, unsupported version, inconsistent sizes or offsets, contradictory counts, an out-of-range section name index, or an extended value that cannot be resolved;
- `ErrTruncated`: the identifier, the fixed header, or section header 0 needed for extended numbering extends beyond the artifact end;
- `ErrLimit`: the artifact exceeds the byte limit;
- `ErrRead`: the supplied reader fails or returns fewer bytes than the declared size.

A section or program header table that extends beyond the artifact end, or whose declared count exceeds the configured limit, is not an error. The parser returns the complete entries that fit, sets `File.Truncated`, and appends a deterministic limitation string. `Header.SectionHeaderCount` and `Header.ProgramHeaderCount` remain the declared counts, so callers can distinguish "the file says 65535" from "8 entries were loaded".

This split keeps truncated downloads and intentionally capped tables usable without presenting them as complete. Header-level ambiguity still fails closed.

### Limits

| Limit | Value |
|---|---:|
| artifact bytes | 2 GiB |
| section headers | 16,384 |
| program headers | 16,384 |

`Limits` may lower each value for a caller or test. Values above the package maximum are clamped, so a caller cannot accidentally remove the allocation ceiling. Zero or negative fields select the default.

Tables are read in one bounded allocation per table: at most 16,384 entries times the 64-byte ELF64 section header or 56-byte ELF64 program header, roughly 1 MiB each. Counts are compared before multiplication, and truncated extents are clamped by available bytes, so offset arithmetic cannot overflow.

### Public API

```go
func Parse(r io.ReaderAt, size int64) (*File, error)
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*File, error)

type File struct {
    Header         Header
    SectionHeaders []SectionHeader
    ProgramHeaders []ProgramHeader
    Truncated      bool
    Limitations    []string
}
```

`SectionHeader` and `ProgramHeader` preserve the on-disk fields plus their table index. `Header` records class, data encoding, identifier version, OS ABI, ABI version, type, machine, version, entry, flags, header and entry sizes, table offsets, resolved counts, section name index, and which extended forms were used.

The artifact size is required because `io.ReaderAt` has no length. It is also the bound used for every range check.

### Testing

- Programmatically built ELF32/ELF64, little-endian/big-endian fixtures with known fields.
- Table-driven malformed-header and contradictory-count cases.
- Physical truncation and configured-limit cases.
- Reader failure and short-read cases.
- `FuzzParse`, which asserts no panic and checks count, index, and completeness invariants.
- A differential test against `debug/elf` over the crafted fixtures and, on Linux, the running test executable. The test is skipped naturally when the executable is not ELF.

Extended-numbering resolution is covered by constructed expectations rather than differential comparison. `debug/elf` requires an extended section count to be at least `SHN_LORESERVE` and does not resolve `PN_XNUM`. REE accepts the escape forms even when the resolved value could have been encoded directly, because the layout is unambiguous and defensive producers exist. The 16,384-entry cap also means that a spec-valid extended section count always produces a partial table in this phase.

Fixtures are generated in test code; no proprietary binary is committed.

## Consequences

- Phase 2 can add section names, contents, symbols, relocations, notes, and build metadata on top of one validated table representation.
- `File.Truncated` and `File.Limitations` become part of the evidence adapter's coverage and limitation reporting.
- The reader is not a sandbox. It bounds its own work, but it cannot make a malformed artifact safe for a later consumer that ignores the declared limits or lengths.
- Every new table reader added in later increments must follow the same declared-count versus loaded-count distinction.
- A future change to accepted header versions or strictness is an observable contract change and needs an ADR update.

## Alternatives considered

- Using `debug/elf` in production: rejected because parsing policy, partial-result behavior, and error identity would be outside REE's control.
- Memory-mapping the artifact: rejected for this phase because it complicates lifetime, portable bounds, and untrusted-input handling without a measured need.
- Lazy table loading: rejected for the foundation because both tables are small at the enforced limits and eager loading gives deterministic truncation reporting.
- Rejecting any truncated table: rejected because partial artifacts are a normal analysis input and the reader can describe exactly what it observed.
- Accepting arbitrary header and entry sizes: rejected because ambiguous layout weakens bounds and differential comparisons.
