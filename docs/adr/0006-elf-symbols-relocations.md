# ADR 0006: ELF symbols and relocations

- Status: accepted
- Date: 2026-10-27

## Context

ADR 0004 and ADR 0005 established the bounded ELF header, table, content, and metadata reader. Phase 2 still needs the two structures analysts use to relate code, data, and references: symbol tables and relocation sections.

Both are index-bearing. A symbol table entry names a section through `st_shndx`, and a relocation entry names a symbol through the packed `r_info` field. Decoding them requires the artifact word size and byte order, and a crafted entry count or string offset must not cause unbounded allocation, an out-of-range slice, or a panic.

Symbol names come from a linked string table. Unlike section names, one string table can serve a table of hundreds of thousands of symbols, and the same table may be shared by `SHT_SYMTAB` and `SHT_DYNSYM`. The reader therefore needs a string-table byte budget in addition to the per-section content limit.

Relocations come in two layouts. `SHT_RELA` stores an explicit signed addend. `SHT_REL` stores the addend at the relocated location, which the reader would have to fetch and interpret using the target section's address and the artifact type. That is a different operation with its own failure modes, so it is deliberately out of scope for this increment.

## Decisions

### Symbols include the null entry

`Symbols` scans every loaded `SHT_SYMTAB` and `SHT_DYNSYM` section in section order and returns a flat `SymbolSet`. Each `Symbol` records `TableIndex` (the section header index of its table) and `Index` (the position within that table).

The null symbol at index 0 is included. This keeps `Index` equal to the raw table index, so a relocation's `SymIndex` can be resolved without an off-by-one adjustment. `debug/elf` omits the null entry for historical compatibility; the differential test accounts for that.

An empty `SymbolSet` with no limitations means the artifact has no symbol table sections. A partially loaded section header table always adds a coverage limitation, so absence is not claimed from incomplete coverage.

### Symbol names

Names are resolved through the symbol table's `sh_link` string table:

- `sh_link == 0` means no linked string table and adds a limitation;
- a link outside the loaded section table adds a limitation;
- a linked section that is not `SHT_STRTAB` adds a limitation;
- a string table above the per-table limit or above the remaining per-call budget adds a limitation and is not read.

A name is accepted only when a NUL appears within `NameBytes` and the bytes are valid UTF-8. Names are not normalized. A rejected name leaves `Name` empty and keeps `NameOffset` intact. Name failures are aggregated into one limitation per symbol table rather than one per symbol, so a malformed string table cannot flood the output.

The null symbol and a symbol with `st_name == 0` both resolve to the empty name when the string table is usable. That is correct: offset 0 points at the string table's leading NUL.

### Extended section indexes

When `st_shndx == SHN_XINDEX` (`0xffff`), `Symbols` looks for a loaded `SHT_SYMTAB_SHNDX` section whose `sh_link` names the same symbol table.

- A table with an entry size other than 4 adds a limitation and is not used.
- The index table is read up to the number of decoded symbols and the artifact bounds.
- A resolved entry sets `SectionIndex` and `ExtendedSectionIndex = true`.
- An unresolved entry leaves `SectionIndex` at `0xffff` and `ExtendedSectionIndex = false`, and contributes to an aggregated limitation.

`SHN_UNDEF`, `SHN_ABS`, `SHN_COMMON`, and processor-specific values are preserved as raw numbers. The reader does not reinterpret them.

### Relocations

`Relocations` scans every loaded `SHT_REL` and `SHT_RELA` section in section order.

- `Offset` is the raw `r_offset`. Its meaning depends on whether the object is relocatable or executable, and the reader does not convert it.
- `Info` is the raw `r_info`.
- `SymIndex` and `Type` are the decoded fields, using the 32-bit split (8/24 or 8/8) for ELF32 and the 64-bit split (32/32) for ELF64.
- `TargetSectionIndex` is the raw `sh_info`, which normally names the section the relocations apply to. It is zero for some dynamic relocation sections.
- `SHT_RELA` sets `HasAddend` and stores the signed `r_addend` in `Addend`. ELF32 addends are sign-extended from 32 bits.
- `SHT_REL` leaves `HasAddend = false` and `Addend = 0`. The stored addend is not inferred.

Implicit addend resolution is not implemented. It would need the target section's file bytes, the symbol's address, and artifact-type-specific semantics, and it would turn a structural read into an interpretation. Evidence must not claim an addend for `SHT_REL`.

### Limits

| Limit | Value |
|---|---:|
| symbol tables scanned | 64 |
| symbols across all tables | 262,144 |
| symbol string bytes per call | 32 MiB |
| one symbol string table | 8 MiB (`StringTableBytes`) |
| one symbol name | 4 KiB (`NameBytes`) |
| relocation sections scanned | 4,096 |
| relocations across all sections | 262,144 |

Limits are fields on `Limits`. Zero or negative values select the default; values above the package maximum are clamped. The symbol string budget is charged once per table read, so two tables that share a string table consume it twice. That mirrors what the reader actually allocates and keeps the accounting simple.

### Error semantics

The per-table policy stays non-fatal:

- a wrong entry size, non-multiple size, out-of-range offset, unavailable string table, unusable string table type, or unresolved extended index becomes a limitation and the rest of the scan continues;
- a symbol table that cannot be read at all is skipped with a limitation;
- name and extended-index failures are counted and reported per table;
- reaching a configured count limit stops the scan and reports how many entries were loaded.

A reader failure propagates as `ErrRead` together with the entries collected so far. `Truncated` on `SymbolSet` and `RelocationSet` means at least one entry, name, or index is missing or partial; it is not limited to physical truncation.

`Limitations` uses the shared cap of 64 entries. The final slot reads `additional limitations omitted`.

## Testing

- Crafted ELF32 and ELF64 fixtures in both byte orders with `SHT_SYMTAB`, `SHT_DYNSYM`, `SHT_SYMTAB_SHNDX`, `SHT_RELA`, and `SHT_REL`, including a resolved extended index and a negative addend.
- Tests for no string table, wrong string table type, string table not loaded, name offset outside the table, invalid UTF-8, unterminated names, the name limit, the string-table limit, the per-call string budget, missing or malformed `SHT_SYMTAB_SHNDX`, entry-size mismatches, trailing bytes, empty tables, artifact truncation, reader failures, and an incomplete section header table.
- Relocation tests cover both layouts, both classes, both byte orders, signed ELF32 and ELF64 addends, `sh_info` propagation, count limits, entry-size mismatches, trailing bytes, empty sections, truncation, and reader failures.
- `FuzzParse` calls `Symbols` and `Relocations` under low limits and asserts no panic.
- Differential tests compare every decoded symbol against `debug/elf` for the crafted fixtures and any target with symbol tables, skipping the null entry and the section index of resolved `SHN_XINDEX` entries because `debug/elf` does not resolve them.
- `debug/elf` has no exported relocation reader, so relocations use constructed expectations.

## Consequences

- `Symbol.Name == ""` is ambiguous on its own: it can be the null symbol, a legitimate empty name, or an unavailable name. Callers must inspect `NameOffset`, `Truncated`, and `Limitations` before treating it as data.
- Consumers must not resolve a relocation's `SymIndex` against the flat `SymbolSet` without matching `TableIndex`; index spaces are per table.
- Symbol versioning (`.gnu.version`, `.gnu.version_r`), symbol libraries, and dynamic loading semantics remain out of scope.
- `SHT_REL` addends and relocation application remain out of scope. Evidence can describe the reference but not the resolved value.
- The limits table is the contract to revisit before adding versioning, implicit addends, or a relocation-target view.

## Alternatives considered

- Reusing `debug/elf.Symbol` and its `Symbols`/`DynamicSymbols` methods: rejected for the same reasons as ADR 0004, and because its version fields and null-symbol omission encode policy REE does not want.
- Failing the whole scan on a single malformed table or name: rejected because symbol and relocation data is auxiliary and one bad table should not hide the rest.
- Reading every linked string table eagerly at `Parse` time: rejected because most callers never request symbols and the budget must stay explicit.
- Resolving `SHT_REL` addends from the relocated bytes: deferred as interpretation, not structure; it needs its own limits, address-mapping rules, and failure semantics.
- Resolving `SymIndex` into a copied `Symbol` inside each `Relocation`: rejected because it duplicates data, inflates output, and hides the per-table index space.
