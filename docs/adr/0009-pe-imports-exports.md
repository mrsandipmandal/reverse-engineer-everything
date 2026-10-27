# ADR 0009: PE imports and exports

- Status: accepted
- Date: 2026-10-27

## Context

The PE foundation in [ADR 0008](0008-pe-reader.md) validates headers, data directories, and the section table, but reads no directory content. Phase 3 needs the two directories that describe an artifact's links: imports, which name the DLLs and functions an image expects from its loader, and exports, which name what an image offers.

Both directories are plain RVA structures that point at further arrays and NUL-terminated strings. Every field is untrusted: a descriptor can name a string in another section, a thunk array can claim an unbounded length, an export can map thousands of names onto one function slot, and an ordinal can fall outside the function table. The reader must bound each of those traversals, keep the declared counts separate from the loaded entries, and say plainly which names it could not decode.

Import and export tables are not needed to interpret the header, and most consumers never look at them. Reading them during Parse would charge every caller for work it may not use.

## Decisions

### On-demand tables

`Imports` and `Exports` are methods on `*File`. Both decode on each call from the original `io.ReaderAt` and return a new table; neither result is cached or shared. This mirrors `SectionData` and keeps Parse's cost proportional to the header and section table.

Both methods return a nil table and an error when the directory itself cannot be used, and a non-nil table with limitations when the directory is usable but its contents are incomplete.

### Directory lookup

The export directory is index 0 and the import directory is index 1, matching the PE specification. A shared helper resolves the slot before either decoder runs:

- a directory slot that was never declared returns `ErrNotFound`;
- a slot declared by the optional header but trimmed by the directory count limit returns `ErrUnavailable`;
- an address and size that are both zero return `ErrNotFound`, because the artifact declares no such directory;
- an address or size that is zero while the other is not returns `ErrInvalid`, because the pair contradicts itself.

An artifact-wide "no imports" answer and a "directory not loaded" answer must not look alike: the first is a property of the image, the second is a property of the reader's configuration.

### Containment

Every read goes through `fileRange`, which resolves one RVA to a file offset and the number of contiguous file-backed bytes in the same headers region or section. A descriptor, thunk, array, or string must lie inside one region. A structure that starts in one section and continues in another is reported as unavailable rather than assembled from two ranges, because section adjacency is not part of the mapping contract.

Strings are read in bounded chunks until a NUL, the per-string limit, the containing region end, or the remaining per-call string budget. Invalid UTF-8 is reported as invalid, never normalized.

### Import descriptors

The descriptor array is scanned from the import directory address in 20-byte steps until an all-zero descriptor, unreadable memory, or the module limit. The declared directory size is not used as a hard bound: real artifacts frequently declare a size that does not cover the terminated array, and the zero descriptor is the authoritative end.

The scan is bounded by the containment rule and by `MaxImportModules`. A non-zero descriptor at the limit sets `Truncated` and appends a deterministic limitation; a zero descriptor at the limit is a complete table.

Each descriptor keeps its raw timestamp, forwarder chain, and thunk addresses, plus the decoded DLL name:

- a zero name address is one unavailable name, not an error;
- an unreadable name, invalid UTF-8 name, or name above the string limit is aggregated into one limitation per category;
- a non-zero name that reads successfully sets `Name` and `NameAvailable`.

The thunk source is the original thunk array when `OriginalFirstThunk` is non-zero, and the IAT when it is zero. Both being zero yields no thunks and an empty `ThunkSource`. The decoded source is recorded so evidence can distinguish a real original-thunk table from an IAT fallback.

### Import thunks

A thunk array is read until a zero entry, unreadable memory, or the shared thunk limit. The shared limit counts every thunk across every module, so a file cannot multiply the per-module work by the module limit.

The ordinal flag is `0x80000000` for PE32 and `0x8000000000000000` for PE32+. An ordinal thunk records only the low 16 bits as `Ordinal` and no name RVA. A named thunk records the full 32-bit value as `NameRVA`; in PE32+ a non-ordinal value above `2^32-1` is reported as an unavailable name rather than truncated into a fabricated RVA.

A named thunk reads a two-byte hint followed by a NUL-terminated name. Hint and name failures are counted separately from module name failures and aggregated at the end. Hitting the thunk limit stops the whole table, not just the current module, because the budget is global.

The table-level `Truncated` flag covers an early-ending thunk array, a thunk count limit, and string-budget exhaustion. A single undecodable name does not set it: the thunk entry still exists and only its name is missing.

### Export directory

The 40-byte export directory is decoded in full. A directory whose structure is not file-backed returns `ErrUnavailable`; the reader does not return a half-populated table for a header it could not read.

The function address table is loaded as one array, because an export slot without its address is not meaningful. A declared function count above `MaxExports` is clamped and reported. A zero table address or an unreadable table yields an empty export list plus a limitation and `Truncated`.

The name table and the ordinal table are loaded as one pair. A zero address for either array reports that the name arrays are missing; an unreadable array reports that they are unavailable. Neither case fails the call, because the function table alone is still usable evidence.

Names are matched to function slots through the 16-bit ordinal table:

- an ordinal at or above the loaded function count is counted as out of range and skipped;
- a slot that already has a name is counted as a duplicate and keeps its first name;
- a zero name RVA is an unavailable name;
- invalid UTF-8 and per-string limit failures are aggregated by category.

`Ordinal` for a slot is `Base + index`, kept as raw 32-bit arithmetic. A declared base near `2^32` can therefore wrap; the value is reported as stored rather than repaired, and the function index remains authoritative.

### Forwarders

An export is treated as a forwarder when its function RVA lies inside the export directory's own `[VirtualAddress, VirtualAddress+Size)` range. The bytes at that RVA are a string RVA; the string is the forwarder target. This is the specification's test, so no name-based heuristic is used.

A zero target, an unreadable target, invalid UTF-8, or an over-limit target records an unavailable forwarder and leaves `ForwarderAvailable` false. Forwarders are never followed: a chained forwarder is reported as the string that was stored, not resolved.

### Errors and partial results

| Condition | Result |
|---|---|
| directory absent or not declared | `ErrNotFound` |
| directory address and size contradict each other | `ErrInvalid` |
| directory slot declared but not loaded | `ErrUnavailable` |
| export directory or a required array outside file-backed memory | `ErrUnavailable` |
| reader failure | `ErrRead` |
| per-string limit or exhausted per-call budget | limitation, and `ErrLimit` only for a direct single read |

A limit or decoding failure inside a table is reported through `Truncated` and `Limitations` instead of an error, because the surrounding entries remain valid observations. Only the reader failing, or a directory that cannot be located, aborts the call.

`Truncated` means the loaded table is known to be incomplete. It is set for a module, thunk, function, or name count limit, an early-ending thunk or descriptor array, and a string-budget exhaustion. A name that is merely unavailable, invalid, or over the per-string limit is recorded as a limitation without setting it.

Limitations are appended in decode order, so structure findings precede aggregate name findings.

### Limits

| Limit | Value |
|---|---:|
| import modules | 4,096 |
| import thunks, all modules | 65,536 |
| exports and export names | 65,536 |
| one name | 4 KiB |
| import strings per call | 16 MiB |
| export strings per call | 16 MiB |

The module, thunk, and export limits bound the entry count a single artifact can add to memory. The per-string limit bounds one allocation, and the per-call budgets bound the total string work even when an artifact declares the maximum number of entries. All values are lowerable through `Limits` and clamped at the package maximum.

### Public API

```go
func (f *File) Imports() (*ImportTable, error)
func (f *File) Exports() (*ExportTable, error)

type ImportModule struct {
    Index              int
    Name               string
    NameAvailable      bool
    NameRVA            uint32
    TimeDateStamp      uint32
    ForwarderChain     uint32
    OriginalFirstThunk uint32
    FirstThunk         uint32
    ThunkSource        ThunkSource
    Thunks             []ImportThunk
    Truncated          bool
}

type Export struct {
    Index              int
    Ordinal            uint32
    RVA                uint32
    Name               string
    NameAvailable      bool
    NameRVA            uint32
    Forwarder          string
    ForwarderAvailable bool
}
```

`ImportTable` and `ExportTable` carry the table-level `Truncated` flag and the limitation list, plus the decoded directory fields. Each entry carries enough raw value to be checked against the artifact without re-parsing.

### Testing

- Crafted PE32 and PE32+ images with one `.rdata` section holding descriptors, thunk arrays, strings, an export directory, and forwarder records.
- Named, ordinal, IAT-only, empty, unnamed, forwarded, and duplicate-name cases.
- Absent, contradictory, unloaded, and unmapped directory cases.
- Module, thunk, export, per-string, and budget limit cases, including the exact-limit boundary.
- Invalid UTF-8, unavailable, and unterminated names; bad name ordinals; zero and unreadable arrays.
- Reader failure during import and export decoding.
- `FuzzParse` also calls `Imports` and `Exports` and checks table invariants.
- A differential test against `debug/pe` compares imported symbols only. `debug/pe` returns a nil stub for `ImportedLibraries`, ignores ordinals, stops at the first zero original thunk, and has no export API, so those paths are covered by REE's own expectations instead.

## Consequences

- Phase 3 can project imports and exports without a second parse or a cached mutable table.
- Evidence must carry the per-entry availability flags and the table limitations; a bare name list would misrepresent undecoded entries as absent.
- Forwarders are observable strings, not resolved targets. A consumer that resolves them does so outside this package.
- Import and export decoding is intentionally lenient about a declared directory size, and strict about containment and counts. A future change to either policy is an observable contract change.
- Resource and certificate decoding in the next increment reuse `fileRange`, the aggregate limitation pattern, and the same declared-versus-loaded distinction.

## Alternatives considered

- Bounding the import descriptor scan by the declared directory size: rejected because many real artifacts declare a size that does not cover the terminated array, and the zero descriptor is the specification's terminator.
- Loading only the first function table entry that fits: rejected because a partial address table cannot be matched against ordinals or names without inventing slots.
- Following forwarders until a non-forwarder: rejected because it adds unbounded cross-image work and hides the stored chain from evidence.
- Failing the whole table on one bad name: rejected because the remaining entries are still valid observations and the failure is better reported as a limitation.
- Using `debug/pe` in production: rejected for the same reasons as ADR 0008, and its export support is absent and its library list is a stub.
