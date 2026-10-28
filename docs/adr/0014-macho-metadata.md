# ADR 0014: Mach-O metadata decoding

- Status: accepted
- Date: 2026-10-28

## Context

ADR 0013 gave `internal/formats/macho` a validated thin and universal header, a bounded load command table, and segment and section tables. Every command outside `LC_SEGMENT` and `LC_SEGMENT_64` was preserved raw and left to the increment that owns it.

This increment owns the rest of the evidence Phase 5 promises: the dylibs an image links against, its identity and build metadata, its entry point, its symbol table, and the headers of its embedded code signature. The provider in the next increment projects these into `ree.payload.macho/1`.

The command payloads have properties the foundation did not have to handle:

- Names are variable-length, offset-addressed strings inside a command, not fixed fields.
- The symbol and string tables are offset-and-length records in the slice, not in the load command table, so reading them needs a second bounded read and a second limit.
- Code signing is a nested container with its own magic, length, and index. It is always big-endian, whatever the image byte order is.
- None of these commands are required. A valid image may have no dylibs, no build version, no entry point, and no signature.

Decoding must stay bounded and must not turn a malformed command into a lost image.

## Decisions

### On-demand methods

Each metadata family is a method on `File`, matching the PE reader's lazy pattern:

| Method | Command | Returns |
|---|---|---|
| `Dylibs()` | `LC_ID_DYLIB`, `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB` | `DylibTable` |
| `UUID()` | `LC_UUID` | `[16]byte` |
| `BuildVersion()` | `LC_BUILD_VERSION` or the first legacy version-min command | `BuildVersion` |
| `EntryPoint()` | `LC_MAIN` | `EntryPoint` |
| `Symbols()` | `LC_SYMTAB` | `SymbolTable` |
| `CodeSignature()` | `LC_CODE_SIGNATURE` | `CodeSignature` |

`Parse` therefore does not read the symbol table or the signature. A caller that only lists sections pays nothing, and a payload budget that cannot hold the symbol table never forces a read.

### Load command table re-read

The foundation does not retain the command table: `File` keeps the table length in `commandBytes` and discards the bytes. `commandTable()` reads the same range again for each metadata call. The table is at most `Limits.LoadCommandBytes` (4 MiB) and the read is bounded by the slice reader, so a call costs one bounded copy and no retained memory.

Retaining the table on `File` would keep up to 4 MiB per slice alive for the lifetime of the artifact, including slices the caller never inspects.

### Missing versus malformed

- A command that the image does not declare is `ErrNotFound`. That includes a `LC_CODE_SIGNATURE` whose offset and length are both zero, and an absent `LC_SYMTAB`.
- A command that is present but too short for its fixed part is `ErrInvalid` for `LC_UUID`, `LC_MAIN`, `LC_SYMTAB`, and `LC_CODE_SIGNATURE`: the command cannot be interpreted at all, and returning a zero record would report a value the file does not contain.
- A defect inside a record that can still be enumerated becomes a limitation on that table, not an error: an unusable dylib name, a tool count that overruns the command, a blob offset outside the superblob.
- A reader failure wraps `ErrRead` and stops the call; a partial table is never returned alongside an error.

The distinction matters to the provider: "the image has no code signature" and "the image has an unreadable code signature command" are different evidence claims.

### Dylib names

A dylib command is 24 bytes: command and size, a string offset, a timestamp, and two packed 32-bit versions. The name starts at `NameOffset` inside the command and ends at the first NUL.

- An offset below 24 or at or beyond the command end makes the name unavailable without a limitation; this is common in crafted files and does not indicate a table defect.
- A name with no NUL inside the command is counted and reported once as `N dylib names are not NUL-terminated`.
- A name longer than `Limits.StringBytes` is counted and reported once.
- Invalid UTF-8 is counted and reported once.
- An empty name is unavailable without a limitation, matching the fixed-name rule in ADR 0013.

Multiple defects of the same kind collapse into one limitation, so a command repeated 2,048 times cannot inflate the limitation list.

`Dylib.Command` keeps the raw command so `LC_LOAD_WEAK_DYLIB` and `LC_LOAD_DYLIB` stay distinguishable. `LC_ID_DYLIB` is included in the same table: it names the image itself, which is the install name a reviewer looks for.

### Build version and legacy version-min

`LC_BUILD_VERSION` carries a platform, a minimum OS, an SDK, and a tool list. Legacy `LC_VERSION_MIN_*` commands carry only a minimum OS and an SDK and no platform. `BuildVersion` reports both shapes:

- `PlatformAvailable` is false for a legacy command, so a zero `Platform` is never read as "platform 0".
- A tool count beyond the command body or above `Limits.BuildTools` yields the tools that fit, `Truncated`, and a limitation.
- `LC_BUILD_VERSION` wins when both forms are present; the legacy command is only used when the modern one is absent. A malformed image carrying several legacy commands reports the first.

### Entry point

`LC_MAIN` carries a file offset and a stack size, not a virtual address. `EntryPoint.EntryOffset` is named to keep that visible; computing a virtual address would require picking a segment and is a provider decision, not a reader one.

`LC_UNIXTHREAD` entry points are not decoded: their register layout is architecture-specific and they are rare in current binaries.

### Symbols

`LC_SYMTAB` gives a symbol table offset and count plus a string table offset and size.

- Entry size is 12 bytes for `nlist` and 16 bytes for `nlist_64`; a 32-bit image widens its value into the 64-bit field.
- The symbol count is clamped by how many entries fit inside the slice and by `Limits.Symbols`.
- The string table size is clamped by the slice end and by `Limits.SymbolStringBytes`.
- Each name is bounded by `Limits.StringBytes`, truncated at the first NUL, and requires valid UTF-8.
- A string index outside the loaded string table, an unterminated name, an over-long name, and invalid UTF-8 are each counted and reported once.
- `Symbol` keeps the raw `StringIndex`, `Type`, `Section`, `Description`, and `Value`, so a consumer can re-derive its own view of `n_type` without the reader committing to a symbol-class taxonomy.
- `DeclaredCount` stays next to `len(Symbols)`. `StringBytes` reports the bytes actually loaded.
- A symbol table with `nsyms == 0` returns an empty table and no error; the command is present and says the table is empty.

Symbols are not filtered: the null symbol at index zero, debugging entries, and undefined symbols are all reported.

### Code signing

`LC_CODE_SIGNATURE` gives a data offset and size relative to the slice. The data is a `CSMAGIC_EMBEDDED_SIGNATURE` superblob: a big-endian magic, a declared length, a blob count, and an index of `(type, offset)` pairs. Each blob begins with a big-endian magic and length.

The reader decodes exactly that:

- `DataOffset` and `DataSize` are reported as declared.
- The superblob magic, declared length, and blob count are reported.
- Each index entry reports its raw type, its offset, and the blob's magic and length when the header is inside the superblob.
- A range outside the slice, a wrong superblob magic, a declared length that disagrees with the bytes read, a count above `Limits.CodeSignBlobs`, index entries beyond the declared length, blob offsets outside the superblob, and blob lengths that escape it each become a limitation, not an error.

The reader does not verify the signature, does not parse the code directory, does not read the requirements, does not decode entitlements, and does not evaluate the certificate chain. A code signature is reported as present data, never as trust. This mirrors the PE certificate-directory decision: presence is not a security signal, and a partial verifier is worse than none because it invites a conclusion the code did not earn.

`CodeSignatureBlob.Type` keeps the raw blob type, so a caller may recognise a code directory (`0xfade0c02`) or an entitlements blob without the reader naming them.

### Limits

| Limit | Default | Scope |
|---|---:|---|
| dylibs | 2,048 | one `Dylibs` call |
| decoded name | 4 KiB | one dylib or symbol name |
| build tools | 128 | one `BuildVersion` call |
| symbols | 262,144 | one `Symbols` call |
| symbol string table | 32 MiB | one `Symbols` call |
| signature blobs | 64 | one `CodeSignature` call |
| signature bytes | 8 MiB | one `CodeSignature` call |

The values match the PE reader's string, symbol, and certificate bounds so an operator meets one vocabulary across formats. `withDefaults` keeps its rule: a non-positive field selects the default, a value above the maximum is clamped, and a caller can lower a bound but never raise it.

### Out of scope

Exports tries, chained fixups, relocations, Objective-C metadata, `LC_UNIXTHREAD` entry points, entitlements and certificate contents, signature validation, dyld shared caches, and ARM64e pointer authentication stripping remain out of scope. The provider records them as unknowns.

## Testing

- Dylibs: clean two-command table, absent command, invalid UTF-8, unterminated name, an offset before the fixed part, an offset past the command, an over-long name at a lowered limit, and a count limit.
- `LC_UUID`: present, absent, and a command shorter than 24 bytes.
- `LC_BUILD_VERSION`: platform, minimum OS, SDK, both tools, a tool limit, the legacy version-min shape, and absence.
- `LC_MAIN`: entry offset and stack size, and absence.
- Symbols: 64-bit and 32-bit decoding, an empty declared table, absence, a string index outside the table, an unterminated name, invalid UTF-8, an over-long name, a symbol count limit, and a string table limit.
- Code signature: a two-blob superblob, per-blob type and length, absence, an empty command, a range outside the slice, a wrong magic, a length that hides the index, an index entry pointing outside the superblob, a short blob length, a blob count limit, and a byte limit.
- Every metadata method on a nil `*File` returns `ErrInvalid`; every method on a reader that fails wraps `ErrRead`.
- Defaulting and clamping of every new limit field.
- `FuzzMetadata` with lowered limits asserts that no input panics and that every returned table respects its configured limit. It found one real defect during development: a 16-byte dylib command reached the name decoder before the fixed size was checked. The command now raises a truncation limitation, and the failing input is kept under `testdata/fuzz/FuzzMetadata/` as a regression seed. 25 seconds of fuzzing executed 2,160,406 inputs.
- Package coverage is 92.6%.

## Consequences

- A consumer can describe an image's dependencies, identity, build target, entry point, symbols, and signature headers without a second parser.
- Every table carries its own `Truncated` and `Limitations`, so a capped table is never mistaken for a complete one.
- `Symbol` keeps raw `nlist` fields; a later increment that wants symbol classes can build them without changing the reader's storage.
- The provider must decide how to spend its payload budget across dylibs, symbols, and signature headers; the reader only bounds each family.
- Re-reading the command table means a metadata call is not free. The cost is one bounded copy per call and is preferred over holding the table for the artifact lifetime.

## Alternatives considered

- Decoding everything in `Parse`: rejected because a caller that needs one section would pay for a 32 MiB string table and an 8 MiB signature.
- Retaining the command table on `File`: rejected because it multiplies retained memory by the number of slices.
- Returning `ErrNotFound` for a malformed command: rejected because it would report a corrupt record as an absent one.
- Returning an error for every malformed dylib name: rejected because one bad command would hide the rest of the table; aggregated limitations keep the enumeration.
- Flattening all dylib commands into one type without `Command`: rejected because the load semantics differ and a reviewer needs them.
- Naming blob types with a full table: rejected as presentation; the raw type is stable and the provider can name the few it reports.
- Verifying the signature: rejected. The reader has no trust model, no certificate store, and no reason to imply one.
- Decoding `LC_UNIXTHREAD` as an entry point: rejected because the register layout is architecture-specific and unused by the provider.
- Emitting a virtual entry address: rejected because it needs a segment choice the reader does not own.
