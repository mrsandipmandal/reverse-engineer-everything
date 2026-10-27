# Threat model

## Assets

- Integrity of evidence and findings.
- Confidentiality of analyzed artifacts and user data.
- Availability of the user's machine and the tool.
- Integrity of releases and dependencies.
- Trust in the project's provenance claims.

## Adversaries

- A malicious or malformed artifact.
- A malicious archive or filesystem path.
- A compromised or malicious external tool or plugin.
- A supply-chain attacker targeting dependencies or releases.
- An attacker with local access to evidence bundles or configuration.

## Trust boundaries

```text
untrusted artifact bytes
        |
        v
bounded parser / reader  ->  evidence records
        |
        v
canonical encoder         ->  offline bundle
        |
        v
CLI / MCP client
```

An external engine, when introduced, crosses another boundary and receives only explicit, authorized inputs. Its output is untrusted until validated.

## Threats and mitigations

### Malformed input

Threat: crashes, panics, excessive memory, or CPU exhaustion.

Mitigations:

- recover at parser boundaries and return errors;
- size, count, depth, and time limits;
- streaming reads where practical;
- fuzz tests for parsers;
- no panics for malformed input.

### ELF parsing

Threat: a crafted ELF header, extended count, table offset, or entry size causes excessive allocation, integer overflow, a panic, or a misleading complete-looking table.

Mitigations:

- validate the identifier, class, byte order, version, header size, and entry sizes before reading tables;
- treat contradictory counts, missing tables, and out-of-range section name indexes as structural errors;
- compare declared counts with configured limits and available bytes before allocating;
- clamp table reads to complete entries and report `Truncated` plus a deterministic limitation;
- keep raw declared counts separate from loaded table lengths;
- fuzz the parser and compare ordinary decoding against `debug/elf` in tests;
- never execute, map, or write artifact content.

Residual risk: the ELF reader is not a sandbox. It bounds its own allocations and reads, but a later consumer that trusts a declared offset or size without checking it can still misbehave.

### ELF content and metadata reads

Threat: a crafted section size, segment size, string table, note, or `.comment` section causes excessive allocation, unbounded output, or a misleading "absent" result; or an artifact-controlled string reaches a consumer that assumes text.

Mitigations:

- bound each section and segment read by an explicit per-read limit, then by the declared artifact size;
- return `ErrUnavailable` for ranges outside the artifact instead of a short slice, so partial data cannot be mistaken for complete data;
- treat `SHT_NOBITS` as having no file bytes;
- bound section and note names, string table and `.comment` sizes, note count, total note bytes, build-id size, and comment entry count;
- cap the note limitation list so malformed artifacts cannot produce unbounded diagnostics;
- reject invalid UTF-8 in names, note names, and `.comment` entries rather than normalizing it;
- report partial note coverage through `NoteSet.Truncated` and return `ErrUnavailable`, not `ErrNotFound`, when absence cannot be proven;
- reject conflicting or empty GNU build-id notes;
- never decompress, execute, or write content; compressed sections are returned as stored bytes.

Residual risk: callers that ignore `Truncated`, `Limitations`, or `ErrUnavailable` can still overstate what an artifact contains. Evidence emitters must map these signals into coverage and limitations rather than into empty values.

### ELF symbols and relocations

Threat: a crafted symbol count, string table, extended-index table, relocation count, or packed `r_info` field causes excessive allocation, integer overflow, a panic, a misleading symbol identity, or a fabricated relocation addend.

Mitigations:

- bound the number of symbol tables, symbols, relocation sections, and relocations before allocating or appending;
- bound one symbol string table with the content limit and all symbol string reads with a per-call byte budget;
- reject invalid UTF-8, unterminated names, out-of-range name offsets, and names above the name limit instead of substituting text;
- keep `TableIndex` and `Index` on every symbol so a per-table index space cannot be mistaken for a global one;
- include the null symbol so indexes match the raw table;
- resolve `SHN_XINDEX` only through a linked `SHT_SYMTAB_SHNDX` table and leave unresolved indexes at `0xffff` with a limitation;
- decode `r_info` with the artifact word size and byte order, and bounds-check every complete entry before slicing;
- record whether an addend was explicit; never infer a `SHT_REL` addend from relocated bytes;
- aggregate name and index failures per table and cap the limitation list so a malformed table cannot flood output;
- return `ErrRead` with the entries collected so far when the reader fails;
- treat an incomplete section header table as a coverage limitation rather than as proof that no symbols or relocations exist.

Residual risk: symbol and relocation indexes are per-table and only meaningful with the original artifact. A consumer that resolves a `SymIndex` against the wrong table, or that reads a relocation as an applied value, can still produce a wrong claim. Symbol versioning and relocation application remain out of scope.

### ELF evidence projection

Threat: the adapter turns a truncated, unavailable, or oversized observation into a complete-looking evidence record; or a crafted artifact inflates the record, exceeds an evidence limit, and causes the encoder to fail after expensive work.

Mitigations:

- hash exactly the caller-declared byte length and fail with `ErrRead` on a short read, so the subject digest always names the whole artifact;
- return no evidence on parse, digest, or reader failure;
- derive coverage from recorded limitations and unknowns, never from array length alone;
- emit `uint64` fields and addends as decimal strings so a JSON double cannot silently change them;
- omit `data_sha256` when a range was not hashed and record why, instead of hashing a prefix;
- bound the payload by a byte budget shared across tables, trim only to a prefix, and state the number of omitted entries;
- cap inline note descriptors and hash larger ones so one note cannot exceed the evidence string limit;
- aggregate per-entry failures and cap limitation and unknown lists;
- let `evidence.Encode` validate the sealed record before returning it;
- keep provider identity fixed and version caller-supplied, so a record cannot claim an engine that did not run;
- never execute, decompress, map, or write artifact content, and do not depend on `debug/elf`.

Residual risk: a consumer that ignores coverage and limitations can still read a trimmed table as complete. Content digests prove equality of a declared range, not that the range means what its section name suggests.

### PE parsing

Threat: a crafted DOS header, `e_lfanew`, optional header size, directory count, section count, section offset, or raw size causes excessive allocation, integer overflow, a panic, or a misleading complete-looking table.

Mitigations:

- require the DOS signature, reject an `e_lfanew` below 0x40, and require the PE signature at the declared offset;
- accept only the PE32 and PE32+ optional header magics and require the fixed header to be fully present before reading fields;
- compare declared directory and section counts with the supported maximum, the bytes physically present, and the configured limits before allocating;
- compute loaded counts from the small bounds first, so a declared count near `2^32` cannot overflow `int` on a 32-bit build;
- clamp a short section table to complete 40-byte entries and report `Truncated` plus a deterministic limitation;
- keep raw declared counts separate from loaded slice lengths;
- bound section content with a per-read limit and return `ErrUnavailable` for a range outside the artifact instead of a short slice;
- reject invalid UTF-8 section names rather than normalizing them, and aggregate name failures into one limitation;
- map RVAs deterministically with a first-match rule and an `Ambiguous` flag, and mark virtual-only tails as not file-backed;
- omit the overlay with a limitation when any section raw range or `SizeOfHeaders` extends beyond the artifact, instead of guessing the boundary;
- fuzz the parser and compare ordinary header, directory, section, and content decoding against `debug/pe` in tests only;
- never execute, map, decompress, or write artifact content.

Residual risk: the PE reader is not a sandbox. It bounds its own allocations and reads, but a later consumer that trusts a declared RVA, directory address, or section raw range without checking it can still misbehave. Overlapping sections and inconsistent virtual and raw sizes are preserved as observed values, not repaired.

### PE imports and exports

Threat: a crafted import descriptor, thunk array, export directory, name table, ordinal table, or forwarder graph causes unbounded traversal, repeated work across modules, allocation growth from long strings, a panic, or a name that appears decoded when it is not.

Mitigations:

- resolve every directory, array, thunk, and string through one containment helper that requires the whole read to sit inside the headers region or a single section's file-backed range;
- cap import modules at 4,096 and share one 65,536-thunk budget across every module, so the module count cannot multiply per-module work;
- cap exports and export names at 65,536 each and load the function table as one array, so ordinals always refer to loaded slots;
- bound one name at 4 KiB and all import and export strings at 16 MiB per call, so a file with the maximum entry count cannot force unbounded string reading;
- treat a non-ordinal thunk value above 32 bits in PE32+ as an unavailable name instead of truncating it into a fabricated address;
- classify an export as a forwarder only when its RVA is inside the export directory range, and never follow a forwarder;
- record per-entry availability flags plus aggregated limitations for unavailable, invalid, and over-limit names instead of presenting empty names as decoded values;
- treat a bad name ordinal, a duplicate name, and a missing name array as limitations with the function table still usable, and keep declared counts separate from loaded entries;
- fuzz the whole reader, including `Imports` and `Exports`, and compare imported symbol decoding against `debug/pe` in tests only.

Residual risk: import and export decoding is intentionally lenient about a declared directory size because real artifacts often declare a size that does not cover the terminated array; the zero descriptor, containment, and count limits are the real bounds. Evidence must carry per-entry availability and the limitation list, because a consumer that reads only names cannot tell an undecodable name from one the artifact does not have. Forwarder strings are stored targets, not verified resolutions.

### Archive bombs and path traversal

Threat: disk exhaustion, writes outside the workspace, symlink escapes.

Mitigations:

- reject absolute paths, `..` traversal, and symlink escapes;
- cap extracted files, total bytes, and nesting depth;
- use isolated temporary directories;
- never follow links outside the extraction root.

### Command injection

Threat: artifact-controlled data reaches a shell.

Mitigations:

- argv-only subprocess execution;
- no shell interpolation;
- sanitized environment;
- fixed tool paths or explicit allowlists;
- strict output caps.

### MCP protocol boundary

Threat: a client sends malformed arguments or a tool contaminates the stdio protocol stream with logs.

Mitigations:

- the Phase 0b tools take no arguments, so artifact data cannot reach a handler;
- the SDK validates tool inputs and outputs against generated JSON Schemas;
- stdout is reserved for MCP protocol messages;
- the SDK logger defaults to discard, and CLI errors go to stderr;
- tool handlers return only version or diagnostic data.

### Doctor subprocesses

Threat: `ree doctor` executes a malicious or unexpected executable found on `PATH`.

Mitigations:

- only fixed executable names and fixed `--version`-style argv are used;
- no shell interpolation;
- two-second timeout and bounded combined output;
- missing tools are reported, not installed;
- the report never includes environment-variable contents or secrets.

Residual risk: a local attacker who controls the user's `PATH` can substitute a tool. The doctor is a diagnostic command, not a sandbox.

### Untrusted subprocesses

Threat: a malicious engine reads files, uses the network, or runs indefinitely.

Mitigations:

- explicit authorization;
- process-group termination;
- timeouts and output caps;
- isolated working directories;
- no implicit network access;
- documented residual risk because REE is not a security sandbox.

### Evidence tampering

Threat: modified bundles or findings.

Mitigations:

- content-addressed subjects;
- canonical payload and record digests;
- a bundle digest that binds the schema, record set, and record order;
- canonical-only import that rejects rather than repairs bytes;
- duplicate and out-of-order record rejection;
- strict schema validation with exact member names on import;
- in-memory import with no extraction or execution;
- bundle, record, payload, string, count, and depth limits;
- no host-specific data in hashed content.

### Supply chain

Threat: compromised dependency or release artifact.

Mitigations:

- dependency review;
- `govulncheck`;
- CodeQL;
- pinned GitHub Actions by SHA;
- least-privilege workflow permissions;
- checksums, SBOM, and keyless signing for releases;
- dependency update automation.

### Sensitive data

Threat: secrets or personal data in evidence, logs, or issues.

Mitigations:

- do not log secrets;
- redact declared sensitive values;
- discourage proprietary fixtures in public contributions;
- document data handling.

## Residual risks

- Static analysis can be incomplete or misleading.
- External engines may have vulnerabilities outside REE's control.
- A local attacker with access to the user's account is out of scope.
- Runtime isolation is not a security boundary until explicitly designed and tested.
- Evidence can be correct about bytes while still being misinterpreted by an analyst.

## Out of scope

- Protecting a compromised host.
- Guaranteeing that an analyzed artifact is benign.
- Legal authorization to analyze an artifact.
- Network sandboxing for arbitrary external tools in early phases.
