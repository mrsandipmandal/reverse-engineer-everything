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
