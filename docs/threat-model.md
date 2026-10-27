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
