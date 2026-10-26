# Architecture

## Principles

REE is evidence-first and read-only by default.

1. Observe before inferring. Every finding identifies its source.
2. Preserve uncertainty. Unknowns are recorded, not hidden.
3. Keep analysis reproducible. Inputs are content-addressed and evidence is deterministic.
4. Bound every resource. Parsers enforce size, count, depth, time, and output limits.
5. Do not execute untrusted artifacts. Runtime analysis is a separate, explicit phase.
6. Keep the public contract stable and versioned.

## Layers

```text
cmd/ree                 CLI entry point
internal/cli            command parsing and presentation
internal/app            use cases and orchestration
internal/contracts      versioned public schemas and canonical encoding
internal/domain         provider-neutral evidence and analysis types
internal/providers      provider implementations and registry
internal/formats        format readers and parsers
internal/process        bounded subprocess execution
internal/platform       OS and architecture integration
internal/setup          tool detection and environment diagnostics
internal/views          paginated projections of retained evidence
internal/mcp            MCP server surface
pkg/sdk                 importable client and provider SDK
docs/adr                architecture decision records
```

## Boundaries

### Provider

A provider identifies one analysis engine or built-in reader and declares its capabilities, version, and limitations.

### Reader

A reader parses one artifact family behind a bounded, context-aware interface. Readers never execute target code.

### Comparator

A comparator relates two authenticated observations and reports changes with explicit coverage.

### Store

A store retains evidence and supports deterministic export and import. The first implementation is in-memory with offline bundles.

### Runner

A runner executes an allowlisted external tool under explicit authorization, isolation, and resource limits. It is not part of the Phase 0a foundation.

## Evidence model

Evidence is the core contract.

- Subject: exact input identity, including SHA-256 and byte length.
- Schema: explicit schema name and version.
- Provider: identifier, version, and analysis profile.
- Authority: `observed`, `derived`, or `inferred`.
- Coverage: `complete`, `partial`, or `unknown`.
- Limitations and unknowns: first-class records.
- Payload: canonical JSON using RFC 8785.
- Integrity: digest of the canonical payload.
- Reproducibility: no wall-clock timestamps or host-specific paths in hashed content.

Evidence bundles are offline, versioned, and deterministic. Import validates every digest and schema before merging.

## Security posture

- Inputs are untrusted.
- Parsers are streaming where practical and always bounded.
- Archive handling rejects traversal, symlink escapes, and decompression bombs.
- Subprocesses use argv only, sanitized environments, isolated temporary directories, rlimits where available, process-group termination, and output caps.
- External tools are detected, not bundled.
- No hidden network access.
- Runtime analysis requires explicit user authorization.

See [threat-model.md](threat-model.md).

## Compatibility

The MCP surface is REE-native and versioned. A compatibility profile for other tools may be added later; it is not part of the initial contract.

## Phase 0a

Phase 0a contains only the CLI foundation:

- `ree version` and `ree help`;
- deterministic build metadata;
- CI, CodeQL, dependency review, and workflow linting;
- open-source repository files.

No artifact parsing, engine execution, or MCP server is present yet.
