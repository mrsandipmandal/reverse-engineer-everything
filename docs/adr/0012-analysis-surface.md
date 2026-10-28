# ADR 0012: Analysis use case and agent-facing surface

- Status: accepted
- Date: 2026-10-28

## Context

Phases 1 to 3 produced an evidence core and two built-in providers: `internal/providers/elf` and `internal/providers/pe`. Both are pure library packages. Neither the CLI nor the MCP server can analyze an artifact, so the project's most useful capability is invisible to every consumer, including the agents the project is meant for.

A tool that reverse engineers anything first has to be callable. The comparison target, `rea`, exposes a single analysis verb over both a command line and an agent protocol and returns structured results. REE already has a stricter evidence model than that target: canonical JSON, subject and payload digests, fixed provider identity, authority, coverage, limitations, and unknowns. Phase 4 connects the model to consumers instead of adding a third invisible reader.

The phase order in the roadmap is therefore changed. The analysis surface becomes Phase 4, and the Mach-O reader moves to Phase 5. A later reader benefits from the surface: it becomes usable the day it merges, and the surface contract is exercised by two providers before it grows.

Two constraints shape the contract:

- evidence must be reproducible and path-free, so two hosts can compare records;
- an agent protocol request must not be able to make the server read an unbounded amount of data or return an unbounded response.

## Decisions

### Package and entry point

The use case lives in `internal/usecase/analyze` and exposes:

```go
func Analyze(ctx context.Context, path string, opts Options) (Result, error)
```

- It owns format selection, artifact bounds, provider invocation, record sealing, and the summary. Providers keep their current API and know nothing about files, paths, or the CLI.
- `Result` carries the `Summary`, the decoded `evidence.Evidence`, and the canonical sealed `Bytes`, so a consumer never re-encodes or re-hashes to display or store the record.
- The use case is the only package that both providers meet. The CLI and the MCP server call it and add no analysis logic of their own.

### Path and size handling

- Only regular files are analyzed. `os.Stat` runs before `os.Open`, and a non-regular path fails with `ErrNotRegular`. A symbolic link is followed by `os.Stat`; the link target must itself be a regular file.
- The size from `Stat` is the declared subject size passed to the provider. A file that changes size between `Stat` and the read fails inside the provider instead of producing a record for bytes that no longer exist.
- `Options.MaxBytes` defaults to `MaxArtifactBytes` (2 GiB, the reader bound). A larger value is clamped rather than rejected, so a caller cannot raise the parser bound. A negative value is `ErrOptions`.
- The artifact is never mapped, executed, decompressed, or written. Reads happen only through the provider's `io.ReaderAt`.

### Format selection

| `Options.Format` | Behaviour |
|---|---|
| empty or `auto` | Read the magic: `\x7fELF` selects ELF, `MZ` selects PE, anything else is `ErrUnsupportedFormat` |
| `elf` | Call the ELF provider directly |
| `pe` | Call the PE provider directly |

Format names are trimmed and lowercased. An explicit format is never a hint: if the bytes do not parse as that format, the provider error is returned and detection does not run. An unknown name is `ErrOptions`.

Magic detection reads four bytes. A short file that matches no prefix is `ErrUnsupportedFormat`, not a read error; a genuine read failure is reported as one.

### Summary contract

`Summary` is stable JSON (`format`, `provider_id`, `profile`, `version`, `size`, `sha256`, `record_sha256`, `coverage`, `limitations`, `unknowns`, `counts`) and carries no host path.

- `format` is the selected provider format, not the requested option.
- Provider identity is copied from the sealed record, so the summary cannot claim a provider that did not run.
- `sha256` is the record's subject digest; `record_sha256` is the SHA-256 of the canonical record bytes, which equals `Record.Digest()`.
- `limitations` and `unknowns` are non-nil copies, so they encode as `[]` rather than `null`.
- `counts` uses one shape for every format. Counts that do not apply are zero, so a consumer reads one struct. `imports` counts modules, not thunks.

### Counts

The counts are derived from the sealed payload with a small per-format extractor that decodes only the arrays it counts and checks the payload schema. Provider API and payload types stay unchanged.

- ELF: `sections`, `segments`, and `symbols`.
- PE: `sections`, `imports` (modules), `exports` (export slots), `resources` (leaves), and `certificates` (records). PE COFF symbols are not decoded, so `symbols` is zero.
- A PE directory member that is `null` counts zero; the record limitation, not the count, separates "absent" from "unusable".
- A trimmed table counts the entries actually present. It is a prefix, never a complete count; coverage and limitations state the gap.

### Errors

| Condition | Error |
|---|---|
| invalid option, unknown format, missing provider version | `ErrOptions` |
| magic matches no built-in provider | `ErrUnsupportedFormat` |
| size above `MaxBytes` | `ErrTooLarge` |
| path is not a regular file | `ErrNotRegular` |
| cancellable context already done | the context error |
| file system failure | wrapped operating system error |
| provider parse, read, or limit failure | the provider error, prefixed with the selected format |

No evidence is returned with an error. Operational errors may name the path, because a local command-line tool should say what it could not read; the record and the summary never do.

### Surface increments

The use case is the first of four increments:

1. this package, its tests, and this ADR;
2. `ree analyze` with `--json`, `--format`, `--max-bytes`, `--out`, and `--force`;
3. the MCP tool `ree_analyze` with a bounded `include_record`, and the surface version raised from `0.1` to `0.2`;
4. the roadmap and project memory closeout.

`--out` writes the canonical record and refuses to replace an existing file without `--force`. `ree_analyze` returns the summary by default and the sealed record only when asked, so an agent does not pay for a multi-megabyte response it will not read. The release verification script must keep accepting `0.1` releases, where `ree_analyze` does not exist.

### Out of scope

Mach-O (Phase 5), archives and application packages (Phase 6), JavaScript and web artifacts (Phase 7), external engines (Phase 8), and runtime analysis (Phase 9) are not part of this surface. There is no bundle export command, no decompilation, no network access, no release tag, and no change to the evidence schema.

## Testing

- An ELF and a PE fixture generated in test code, with no proprietary artifact committed.
- Detection, explicit format, explicit-format mismatch, unsupported bytes, size limit, clamping, non-regular path, missing file, and canceled context.
- Record round-trip through `evidence.Decode`, digest agreement, and canonical re-encoding.
- Determinism across two paths holding identical bytes, and a check that neither the summary nor the record contains the artifact name or directory.
- Summary JSON member presence and `[]` encoding for empty lists.
- Count extraction for present, empty, absent, and malformed payloads, and reader-error propagation in detection.

## Consequences

- A new reader can be shipped as a provider plus one dispatch entry; the rest of the surface follows.
- The summary is a stable, low-cost view for agents and humans, while the record remains the evidence of record.
- Evidence stays path-free, so records from different hosts can be compared and shared.
- Raising the surface version makes `0.2` the current contract. Consumers that hard-code the `0.1` tool list must update; the release script keeps a compatibility branch for old tags.
- The MCP server reads any regular file the user can read. That is the same authority the user already has, and it is stated plainly rather than presented as a sandbox.

## Alternatives considered

- Wiring each provider into its own CLI command: rejected because format detection, bounds, and summary shape would be duplicated per provider.
- Returning the provider payload directly to consumers: rejected because it exposes wire details twice and lets a consumer skip coverage and limitations.
- Including the artifact path in the summary for convenience: rejected because it leaks host layout into comparable evidence and invites storing it.
- Running detection inside each provider: rejected because a provider should accept the format its caller selected and stay independent of sibling providers.
- Making `counts` format-specific: rejected because consumers would carry per-format logic for a summary field.
- Shipping Mach-O first: rejected because it adds another invisible reader before anything is callable.

## See also

- [ADR 0003](0003-evidence-core.md) for the evidence record and its limits.
- [ADR 0007](0007-elf-evidence-adapter.md) and [ADR 0011](0011-pe-evidence-adapter.md) for the two providers this use case selects.
- [roadmap.md](../roadmap.md) for the reordered phase plan.
