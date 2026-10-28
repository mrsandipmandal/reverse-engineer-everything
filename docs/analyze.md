# Analyzing artifacts with `ree analyze`

`ree analyze` reads one local artifact, selects a built-in provider, and emits
sealed `ree.evidence/1` evidence with a deterministic summary. It is the first
REE command that turns the library providers into a usable analysis surface.

The command is read-only. It never executes, maps, decompresses, or writes
artifact content, and it never contacts a network service.

## Usage

```text
ree analyze <path> [--json] [--format auto|elf|pe] [--max-bytes N] [--out FILE] [--force]
```

| Flag | Meaning |
|---|---|
| `--json` | Print the summary as indented JSON on stdout. |
| `--format` | Select the provider: `auto` (default), `elf`, or `pe`. The value is case-insensitive. |
| `--max-bytes` | Reject artifacts above this size. `0` uses the built-in limit; larger values are clamped to it. |
| `--out` | Write the canonical evidence record to this file. |
| `--force` | Allow `--out` to replace an existing file. Requires `--out`. |

Flags may appear before or after the path.

## Examples

Text output:

The examples below are abridged; digests, counts, and notes depend on the
artifact and on the provider budgets.

```text
$ ree analyze /bin/ls
REE Analyze
artifact: ls
format: elf
provider: builtin.elf/default (0.0.2)
size: 151344 bytes
sha256: 0f3a...c21d
record: 4b8e...91aa
coverage: partial
counts: sections=31 segments=13 symbols=288 imports=0 exports=0 resources=0 certificates=0
limitations: 1
  - payload budget omitted 12 symbols
unknowns: 2
  - symbol versioning is not decoded
  - ... 
```

Summary JSON:

```text
$ ree analyze ./sample.exe --json
{
  "format": "pe",
  "provider_id": "builtin.pe",
  "profile": "default",
  "version": "0.0.2",
  "size": 512,
  "sha256": "...",
  "record_sha256": "...",
  "coverage": "complete",
  "limitations": [],
  "unknowns": [],
  "counts": {
    "sections": 0,
    "segments": 0,
    "symbols": 0,
    "imports": 0,
    "exports": 0,
    "resources": 0,
    "certificates": 0
  }
}
```

Writing the sealed record:

```text
$ ree analyze ./sample.elf --out record.json
ree: wrote 842915-byte evidence record to record.json
$ ree analyze ./sample.elf --out record.json
ree: refusing to overwrite record.json: ... (use --force)
```

`--json` and `--out` combine: stdout stays valid summary JSON and the write
confirmation goes to stderr. The record file contains exactly the canonical
encoded bytes, with no trailing newline, so `evidence.Decode` accepts it
unchanged and its digest equals `record_sha256`.

## Output

### Summary members

| Member | Meaning |
|---|---|
| `format` | The provider that ran: `elf` or `pe`. |
| `provider_id` | Fixed provider identity, `builtin.elf` or `builtin.pe`. |
| `profile` | Provider profile; currently always `default`. |
| `version` | The REE build version recorded as `provider.version`. |
| `size` | Artifact size in bytes, hashed in full. |
| `sha256` | SHA-256 of those bytes. |
| `record_sha256` | SHA-256 of the canonical `ree.evidence/1` bytes. |
| `coverage` | `complete` only when the record has no limitation and no unknown. |
| `limitations` | Why the record may be incomplete; `[]` when none. |
| `unknowns` | Structures that were present but deliberately not decoded; `[]` when none. |
| `counts` | Table sizes from the payload. |

`counts.sections` counts section headers, and `counts.segments` is nonzero only
for ELF. `counts.symbols` covers ELF symbol tables. For PE, `counts.imports`
counts import **modules**, not thunks, and `counts.resources` counts resolved
resource leaves. A table the format does not have, or a PE directory that is
absent, reports zero.

Counts describe the evidence payload, not a promise about the artifact: when
the provider trims a table to fit the payload budget, the count is the prefix
that was included, and `coverage: partial` plus a limitation name the omission.

### Paths

The summary and the record never contain the artifact path, directory, or name.
Identical bytes at different paths produce identical output. The human-readable
text prints only the base name.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Analysis succeeded. |
| `1` | Operational failure: unsupported format, unreadable or missing path, non-regular path, artifact above the limit, or a provider failure. |
| `2` | Invalid usage: bad flag, missing or extra path, unknown `--format`, negative `--max-bytes`, `--force` without `--out`, or `--out` naming the artifact. |

Errors are written to stderr as `ree: ...`; stdout carries only the requested
report.

## Bounds and safety

- Only regular files are analyzed; directories, devices, and named pipes are
  rejected.
- The artifact limit is 2 GiB, or a smaller `--max-bytes`. The subject digest
  covers exactly the declared size.
- Provider payload, string, table, depth, and hashing budgets are unchanged
  from the providers; see [payload-elf.md](payload-elf.md) and
  [payload-pe.md](payload-pe.md).
- `--out` creates the file with mode `0644` and refuses to replace an existing
  file unless `--force` is set. It also refuses to name the artifact itself. No
  other file is written.
- The command does not follow formats it was not asked for: an explicit
  `--format` that does not parse returns the provider error instead of falling
  back to detection.

## Supported formats

ELF and PE are available now. Mach-O, archives, application packages,
JavaScript and web artifacts, external engines, and runtime analysis are later
phases; see [roadmap.md](roadmap.md).

## MCP

The same analysis is available to MCP clients as `ree_analyze` in surface `0.2`. It accepts `path`, the same `format` and `max_bytes` values, and `include_record`.

The result carries the summary under `summary` and, when `include_record` is true and the sealed record is at most 1 MiB, the exact record under `record`. A larger record is replaced by a `record_omitted` explanation; export it with `ree analyze --out`. The tool returns the same path-free summary as `ree analyze --json`, and failures use messages such as `artifact not found`, `unsupported format`, or `path is not a regular file`.

## See also

- [ADR 0012](adr/0012-analysis-surface.md) for the use case boundary, summary
  contract, and error taxonomy.
- [evidence.md](evidence.md) for the `ree.evidence/1` schema.
- [payload-elf.md](payload-elf.md) and [payload-pe.md](payload-pe.md) for the
  provider wire formats.
