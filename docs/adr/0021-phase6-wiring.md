# ADR 0021: Phase 6 analysis wiring and inventory views

- Status: accepted
- Date: 2026-10-28

## Context

Phase 6 added four readers and four evidence providers: archives (ZIP, tar,
gzip), APK, ASAR, and plist. Until this increment no surface called them.
`internal/usecase/analyze` knew only ELF, PE, and Mach-O, `ree analyze` listed
those three formats, and the MCP surface was at `0.2`.

An inventory is a different question from an analysis. A caller that already
holds a sealed record wants the entry list, a page of it, a filtered view, or a
diff against another artifact. Re-parsing the artifact for that would duplicate
the reader's limits, disagree with the record, and make the view depend on the
file rather than on the evidence.

Three risks had to be settled:

- a ZIP and an APK share a container, and an ASAR and a ZIP share a prefix
  neighbourhood, so auto detection must not label one as the other;
- an archive can nest a container inside a member, so a flat list needs an
  explicit depth notion;
- a compare needs a stable key even when a member has no usable name.

## Decisions

### Format selection

`internal/usecase/analyze` grows six formats: `zip`, `tar`, `gzip`, `apk`,
`asar`, and `plist`. The three container formats share the archive provider and
pass the expected container, so `--format zip` on a tar artifact is an options
error rather than a tar analysis labelled `zip`. `apk`, `asar`, and `plist` map
to their own providers.

An explicit format is never reinterpreted. Auto detection reads one 512-byte
prefix and decides in this order:

1. ELF, `MZ`, and the Mach-O magics;
2. a Chromium Pickle header whose first payload size is 4 and whose header size
   is between 8 and 64 MiB, which is an ASAR candidate;
3. the archive magic: a ZIP is probed with the APK reader and becomes `apk`
   when that reader accepts it, otherwise `zip`; `ustar` at offset 257 is
   `tar`; the gzip magic is `gzip`;
4. a `bplist` prefix is `plist`; an XML prefix is `plist` only when it contains
   the property-list marker, so a generic XML document is not claimed;
5. anything else is `unsupported format`.

The APK reader reports a valid ZIP without a root `AndroidManifest.xml` as
`apk: root AndroidManifest.xml is missing`, a distinct sentinel rather than a
generic invalid artifact. Detection uses that sentinel to fall back to `zip`;
an explicit `--format apk` returns it to the caller.

### Counts

`analyze.Counts` gains `entries`, `objects`, `dex`, `native_libraries`, and
`signing_pairs`, all `omitempty`. Each format fills only the counts it has, so
the ELF, PE, and Mach-O JSON keeps its existing shape and a zero count is absent
rather than printed.

Counts are read from the payload schema, not from the reader, because the
summary describes the record. A schema mismatch is an error: the summary and
the record must not disagree.

### Inventory projection

`internal/usecase/inventory` turns one sealed record into a flat list. It never
re-opens or re-parses the artifact.

- `Item` is `index`, `kind`, `name`, `name_available`, `unsafe`, `size`,
  `digest`, `digest_available`, `depth`, and `limitations`.
- Archive members are flattened depth-first with `depth` one inside a member
  container, using the provider's nested payloads. The provider already bounds
  nesting, so the flattening cannot recurse without limit.
- Archive size prefers `uncompressed_size` and falls back to
  `compressed_size`; ASAR uses `size`; APK prefers `uncompressed_size`; a plist
  object uses the decoded text as its name and has no size.
- A record limitation is copied into the collection, so a view never claims
  more than its record.
- ELF, PE, and Mach-O payloads have no entry list. `Build` returns
  `ErrUnsupported` for them, and the CLI points the caller at `ree analyze`
  instead of inventing a table.

### Paging, search, and compare

`Collection.Page(offset, limit)` returns the window, the total, and a
`next_offset` only when more items remain. The default limit is 50 and the
maximum is 1000; a negative offset or a limit outside `1..1000` is a usage
error. A window past the end is an empty page, not an error, so a caller can
walk pages until `next_offset` is absent.

`Collection.Search` is a case-insensitive substring match on an available name.
An empty or whitespace-only query is `ErrQuery` rather than "return everything",
because a filter that silently matches all rows is easy to mistake for a real
result. Filtering preserves order and copies the collection metadata.

`Compare(left, right)` keys items by name when the name is available and
non-empty, and by `#<index>` otherwise. A key only on the right is `added`, only
on the left is `removed`, and a key on both with a different kind, name, depth,
digest, or size is `changed`. Each list is sorted by key. Index-derived keys are
a fallback: two different unnamed members can collide, and the payload's own
limitation already says the name is unavailable.

### Commands

Three commands share the analysis path and the window flags:

```
ree inventory <path> [--json] [--format F] [--max-bytes N] [--offset N] [--limit N]
ree search    <path> [--json] [--format F] [--max-bytes N] [--query TEXT] [--offset N] [--limit N]
ree compare   <left> <right> [--json] [--offset N] [--limit N]
```

`inventory` and `search` analyze one artifact and project its record.
`compare` analyzes both and diffs their collections. Exit codes follow the
existing taxonomy: `0` success, `1` operational failure, `2` invalid usage.
A missing artifact, a canceled context, or a reader failure is `1`; a bad flag,
a missing or extra path, a paging bound violation, an empty query, or an
unsupported payload is `2`.

Text output prints a header, the artifact base name, the format and schema, the
total and page window, one line per item, and the collection limitations. JSON
output is the same view with snake_case members, so a machine consumer never
parses the text form.

### MCP surface

The MCP surface becomes `0.3`. `ree_analyze` accepts the new formats, and its
instructions name them. No inventory tool is added: inventory, search, and
compare are CLI views over a record, and an MCP client can obtain the record
with `include_record` and page it locally. The surface stays read-only and
argument-taking only through `ree_analyze`.

### Deferred

Binary `AndroidManifest.xml` decoding, `resources.arsc` and DEX parsing,
signature or certificate verification, nested detection inside ASAR entries,
filesystem extraction, archive writing, a release tag, and any change to
`ree.evidence/1` remain out of scope.

## Consequences

- Every Phase 6 reader is reachable from `ree analyze` and `ree_analyze`, and
  every archive, package, or property list record is reachable from the
  inventory commands.
- A ZIP with a root manifest is an APK by detection; an explicit format never
  falls back, so the caller can always force the container interpretation.
- Inventory views are deterministic functions of the record, not of the
  artifact, so a bundle round-trip preserves them.
- Compare cannot distinguish two unnamed members with the same index in
  different artifacts. That is a known limit of a name-keyed diff and is
  reported in the item's limitations.
- No inventory state is cached or written; every command analyzes the artifact
  again under the same limits.
