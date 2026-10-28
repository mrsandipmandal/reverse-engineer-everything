# ADR 0018: ASAR reader and evidence adapter

- Status: accepted
- Date: 2026-10-28

## Context

Phase 6 adds application packages. Electron applications ship their resources in
an ASAR archive: a Chromium Pickle header followed by a JSON directory and the
concatenated file data. The directory is the only inventory the format stores;
there is no per-file header to cross-check, and every offset and size in it is
attacker-controlled.

The header is small enough to read in one buffer, but the JSON directory is
recursive. A crafted directory can nest arbitrarily deep, declare hundreds of
thousands of entries, repeat paths, or point a file at a range outside the
artifact. A reader must bound all of that, and it must not present a directory
it could not finish reading as complete.

The tool never extracts archives. ASAR is no exception: file content is read in
memory on demand, links are never followed, and nothing is written.

## Decisions

### Package boundary and API

The reader lives in `internal/formats/asar` and exposes:

- `Parse(io.ReaderAt, size)` and `ParseWithLimits(io.ReaderAt, size, Limits)`;
- `Archive` with `HeaderBytes`, `JSONBytes`, `DataOffset`, `Entries`,
  `Truncated`, and `Limitations`;
- `EntryData(index)` and `EntryPrefix(index, n)` for bounded, in-memory file
  reads.

`Entry` carries the decoded path and its raw bytes, the type, the declared size
and offset relative to `DataOffset`, the resolved absolute data offset, the
executable and unpacked flags, integrity metadata, the link target, and
per-entry limitations.

### Header validation

The four leading little-endian integers are validated before any JSON is read:

- the first pickle payload size must be 4;
- `header_size` must be at least 8 and at most `Limits.HeaderBytes`;
- the header must end inside the artifact;
- `json_len <= json_size` and `json_size <= header_size - 8`;
- `json_len` must be non-zero and the JSON must start with an object.

`DataOffset` is `8 + header_size`. A header that violates one of these rules is
invalid or truncated; it never produces a partial inventory.

### Directory walk

The JSON is decoded one node at a time with `encoding/json`, and the walk is an
explicit recursion over a decoded map. The recursion depth is compared with
`Limits.Depth` before descending, so a deeply nested directory cannot exhaust
the stack. A depth or entry limit sets `Truncated` and records a limitation;
the entries already loaded stay in the inventory.

JSON object order is not preserved by map decoding, so a directory's children
are sorted by key before they are visited. Entries are therefore emitted in
sorted path order, which is deterministic for a given header and independent of
the toolchain's map iteration order.

A node is a directory when it carries a `files` object, a link when it carries
`link`, and a file when it carries `size`. A node with none of those is
inventoried as `other` with a limitation. A directory that also carries file
fields is a contradiction and fails as invalid.

### Paths

Paths are joined from directory keys with `/` and decoded as UTF-8. They are
never repaired: an empty path, a path above `Limits.PathBytes`, invalid UTF-8,
or a NUL byte is reported as unavailable with the raw bytes preserved. A path
that is absolute, starts with a drive letter, contains a backslash, contains a
parent-directory segment, or resolves to the archive root is inventoried with
its reason, and its content is never read.

Duplicate JSON keys follow `encoding/json`: the last value wins. The reader does
not silently accept a duplicate as two entries, because the JSON object already
collapsed them before the reader sees it.

### File ranges and content

`size` and `offset` are accepted as JSON numbers or decimal strings, which both
appear in ASAR writers. A negative, fractional, exponent, or non-decimal value
is invalid. A file whose `offset + size` lies outside the artifact keeps its
declared values, is marked `RangeOutside`, and its content read returns
`ErrTruncated`; the inventory is otherwise unaffected.

Content is read from `DataOffset + offset` in one bounded allocation. A declared
size above `Limits.EntryDataBytes` returns `ErrLimit`. A directory, a link, an
unpacked file, an unsafe path, or an entry without a usable range returns
`ErrUnavailable`. Integrity metadata (`algorithm`, `hash`, `blocks`) is reported
as declared and is never verified, because verification would require reading
content that the caller may not request.

### Limits and errors

`Limits` covers artifact size, header bytes, entry count, path bytes, directory
depth, and entry data bytes. Zero selects the default; a value above the package
maximum is clamped. Sentinel errors mirror the archive reader:

- `ErrInvalid`: the header contradicts itself.
- `ErrTruncated`: the artifact or a declared range ends before the structure
  does.
- `ErrLimit`: a configured byte, depth, or count limit was reached.
- `ErrRead`: the underlying reader failed.
- `ErrOutOfRange`: an entry index is outside the inventory.
- `ErrUnavailable`: the entry content cannot be produced.

A depth or entry limit returns a non-nil archive with `Truncated` set and a nil
error. A header that cannot be interpreted returns a nil archive and an error.

### Evidence adapter

`internal/providers/asar` emits one `ree.evidence/1` record per artifact with a
`ree.payload.asar/1` payload. `Observe` validates the provider version, parses
the artifact, hashes the whole artifact stream, projects the header and every
entry, and lets `evidence.Encode` validate the record.

- Unsigned 64-bit sizes and offsets are decimal strings so values above 2^53
  survive canonical JSON; the executable, unpacked, and range flags stay
  booleans, and raw paths are lowercase hexadecimal.
- Absent values are JSON `null`: a directory has no size or offset, an unpacked
  file has no data offset, and a node without integrity metadata has no
  integrity object.
- Entries are emitted once at the top level. `artifact.entry_count` is the
  loaded inventory size and `artifact.loaded_entry_count` is the number the
  payload budget allowed.
- The payload budget charges the artifact envelope first and spends the
  remainder on entries in sorted path order. A payload that cannot hold every
  entry records `payload budget omits entries after N of M` as a record
  limitation and marks coverage partial.
- An artifact limitation or a truncated inventory makes coverage partial.
  Per-entry limitations stay in the payload so the record still states that the
  artifact was fully inventoried while a particular entry could not be read.

Nested container detection inside ASAR entries is not part of this increment.
The archive provider performs nested detection for ZIP, tar, and gzip members;
ASAR file data is projected as declared metadata and is not parsed as another
container.

### Deferred

APK and plist readers, ASAR nested detection, wiring into `ree analyze` and
`ree_analyze`, inventory/search/compare commands, and the MCP surface change are
deferred to later Phase 6 increments.

## Consequences

- One deterministic inventory covers directories, files, and links without any
  extraction policy of its own.
- A crafted depth, entry count, path, or range is bounded before it can allocate
  or recurse without limit.
- Sorted paths make the payload reproducible, at the cost of the original JSON
  object order, which the format does not preserve anyway.
- Integrity metadata is reported, not verified; a consumer that needs
  verification must read the content and compute the digest itself.
- There is no differential oracle for ASAR. Fixtures and fuzzing carry the
  verification burden, and a malformed header is rejected as a whole rather
  than partially trusted.
