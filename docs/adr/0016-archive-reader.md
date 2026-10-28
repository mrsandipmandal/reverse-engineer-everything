# ADR 0016: Archive reader foundation

- Status: accepted
- Date: 2026-10-28

## Context

Phase 6 adds archives and application packages. The first increment needs one
validated inventory of ZIP, tar, and gzip containers so later increments can add
APK, ASAR, plist, nested detection, and the evidence adapters without inventing
a second container model.

Archive metadata is attacker-controlled. Entry counts, central directory sizes,
name lengths, extra fields, tar sizes, and gzip header fields can all be chosen
to cause unbounded allocation, integer overflow, quadratic work, or a panic.
The tool must also stay honest: a partial inventory must never look complete,
and an entry whose name escapes the archive root must never have its content
read even though nothing is ever written to disk.

Phase 6 explicitly does not extract archives to the filesystem. A reader that
vendors a general-purpose extraction API would make the no-write policy
impossible to verify, so the package exposes only in-memory inventory and
bounded content reads.

## Decisions

### Package boundary and API

The reader lives in `internal/formats/archive` and exposes:

- `Detect(prefix)` for magic-based container selection;
- `Parse(io.ReaderAt, size)` and `ParseWithLimits(io.ReaderAt, size, Limits)`;
- `Archive` with `Container`, `Entries`, `Truncated`, `Limitations`, and the
  gzip header;
- `EntryData(index)` and `EntryPrefix(index, n)` for bounded on-demand reads.

`Archive` keeps the original `io.ReaderAt` and the artifact size. Entry content
is returned in memory only; the package has no file, directory, or link API.

ZIP method numbers are reused as `Method` values, so an unsupported method is
reported by its standard number and name rather than collapsed into "unknown".
`Entry.Method` is `stored` for tar and `deflate` for gzip.

### Container detection

`Detect` recognizes:

- gzip by `1f 8b 08`;
- ZIP by the local header (`PK\x03\x04`) or the empty-archive end record
  (`PK\x05\x06`);
- tar by `ustar` at offset 257.

Tar without the ustar magic is not recognized. Ancient V7 tar has no magic and
a checksum-valid random block can look like a header, so magic-less detection is
deliberately out of scope. A ZIP with prepended self-extractor data is also not
recognized; the reader reports the container as unrecognized instead of
searching for a directory at an arbitrary offset.

### ZIP

The end record is found by scanning the last 65,557 bytes and requiring the
declared comment length to end exactly at the artifact end. A signature inside
a comment therefore cannot shadow the real record.

- Multi-disk archives are rejected as invalid. A split archive's entry data is
  not in this artifact, so reporting sizes as if it were would be misleading.
- ZIP64 is read only when a base field is saturated: the locator, the ZIP64 end
  record, and the per-entry ZIP64 extra field. The end record must sit directly
  before its locator, so a relocated record is rejected.
- The central directory is read into one buffer capped by
  `Limits.DirectoryBytes`. A declared count above `Limits.Entries` or a
  directory larger than the byte cap yields the entries that fit, sets
  `Truncated`, and records one limitation.
- Entry sizes, CRC-32, method, flags, DOS time, external attributes, and the
  local header offset are reported as declared. The local header is not read
  until content is requested.
- Content reads re-check the local signature, re-read the local name, and
  require it to equal the central directory name. A mismatch is invalid.
- Stored entries require equal compressed and uncompressed sizes. Deflate
  entries are read through a size-limited `compress/flate` reader; a short
  stream is truncation, a corrupt stream is invalid, and a decompressed size
  that differs from the declared size is invalid.
- CRC-32 is verified only on a full read. A prefix read cannot verify a checksum
  and does not claim to.
- An encrypted entry, an unsupported method, or a non-file entry reports
  `ErrUnavailable`; its metadata is still inventoried.

### tar

The header chain is walked block by block with an unsigned and a signed
checksum, either of which is accepted. A bad checksum is structurally invalid
and returns no archive, because the chain cannot be trusted from that point.

- Only ustar, PAX (`x`, `g`), and GNU (`L`, `K`) extensions are decoded. PAX
  `path`, `linkpath`, and `size` apply to the next entry; global PAX attributes
  are skipped with one limitation.
- GNU long names and long links are read up to `Limits.NameBytes`; a longer
  value is skipped with a limitation and the header name is used.
- Octal and GNU base-256 numeric fields are supported. A negative or
  overflowing field is invalid.
- PAX records are length-prefixed. A malformed record stops PAX decoding, keeps
  the values already applied, and records one limitation. A PAX block above
  `Limits.PaxBytes` is skipped with a limitation.
- Entry data is stored, so a read is a bounded range read. A range outside the
  artifact records a per-entry limitation and stops the chain, because the next
  header position is no longer trustworthy.
- A GNU sparse entry stops the chain after being inventoried: its extension
  headers make the following offset unknown, and silently skipping `size` bytes
  would misparse the rest of the archive.
- Symlinks, hardlinks, devices, and FIFOs are inventoried with their declared
  target and type. Their content is never read or followed.

### gzip

A gzip artifact is one stream entry. The first member header is parsed for name,
comment, extra length, modification time, OS, and header CRC; `FHCRC` is
verified. Concatenated members are decoded by `compress/gzip` on demand.

Member boundaries and the uncompressed size are not enumerated during parse, so
`Entry.UncompressedSizeKnown` is false and `Entry.CRC32Available` is false for
gzip. `EntryData` decodes the concatenated members under the content limit and
lets the standard library verify each member's CRC-32 and size. Inventing a
member list without decompressing would be either unbounded work or an
incomplete list presented as complete.

### Names and path policy

Names are decoded as UTF-8 and never repaired. Empty names, names longer than
`Limits.NameBytes`, invalid UTF-8, and NUL bytes are reported as unavailable
with the raw bytes preserved up to the limit. CP437 ZIP names are not
transcoded.

A path is unsafe when it is absolute, starts with a drive letter, contains a
backslash separator, contains a parent-directory segment, or resolves to the
archive root. An unsafe name is still inventoried, but `EntryData` and
`EntryPrefix` return `ErrUnavailable`. Parent-directory segments are checked on
the raw path, so `a/../../b` is rejected without normalization.

gzip name and comment and tar link targets are metadata, not archive paths, so
they are checked for encoding and NUL bytes only. A gzip file name is not used
to decide whether content may be read.

### Limits and errors

`Limits` covers artifact size, entry count, name bytes, ZIP directory bytes,
entry data bytes, ZIP and gzip extra bytes, PAX bytes, and gzip comment bytes.
Zero selects the default; a value above the package maximum is clamped.

Sentinel errors separate the cases a caller must handle differently:

- `ErrInvalid`: the structure contradicts itself.
- `ErrTruncated`: the artifact ends before a required structure does.
- `ErrLimit`: a configured byte or count limit was reached.
- `ErrRead`: the underlying reader failed.
- `ErrOutOfRange`: an entry index is outside the inventory.
- `ErrUnavailable`: the entry content cannot be produced (unsafe name,
  encryption, unsupported method, non-file type).

A truncated directory or header chain returns a non-nil archive with
`Truncated` set and a nil error. A container whose first structure cannot be
interpreted returns a nil archive and an error.

### Deferred

APK, ASAR, and plist readers; nested member detection; evidence adapters; the
`ree analyze` and inventory surfaces; filesystem extraction; archive writing;
and any decompression outside a bounded content read are deferred to later
Phase 6 increments.

## Consequences

- Callers get one inventory model for three containers and can read entry bytes
  without any extraction policy of their own.
- A crafted entry count or size cannot allocate beyond the configured limits,
  and integer arithmetic is checked before every slice.
- gzip inventories are intentionally thin: one entry, unknown uncompressed
  size, and no member list. Consumers that need member-level detail must read
  the entry, which decompresses under the content limit.
- Tar with a bad checksum yields no partial inventory. This is stricter than
  the truncation path but keeps the chain trustworthy.
- The package has no differential oracle for ZIP or tar beyond the standard
  library writers in tests, so fixtures, fuzzing, and round-trip tests carry the
  verification burden.
