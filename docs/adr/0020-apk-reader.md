# ADR 0020: APK reader and evidence adapter

- Status: accepted
- Date: 2026-10-28

## Context

Phase 6 adds application packages. An Android package is a ZIP archive with a
fixed layout: `AndroidManifest.xml`, one or more `classes*.dex` files,
`resources.arsc`, native libraries under `lib/`, resources under `res/`, assets
under `assets/`, and signing material under `META-INF/`. Modern packages also
carry an APK Signing Block in front of the central directory.

The container is already covered by `internal/formats/archive`, which validates
the end record, the central directory, ZIP64, data descriptors, and unsafe
paths. What an APK reader has to add is the Android meaning of each entry and
the structure of the signing block, which sits outside the ZIP directory and is
therefore invisible to the archive reader.

The manifest, DEX, and resource table are binary Android formats. Decoding them
is a separate and much larger problem, and it is not needed to inventory a
package: their presence, size, and digest are already observable. The same
applies to signature validity, which requires verifying digests and
certificate chains over content.

The tool never extracts archives, so an APK is read entirely in memory.

## Decisions

### Package boundary and API

The reader lives in `internal/formats/apk` and exposes:

- `Parse(io.ReaderAt, size)` and `ParseWithLimits(io.ReaderAt, size, Limits)`;
- `APK` with the embedded `*archive.Archive`, one `Entry` per ZIP entry in the
  same order, the `Signing` block, `Truncated`, and `Limitations`;
- `Entry` carrying the Android `Kind`, the ABI for a native library, and the
  content digest when it was computed;
- `SigningBlock` with `Present`, `Offset`, `Size`, `Pairs`, `Truncated`, and
  `Limitations`.

ZIP header fields are not copied. `APK.ZIP.Entries[index]` is the single source
of truth for the name, sizes, offsets, method, and ZIP limitations of the entry
that `APK.Entries[index]` classifies. Duplicating them would allow the two views
to disagree.

### Identification

A package is identified by the container and its root manifest:

- the archive must be a ZIP (`ContainerZIP`), not a tar or gzip stream;
- a file entry named exactly `AndroidManifest.xml` must exist at the archive
  root.

A directory named `AndroidManifest.xml`, a manifest deeper in the tree, or a
manifest with a different case is not a package manifest. An archive without
one is rejected with `ErrInvalid`, because an APK without a manifest is not
installable and its absence usually means the wrong file was selected. A
package that carries more than one root manifest is inventoried, and the extra
entries are reported in one limitation: the reader does not guess which one the
platform would honour.

### Entry classification

Classification is purely structural and case-sensitive, because the Android
packaging rules are:

| Name | Kind |
|---|---|
| `AndroidManifest.xml` | `manifest` |
| `classes.dex`, `classes2.dex`, ... at the root | `dex` |
| `resources.arsc` | `resources` |
| `lib/<abi>/<name>.so` | `native_library` |
| `res/...` | `resource` |
| `assets/...` | `asset` |
| `META-INF/*.SF`, `.RSA`, `.DSA`, `.EC` | `signature` |
| anything else | `other` |

A DEX file must be at the root, begin with `classes`, and end with `.dex`; a
nested `classes.dex` is `other`. A native library must be directly under
`lib/<abi>/`; the first segment after `lib/` is reported as the ABI. Signature
file suffixes are matched case-insensitively because `META-INF` files are
compared that way by the platform, but the base name must be non-empty.

An entry whose name is unavailable keeps `KindOther`: a path the ZIP reader
could not decode cannot be classified, and guessing from raw bytes would
invent a role the platform would not assign.

### Content digests

Only `manifest`, `dex`, and `resources` entries are hashed. They are the files a
consumer needs to correlate a package with a payload or another package, and
they are small enough that hashing them does not dominate a read. Native
libraries, resources, and assets are reported by declared size and left
unhashed, because hashing every asset would turn an inventory into a full
decompression of the package.

A digest is SHA-256 over the entry content returned by the archive reader, which
verifies CRC-32 on a full read. Three limits apply:

- `DigestBytes` bounds one entry's content; a larger entry is skipped with a
  per-entry limitation;
- `TotalDigestBytes` bounds the aggregate across the artifact; once it is
  reached, later entries are skipped with a per-entry limitation;
- a read failure records `content digest unavailable: <reason>` and does not
  fail the observation, because the inventory is still meaningful.

Every skip and failure is also recorded as an artifact limitation, so coverage
becomes partial instead of silently claiming that an unhashed manifest matched.

### Signing block

The APK Signing Block sits immediately before the ZIP central directory:

```
pair 1: uint64 length, uint32 id, value
...
uint64 size (excluding this field)
"APK Sig Block 42"
```

The reader locates the central directory first. The archive reader already
parses the end record, but it does not expose the directory offset, so the APK
reader scans the trailing `22 + 0xFFFF` bytes for a `PK\x05\x06` end record whose
comment length ends exactly at the artifact end, preferring the last such
record. When the 32-bit directory offset or size is `0xFFFFFFFF`, the ZIP64
end record is located through the locator 20 bytes before the first end record.

With the directory offset known, the last 24 bytes before it are read. A
missing magic means no signing block, which is normal for a v1-only package. A
present block is validated as a whole:

- the declared size must be at least 24 and must not exceed the directory
  offset, so the block cannot extend into the directory or before the artifact;
- the size repeated at the start of the block must agree with the footer, so a
  block cannot be truncated at the front while keeping a valid tail;
- each pair begins with an 8-byte length and a 4-byte identifier; a length below
  4 or a value that runs past the inspected area is invalid or truncated.

Known identifiers are named (`v2`, `v3`, `v3.1`, source stamp, verity padding);
an unknown pair is reported with an empty scheme and its value digest, so a new
scheme is visible without a code change.

The pair area is capped at `SigningBytes`, and the number of pairs at
`SigningPairs`. A cap sets `Truncated` and a limitation rather than failing the
artifact. Each pair value is hashed with SHA-256, which lets a consumer compare
two packages without the reader holding the values.

The reader makes no signature claim. It does not verify digests against the
archive, parse the v2/v3 signer structures, or check a certificate. The payload
says a block is present, how large it is, which schemes it declares, and what
the value digests are; whether that signature is valid or which key signed it is
out of scope.

### Limits and errors

`Limits` covers artifact size, entry count, signing block bytes, signing pair
count, one digest's bytes, and aggregate digest bytes. Zero selects the default;
a value above the package maximum is clamped. Artifact and entry limits are the
archive reader's, so an APK cannot be read under looser container rules than a
plain ZIP.

Sentinel errors mirror the archive and ASAR readers:

- `ErrInvalid`: the container is not a ZIP, the manifest is missing, or the
  signing block contradicts itself.
- `ErrTruncated`: the artifact ends before a declared structure does.
- `ErrLimit`: a configured byte or count limit was reached before an inventory
  could be produced.
- `ErrRead`: the underlying reader failed.

An archive-level error is mapped to the matching APK sentinel, so a caller does
not need to import both packages to classify a failure. A signing block that is
absent is not an error; a signing block that is present and malformed is.

### Evidence adapter

`internal/providers/apk` emits one `ree.evidence/1` record per package with a
`ree.payload.apk/1` payload. `Observe` validates the provider version, parses the
artifact, hashes the whole artifact stream, projects the artifact, the kind
counts, the signing block, and every entry, and lets `evidence.Encode` validate
the record.

- 64-bit sizes and the signing block offset are decimal strings; entry counts,
  pair counts, and booleans stay JSON numbers and booleans; raw names are
  lowercase hexadecimal.
- Absent values are `null`: a signing block that is not present has no offset or
  size, an entry without a computed digest has no digest, and a size the ZIP
  header did not declare is `null` rather than zero.
- `entry_count` is the number of ZIP entries loaded and `loaded_entry_count` is
  the number the payload budget allowed.
- The payload budget charges the artifact envelope first and spends the
  remainder on entries in ZIP order. A payload that cannot hold every entry
  records `payload budget omits entries after N of M` and marks coverage
  partial.
- An artifact limitation or a truncated inventory makes coverage partial.
  Per-entry limitations stay in the payload.

### Deferred

Binary `AndroidManifest.xml` decoding, `resources.arsc` decoding, DEX parsing,
signature verification, certificate and signer inspection, and v4 signature
files are deferred. Wiring the provider into `ree analyze` and `ree_analyze`,
inventory/search/compare commands, and the MCP surface change belong to the
final Phase 6 increment.

## Consequences

- One inventory covers the package layout and the signing block without
  decoding any binary Android format.
- A crafted ZIP, entry count, signing size, or pair count is bounded before it
  can allocate or loop without limit.
- Package identity rests on the root manifest, so a ZIP with unrelated content
  is rejected instead of being reported as a degenerate package.
- Only manifest, DEX, and resource table content is hashed; assets and native
  libraries are reported by declared size, and a consumer that needs their
  content must read it itself.
- Signature presence is not a trust signal. A consumer that needs to know
  whether a package is signed for a given key must verify the block itself.
- There is no differential oracle for APK. Fixtures built with `archive/zip` and
  fuzzing carry the verification burden.
