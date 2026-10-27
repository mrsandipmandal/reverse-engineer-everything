# ADR 0010: PE resources and certificates

- Status: accepted
- Date: 2026-10-27

## Context

Phase 3's third increment reads the two PE directories that describe an image's own payload rather than its links: the resource tree and the attribute certificate table.

The resource directory is a self-relative tree. Every branch entry holds a named string offset or an integer identifier, and every child pointer is an offset from the tree's base, not an RVA. A malformed tree can point at itself, fan out to the entry budget, or declare names whose UTF-16 length exceeds the bytes that follow. Resource names are UTF-16, unlike the UTF-8 import and export names.

The certificate table is not an RVA structure at all: the security directory stores a file offset and a byte size, and the bytes are a sequence of `WIN_CERTIFICATE` records padded to eight-byte boundaries. The records describe signatures. Reading their headers is not the same as validating them, and this reader must not imply trust.

Both structures are needed only by consumers that ask for them, and both can be large enough to require explicit budgets.

## Decisions

### On-demand APIs

```go
func (f *File) Resources() (*ResourceTable, error)
func (f *File) Certificates() (*CertificateTable, error)
func (f *File) CertificateData(index int) ([]byte, error)
```

`Resources` decodes the tree and leaf data entries but never reads resource bytes. `Certificates` decodes the record headers but never reads certificate blobs. `CertificateData` returns a copy of one blob and is the only path that reads certificate bytes.

Neither table is cached. Each call re-reads from the original `io.ReaderAt`, so a `File` remains immutable and no caller can observe another caller's decode state.

### Resource directory location

The resource directory is data directory index 2. Its address is an RVA, so the whole declared tree must sit inside one contiguous file-backed range:

- an absent directory returns `ErrNotFound`;
- a contradictory address and size pair returns `ErrInvalid`;
- a slot declared but trimmed by the directory count limit returns `ErrUnavailable`;
- a tree whose declared size exceeds the file-backed bytes at its address returns `ErrUnavailable`.

All child offsets are relative to the directory address. The reader resolves the base once and then bounds every child read against the declared directory size before touching the artifact, so a child pointer can never escape into unrelated file content.

### Traversal

The tree is walked iteratively, not recursively, so nesting cannot exhaust the goroutine stack. A stack of pending directories and leaves is filled in reverse on-disk order, which makes the emitted resources depth-first in on-disk order: named children before integer children, and earlier siblings before later ones.

Three bounds apply:

- `ResourceDepth` (8) limits directory nesting below the root; a subdirectory below the limit is reported as a limitation and not expanded;
- `ResourceEntries` (4,096) is one shared budget for every directory entry walked in the call;
- `ResourceStringBytes` (16 MiB) bounds all name strings read in the call.

A cycle is therefore bounded by depth and by the shared entry budget, and produces a deterministic limitation instead of a hang.

When a directory declares more entries than fit in the declared directory size, the entries that fit are used and the shortfall is recorded. When the remaining shared budget cannot cover the declared entry list, the walk stops instead of reporting a prefix as if it were the whole directory. This differs deliberately from a per-entry skip: a partial sibling list would make the path order look complete when it is not.

### Resource identifiers

A branch entry's name field is either a 31-bit integer identifier or a 31-bit offset with the high bit set. A named level is decoded from an `IMAGE_RESOURCE_DIR_STRING_U`: a 16-bit code-unit count followed by little-endian UTF-16 code units. The name must fit the declared directory, the per-string limit, and the remaining string budget.

UTF-16 is decoded strictly. Unpaired high or low surrogates make the name unavailable; they are never replaced with `U+FFFD`, because a replaced name would look like decoded text. Names are not normalized, trimmed, or case-folded.

A name that is unavailable, invalid, or over the limit keeps `IsName` true and `NameAvailable` false. The three failure kinds are counted separately and reported as aggregate limitations.

### Leaf data entries

A branch entry without the subdirectory flag points at a 16-byte `IMAGE_RESOURCE_DATA_ENTRY`: data RVA, data size, code page, and a reserved field. The decoder reads the structure, keeps the raw values, and checks whether the declared data range is file-backed.

`DataAvailable` is true for a zero-size resource and for a range that resolves through `fileRange` with enough contiguous bytes. The bytes themselves are not read. A non-file-backed range is preserved as declared with `DataAvailable` false and aggregated into a limitation.

### Certificate table

The security directory is index 4. Its address is a file offset, not an RVA, so it is checked directly against the artifact size.

- an absent directory returns `ErrNotFound`;
- a contradictory offset and size pair returns `ErrInvalid`;
- a declared table above `CertificateBytes` (8 MiB) returns `ErrLimit`;
- a table range outside the artifact returns `ErrUnavailable`.

Records are read in order. Each record starts with `dwLength`, `wRevision`, and `wCertificateType`. A length below the eight-byte header, or a length that exceeds the remaining declared table, is a structural contradiction and returns `ErrInvalid`: the record boundaries cannot be recovered without guessing.

Otherwise the header and blob bounds are recorded and the next record starts at the next eight-byte boundary. A final record whose padding does not fit inside the declared table ends the table. Bytes after the last record are padding: an all-zero remainder is ignored, and a non-zero remainder is reported as a limitation with `Truncated` set.

`Certificates` loads at most `Certificates` (256) records. At the limit, an eighth-byte header that is entirely zero is treated as padding; a non-zero header sets `Truncated` and appends a limitation.

`CertificateData` returns one blob as stored. It re-runs the header decode to locate the record, which keeps the `File` stateless. The blob is not parsed as PKCS#7, not checked against a digest, not chained, and not trusted. Revision and type are raw values, and a caller that wants a trust decision must make it elsewhere.

### Errors and partial results

| Condition | Result |
|---|---|
| absent directory | `ErrNotFound` |
| contradictory address and size pair | `ErrInvalid` |
| directory slot declared but not loaded | `ErrUnavailable` |
| resource tree or certificate table outside file-backed bytes | `ErrUnavailable` |
| certificate table above its size limit | `ErrLimit` |
| certificate record shorter than its header or longer than the table | `ErrInvalid` |
| reader failure | `ErrRead` |
| limit, shortfall, or undecodable name inside a usable tree | limitation |

`Truncated` means the loaded structure is known to be incomplete. It is set for the depth limit, the entry budget, entries that do not fit the declared directory, an unreadable leaf data entry, a certificate count limit, and trailing non-zero table bytes. It is not set for a merely unavailable or invalid name, because the tree shape is still complete.

Limitations are appended in walk order; structure findings precede the aggregate name and data-range findings.

### Limits

| Limit | Value |
|---|---:|
| resource directory depth below the root | 8 |
| resource entries per call | 4,096 |
| resource name strings per call | 16 MiB |
| one resource name | 4 KiB |
| certificate records | 256 |
| certificate table | 8 MiB |

The depth and entry limits bound traversal. The string limits bound name allocation, and the certificate limits bound the table and the largest blob a caller can request. All values are lowerable through `Limits` and clamped at the package maximum.

### Testing

- Crafted PE32 and PE32+ images with a three-level resource tree mixing named and integer identifiers, a code page, and leaf blobs.
- Empty trees, absent and contradictory directories, trimmed directory slots, and trees outside the file-backed range.
- Entry and depth limits, exhausted name budgets, declared counts that exceed the directory, and self-referential directory cycles.
- Invalid UTF-16, unavailable names, empty resources, leaf entries outside the directory, and data ranges outside the file.
- Reader failure during the walk.
- Certificate tables with two records, unpadded final records, zero padding, non-zero trailing bytes, a table above the size limit, short and over-long records, the count limit, and reader failure.
- `FuzzParse` calls `Resources`, `Certificates`, and checks the counts, path depth, and record arithmetic.
- No differential test is possible: `debug/pe` exposes neither the resource tree nor the certificate table.

## Consequences

- The evidence adapter can report resource paths, data bounds, and certificate record headers without reading payloads, and can hash certificate blobs only when asked.
- Evidence must preserve `NameAvailable` and `DataAvailable`; an empty name or unbacked range is not the same as an absent entry.
- The certificate reader makes no trust claim. A consumer that reports "signed" from the presence of a table would be wrong, and the threat model records that residual risk.
- Resource data and certificate blobs remain unparsed. Executable resource types, version structures, and PKCS#7 content are out of scope.
- A future change to traversal order, depth semantics, or certificate leniency is an observable contract change and needs an ADR update.

## Alternatives considered

- Recursive traversal: rejected because the tree comes from an untrusted file and the Go stack is a poor budget.
- Reporting the loaded prefix of an over-budget sibling list: rejected because it makes a partial directory look complete.
- Treating resource names as UTF-8: rejected because the format is UTF-16 and a byte-wise read would produce plausible but wrong evidence.
- Reading all resource data during `Resources`: rejected because most consumers need only the tree, and the data can be much larger than the metadata budgets.
- Following a data RVA through `MapRVA` and calling it available whenever it is mapped: rejected because a virtual-only tail is mapped but has no file bytes.
- Using `debug/pe`: rejected because it exposes neither the resource tree nor the certificate table.
- Parsing the PKCS#7 payload or verifying signatures: rejected for this phase; it requires cryptography, trust anchors, and an explicit claim the project is not making yet.
