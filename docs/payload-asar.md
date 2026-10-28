# ASAR payload

This page describes `ree.payload.asar/1`, the payload produced by
`internal/providers/asar` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0018](adr/0018-asar-reader.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.asar` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation was recorded |
| `payload.schema` | `ree.payload.asar/1` |

One artifact produces exactly one record. `Observe` returns an error and no
record when the header cannot be parsed, because a record built from a partial
header would understate the artifact.

## Value encoding

| Kind | Encoding |
|---|---|
| `uint8`, `uint16`, `uint32` | JSON number |
| 64-bit sizes and offsets | decimal string, so values above 2^53 survive |
| raw path bytes | lowercase hexadecimal |
| decoded paths and link targets | text validated by the reader; never repaired |
| absent value | `null` |

The 64-bit decimal strings are `artifact.header_bytes`, `artifact.json_bytes`,
`artifact.data_offset`, `entries[].size`, `entries[].offset`, and
`entries[].data_offset`.

## Members

### Artifact

| Member | Meaning |
|---|---|
| `header_bytes` | declared header pickle payload size |
| `json_bytes` | declared JSON string payload size, including alignment padding |
| `data_offset` | absolute offset where file data begins |
| `entry_count` | entries the reader loaded |
| `loaded_entry_count` | entries projected into this payload |
| `truncated` | a depth or entry limit stopped the directory walk |
| `status` | `parsed` when the header and directory were decoded |
| `limitations` | why the inventory is incomplete |

`entry_count` above `loaded_entry_count` means the payload budget omitted
entries, not that the directory walk stopped; `truncated` reports the latter.

### Entry

| Member | Meaning |
|---|---|
| `index` | position in sorted path order |
| `path`, `path_available`, `path_hex` | decoded path, its availability, and the raw bytes |
| `unsafe` | why the path cannot be used, empty when it is safe |
| `type` | `file`, `directory`, `link`, or `other` |
| `size`, `offset` | declared file fields relative to `data_offset`, `null` when absent |
| `data_offset` | absolute artifact offset of the file data, `null` when the range is missing or outside the artifact |
| `executable` | declared executable bit |
| `unpacked` | the file data lives outside the artifact |
| `range_outside` | the declared range lies outside the artifact |
| `integrity` | declared integrity metadata, `null` when absent |
| `link_target`, `link_target_available` | declared link target; never followed |
| `limitations` | why this entry's view is incomplete or its content cannot be read |

A directory has no `size`, `offset`, or `data_offset`. A link has a
`link_target` and no content. An `unpacked` file keeps its declared size and
offset but has no readable content.

### Integrity

| Member | Meaning |
|---|---|
| `algorithm`, `algorithm_available` | declared hash algorithm |
| `hash`, `hash_available` | declared digest, lowercased when the header stores hex |
| `block_count` | number of declared block digests |

Integrity metadata is reported as declared and is never verified. Verification
would require reading content the caller may not request, and the payload does
not claim that the digest matches the file.

## Completeness

`coverage` is `partial` when the record carries a limitation. That happens when
the reader stopped at a depth or entry limit, or when the payload budget could
not hold every entry. Per-entry limitations such as `file content is unpacked`,
`content range is outside the artifact`, or an unsafe path stay in the payload:
the inventory itself is complete, but the named entry's content is unavailable.

`truncated` in the payload and `payload budget omits entries after N of M` in
the record limitations are independent. A complete but large directory can be
truncated by the payload budget without the reader's walk having stopped.

## Example

```json
{
  "schema": "ree.payload.asar/1",
  "artifact": {
    "header_bytes": "212",
    "json_bytes": "204",
    "data_offset": "220",
    "entry_count": 2,
    "loaded_entry_count": 2,
    "truncated": false,
    "status": "parsed",
    "limitations": []
  },
  "entries": [
    {
      "index": 0,
      "path": "index.js",
      "path_available": true,
      "path_hex": "696e6465782e6a73",
      "unsafe": "",
      "type": "file",
      "size": "12",
      "offset": "0",
      "data_offset": "220",
      "executable": false,
      "unpacked": false,
      "range_outside": false,
      "integrity": null,
      "link_target": "",
      "link_target_available": false,
      "limitations": []
    },
    {
      "index": 1,
      "path": "lib",
      "path_available": true,
      "path_hex": "6c6962",
      "unsafe": "",
      "type": "directory",
      "size": null,
      "offset": null,
      "data_offset": null,
      "executable": false,
      "unpacked": false,
      "range_outside": false,
      "integrity": null,
      "link_target": "",
      "link_target_available": false,
      "limitations": []
    }
  ]
}
```
