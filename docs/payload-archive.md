# Archive payload

This page describes `ree.payload.archive/1`, the payload produced by
`internal/providers/archive` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0017](adr/0017-archive-evidence-adapter.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.archive` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation was recorded |
| `payload.schema` | `ree.payload.archive/1` |

One artifact produces exactly one record. A nested container is a subtree of
that record, never a separate record, so `subject.sha256` always covers a file a
consumer can hash.

`Observe` returns an error and no record when the artifact cannot be parsed. A
nested member that cannot be read or parsed keeps its own status and limitation
and does not fail the record.

## Value encoding

| Kind | Encoding |
|---|---|
| `uint8`, `uint16`, `uint32` | JSON number |
| 64-bit sizes, offsets, and times | decimal string, so values above 2^53 survive |
| raw name bytes | lowercase hexadecimal |
| decoded names | text validated by the reader; never repaired |
| absent value | `null` |

The 64-bit decimal strings are `artifact.size`, `header_bytes`,
`compressed_size`, `uncompressed_size`, `modified_unix`, `header_offset`, and
`data_offset`.

## Members

### Container

Every container — the artifact and each nested member — has the same shape:

| Member | Meaning |
|---|---|
| `depth` | `0` for the artifact, `1` or more for a nested member |
| `container` | `zip`, `tar`, or `gzip` |
| `size` | artifact size in bytes; `null` for a nested member |
| `entry_count` | entries the reader loaded |
| `loaded_entry_count` | entries projected into this payload |
| `truncated` | the directory or header chain is incomplete |
| `status` | `parsed`, or the sentinel that stopped a nested parse |
| `gzip` | first gzip member header, `null` otherwise |
| `limitations` | why this container's view is incomplete |
| `entries` | entries of a nested container; `null` for the artifact, whose entries are at the top level |

`status` is `parsed` for the artifact. A nested container that fails reports
`invalid`, `truncated`, `limit`, `unavailable`, or `read`, with the reader's
error text in its own `limitations`.

`entry_count` above `loaded_entry_count` means the payload budget omitted
entries; it is not the same as `truncated`, which mirrors the reader's chain.

### gzip header

| Member | Meaning |
|---|---|
| `name`, `name_available`, `name_hex` | original file name, its availability, and the raw bytes |
| `comment`, `comment_available` | comment text and its availability |
| `modified_unix` | modification time in Unix seconds, `null` when absent |
| `os` | gzip operating system identifier |
| `extra_bytes` | declared extra field length |
| `header_bytes` | bytes before the compressed data |

The header describes the first member only. Concatenated members are decoded by
the reader on demand, not enumerated.

### Entry

| Member | Meaning |
|---|---|
| `index` | position in the container's entry list |
| `name`, `name_available`, `name_hex` | decoded name, its availability, and the raw bytes |
| `unsafe` | why the name cannot be used, empty when it is safe |
| `type` | `file`, `directory`, `symlink`, `hardlink`, `fifo`, `character-device`, `block-device`, or `other` |
| `method` | `stored`, `deflate`, or the standard ZIP method name or number |
| `mode` | Unix permission and type bits, `null` when the container stores none |
| `encrypted` | ZIP entry data is encrypted; its content is never read |
| `compressed_size`, `uncompressed_size` | declared sizes, `null` when the container stores none |
| `crc32` | declared CRC-32 of the uncompressed bytes, `null` when absent |
| `modified_unix` | declared modification time, `null` when absent |
| `header_offset`, `data_offset` | stored byte offsets |
| `link_target`, `link_target_available` | declared tar link target |
| `sparse` | GNU sparse layout is not decoded |
| `limitations` | why this entry's view is incomplete |
| `nested` | contained container, `null` when none was detected |

`unsafe` names a path the reader refused to treat as a relative archive path:
absolute, drive-letter, backslash-separated, rooted at `.`, or containing a
parent-directory segment. The entry is still inventoried; nothing is extracted.

`nested` is present only for a regular-file entry with a safe name, no
encryption, and a stored or deflate method whose prefix the reader recognizes
as a container.

### Nesting

Nested detection inspects one level by default and at most two. It also stops
at 256 parsed containers (4096 maximum) and 64 MiB of decoded member bytes
(1 MiB minimum) per payload, shared across levels. When a budget stops
detection, one limitation says so and no further members are inspected.

A nested member that is recognized but unreadable keeps a `status` and an empty
`entries` list, so a consumer can distinguish "not a container" from "container
that could not be read".

## Completeness

Coverage is `complete` only when the record has no limitation. The adapter
records no unknowns.

| Situation | Effect |
|---|---|
| Reader limitation | copied to record limitations |
| Reader truncation | `truncated` plus `artifact inventory is partial` |
| Nested parse failure | nested `status` plus one record limitation |
| Nested truncation | nested `truncated` plus one record limitation |
| Payload budget exhaustion | `loaded_entry_count` below `entry_count` plus one limitation |
| Nested byte or member budget | one limitation, detection stops |

## Abridged example

```json
{
  "schema": "ree.payload.archive/1",
  "artifact": {
    "depth": 0,
    "container": "tar",
    "size": "10240",
    "entry_count": 1,
    "loaded_entry_count": 1,
    "truncated": false,
    "status": "parsed",
    "gzip": null,
    "limitations": [],
    "entries": null
  },
  "entries": [
    {
      "index": 0,
      "name": "inner.zip",
      "name_available": true,
      "name_hex": "696e6e65722e7a6970",
      "unsafe": "",
      "type": "file",
      "method": "stored",
      "compressed_size": "412",
      "uncompressed_size": "412",
      "nested": {
        "depth": 1,
        "container": "zip",
        "size": null,
        "entry_count": 1,
        "loaded_entry_count": 1,
        "truncated": false,
        "status": "parsed",
        "gzip": null,
        "limitations": [],
        "entries": [
          {
            "index": 0,
            "name": "leaf.txt",
            "name_available": true,
            "type": "file",
            "method": "stored",
            "nested": null
          }
        ]
      }
    }
  ]
}
```

The example is abridged: fields that were not relevant are omitted rather than
shown as defaults.
