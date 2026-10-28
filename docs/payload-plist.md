# plist payload

This page describes `ree.payload.plist/1`, the payload produced by
`internal/providers/plist` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0019](adr/0019-plist-reader.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.plist` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation was recorded |
| `payload.schema` | `ree.payload.plist/1` |

One artifact produces exactly one record. `Observe` returns an error and no
record when the artifact cannot be parsed, because a record built from a partial
structure would understate the artifact.

## Value encoding

| Kind | Encoding |
|---|---|
| object count, index, depth | JSON number |
| `integer` | canonical decimal text |
| `date_unix`, `data_bytes`, `uid` | decimal string, so 64-bit values survive canonical JSON |
| `real` | JSON number, `null` when not finite |
| raw string bytes | lowercase hexadecimal in `text_hex` |
| absent value | `null` |

## Members

### Artifact

| Member | Meaning |
|---|---|
| `format` | `binary` or `xml` |
| `version` | binary plist version such as `00`, empty for XML |
| `object_count` | objects the reader loaded |
| `loaded_object_count` | objects projected into this payload |
| `top_object` | index of the root value, `-1` when a limit skipped it |
| `truncated` | an object, string, or depth limit stopped the inventory |
| `status` | `parsed` when the structure was decoded |
| `limitations` | why the inventory is incomplete |

`object_count` above `loaded_object_count` means the payload budget omitted
objects, not that the reader stopped; `truncated` reports the latter.

### Object

Objects are emitted once at the top level, in document or object-table order.
`artifact.objects` does not exist; there is no second copy.

| Member | Meaning |
|---|---|
| `index` | position in the inventory, and the value a reference carries |
| `type` | `dictionary`, `array`, `set`, `string`, `integer`, `real`, `boolean`, `date`, `data`, `uid`, `null`, or `unknown` |
| `reachable` | the object is reachable from `top_object` within the depth limit |
| `depth` | distance from `top_object`, `-1` when unreachable |
| `keys`, `values` | parallel object indices of a dictionary, omitted otherwise |
| `refs` | element indices of an array or set, omitted otherwise |
| `text`, `text_available` | decoded string and whether it is valid |
| `text_hex` | raw stored string bytes, capped by the string limit |
| `boolean` | value of a boolean object |
| `integer` | canonical decimal text of an integer object, empty otherwise |
| `real` | finite real value, `null` otherwise |
| `date_unix` | Unix seconds of a finite date, `null` otherwise |
| `data_bytes` | declared length of a data object, `null` otherwise |
| `uid` | value of a UID object, `null` otherwise |
| `limitations` | why this object's view is incomplete |

A reference is an index into this same list. A consumer that follows a
reference must check it against `object_count` itself; the reader already
validated it, but the payload is not a navigation API.

## Completeness

`coverage` is `partial` when the record carries a limitation. That happens when
the reader stopped at an object, string, or depth limit, when objects are
unreachable from the root, or when the payload budget could not hold every
object. Per-object limitations such as `string is not valid UTF-8`,
`integer exceeds 64 bits`, or `unsupported simple marker 0x0f` stay in the
payload: the inventory itself is complete, but the named object's value is not.

An unreachable object does not set `truncated`. The document was fully read, but
the object is not part of the value the root describes, so the record states
that as a limitation instead of claiming a short read.

## Example

```json
{
  "schema": "ree.payload.plist/1",
  "artifact": {
    "format": "xml",
    "version": "",
    "object_count": 4,
    "loaded_object_count": 4,
    "top_object": 0,
    "truncated": false,
    "status": "parsed",
    "limitations": ["1 objects are not reachable from the top object"]
  },
  "objects": [
    {
      "index": 0,
      "type": "dictionary",
      "reachable": true,
      "depth": 0,
      "keys": [1],
      "values": [2],
      "text": "",
      "text_available": false,
      "text_hex": "",
      "boolean": false,
      "integer": "",
      "real": null,
      "date_unix": null,
      "data_bytes": null,
      "uid": null,
      "limitations": []
    },
    {
      "index": 1,
      "type": "string",
      "reachable": true,
      "depth": 1,
      "text": "name",
      "text_available": true,
      "text_hex": "6e616d65",
      "boolean": false,
      "integer": "",
      "real": null,
      "date_unix": null,
      "data_bytes": null,
      "uid": null,
      "limitations": []
    },
    {
      "index": 2,
      "type": "integer",
      "reachable": true,
      "depth": 1,
      "text": "",
      "text_available": false,
      "text_hex": "3132",
      "boolean": false,
      "integer": "12",
      "real": null,
      "date_unix": null,
      "data_bytes": null,
      "uid": null,
      "limitations": []
    },
    {
      "index": 3,
      "type": "string",
      "reachable": false,
      "depth": -1,
      "text": "hidden",
      "text_available": true,
      "text_hex": "68696464656e",
      "boolean": false,
      "integer": "",
      "real": null,
      "date_unix": null,
      "data_bytes": null,
      "uid": null,
      "limitations": []
    }
  ]
}
```
