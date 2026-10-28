# ADR 0019: plist reader and evidence adapter

- Status: accepted
- Date: 2026-10-28

## Context

Apple platforms and many macOS applications ship configuration in property
lists. A property list has two on-disk representations: the XML document and
the binary `bplist` container, which stores a flat object table, an offset
table, and a 32-byte trailer. Both are small enough to read in memory, but both
let the writer declare the shape of the document: the binary trailer declares
how many objects exist, where the object table starts, and which object is the
root, and every reference in a collection points at another object by index.

An untrusted property list can therefore declare a huge object count, place an
object outside the object area, point a reference past the table, nest
collections until the reader recurses without limit, or declare a string whose
length exceeds the artifact. The XML representation has the same shape of
problem through element nesting and text size. A reader must bound all of it and
must not present a document it could not finish reading as complete.

The tool never executes, writes, or resolves anything from an artifact. A
property list is inventoried as data: references stay references and are never
followed into another artifact.

## Decisions

### Package boundary and API

The reader lives in `internal/formats/plist` and exposes:

- `Detect(prefix)` returning `FormatBinary`, `FormatXML`, or `FormatUnknown`;
- `Parse(io.ReaderAt, size)` and `ParseWithLimits(io.ReaderAt, size, Limits)`;
- `Plist` with `Format`, `Version`, `Objects`, `TopObject`, `Truncated`, and
  `Limitations`;
- `ObjectAt(index)` and `Size()`.

`Object` carries its index, its type, and only the value fields that belong to
that type: `Keys` and `Values` for a dictionary, `Refs` for an array or set,
`Text` with `TextAvailable` and `TextBytes` for a string, `Integer` as canonical
decimal text, `Real`, `Boolean`, `DateUnix` with `DateAvailable`, `DataBytes`,
and `UID`. Every object also carries `Reachable`, `Depth`, and its own
limitations.

### Flat object table, not a live tree

A parsed property list is a table of validated values in document or
object-table order. References are object indices, never pointers, and the
reader never materialises a nested Go value for a dictionary or array.

This keeps a hostile document cheap to inventory: a shared subtree is stored
once, a cycle is representable, and the inventory size is the object count the
artifact declares rather than the expansion a naive decoder would produce. It
also makes the evidence projection a direct walk of one slice.

### Binary validation

The first eight bytes must be `bplist` plus a supported version (`00`, `15`, or
`16`). The trailer is read at `size - 32` and checked before any object is
decoded:

- offset integer size and object reference size must each be in `1..8`;
- `numObjects` must be non-zero and at most `Limits.Objects`;
- `topObject` must be below `numObjects`;
- `tableOffset` must be at least 8 and at most `size - 32`;
- the offset table (`numObjects * offsetIntSize` bytes) must fit before the
  trailer.

Each entry of the offset table must lie in `[8, tableOffset)`, so no object can
be decoded from the header, the offset table, or the trailer. A collection
reference is validated against `numObjects` while it is read, so a reference
cannot escape the table.

An integer wider than 8 bytes keeps its low 64 bits and records a limitation. A
UID wider than 8 bytes does the same. A real or date that is not finite is
inventoried with a limitation instead of being converted into an undefined
value.

### Depth is a reachability walk

Depth is not the recursion depth of the decoder; it is the distance from
`TopObject` in the reference graph. After every object is decoded, a
breadth-first walk from the top object marks each object reachable and records
its depth. When the walk would descend past `Limits.Depth`, the parent keeps its
type and scalar value, loses its child references, records a limitation, and
the plist is marked truncated.

Objects that the walk never reaches stay in the inventory with
`Reachable=false`, `Depth=-1`, and one aggregate limitation naming how many
there are. They do not mark the plist truncated, because the document was fully
read; they are simply not part of the value the top object describes.

### XML as a token stream

The XML representation is decoded with `encoding/xml` one token at a time. The
root must be `<plist>` with exactly one value element, and trailing text or a
second value is invalid. A dictionary alternates `<key>` and a value element; an
array holds value elements; `<true/>`, `<false/>`, `<string>`, `<integer>`,
`<real>`, `<date>`, `<data>`, and `<uid>` map to their types. An unsupported
element is inventoried as an unknown object with a limitation and its subtree is
skipped.

Because the decoder is a token stream, the object count and depth limits apply
before a subtree is expanded, and a document that exceeds them is skipped rather
than buffered. `integer`, `real`, `date`, `data`, and `uid` text is validated but
never repaired: an unparsable value keeps the raw text bytes and a limitation.

### Limits and errors

`Limits` covers artifact size, object count, graph depth, and one string's
bytes. Zero selects the default; a value above the package maximum is clamped.
Sentinels:

- `ErrInvalid`: the structure contradicts itself.
- `ErrTruncated`: the artifact ends before a required structure does.
- `ErrLimit`: a configured size or count limit was reached where no coherent
  inventory can be produced.
- `ErrRead`: the underlying reader failed.
- `ErrOutOfRange`: an object index is outside the inventory.

An object, string, or depth limit reached after the structure is valid returns a
non-nil plist with `Truncated` set and a nil error. A trailer that cannot be
interpreted returns a nil plist and an error.

### Evidence adapter

`internal/providers/plist` emits one `ree.evidence/1` record per artifact with a
`ree.payload.plist/1` payload. `Observe` validates the provider version, parses
the artifact, hashes the whole artifact stream, projects the artifact and every
object, and lets `evidence.Encode` validate the record.

- `format`, `version`, `top_object`, `object_count`, and
  `loaded_object_count` describe the container; `top_object` is `-1` when the
  root was skipped by a limit.
- Object indices in `keys`, `values`, and `refs` are the same indices the
  payload reports, so a consumer can resolve a reference without re-parsing.
- 64-bit values are decimal strings: `date_unix`, `data_bytes`, and `uid`.
  `integer` is the canonical decimal text the reader produced.
- A real is a JSON number and is `null` when the value is not finite; a date is
  `null` when it is not a finite timestamp.
- `text_hex` carries the raw stored string bytes, so a string that is not valid
  UTF-8 or that exceeded the string limit still has a stable representation.
- The payload budget charges the artifact envelope first and then spends the
  remainder on objects in index order. A payload that cannot hold every object
  records `payload budget omits objects after N of M` and marks coverage
  partial.
- An artifact limitation or a truncated inventory makes coverage partial.
  Per-object limitations stay in the payload.

The provider reports no unknowns: the reader either decodes a value or states
why it could not, and there is no absent table to confuse with an empty one.

### Deferred

The APK reader and `ree.payload.apk/1`, wiring any Phase 6 provider into
`ree analyze` and `ree_analyze`, format detection, `Counts`, inventory/search/
compare commands, and the MCP surface change are deferred to later Phase 6
increments.

## Consequences

- One deterministic inventory covers both representations with the same
  object model and the same evidence projection.
- A crafted object count, offset, reference, depth, or string length is bounded
  before it can allocate or recurse without limit.
- A shared or cyclic subtree is represented once and walked safely, because
  depth is measured on the reference graph rather than on decoder recursion.
- Unreachable objects stay visible instead of being silently dropped, so a
  document that hides a payload off the root path is still reported.
- String text is capped and the raw bytes are preserved, so a very long string
  is reported as incomplete rather than truncated without notice.
- There is no differential oracle for property lists. Fixtures, crafted
  malformed artifacts, and fuzzing carry the verification burden.
