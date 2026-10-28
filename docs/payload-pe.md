# PE payload

This page describes `ree.payload.pe/1`, the payload produced by
`internal/providers/pe` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0011](adr/0011-pe-evidence-adapter.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.pe` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation or unknown was recorded |
| `payload.schema` | `ree.payload.pe/1` |

`Observe` returns an error and no record when the artifact cannot be parsed,
when the subject digest cannot be read, or when any directory read fails with a
reader error. A record is never produced from an unreadable artifact.

## Value encoding

| Kind | Encoding |
|---|---|
| `uint8`, `uint16`, `uint32` | JSON number |
| `uint64` values | decimal string, so values above 2^53 survive |
| digests and raw section names | lowercase hexadecimal |
| names | UTF-8 or UTF-16 text validated by the reader |
| `data_sha256` | SHA-256 of the declared raw section range, or absent |

`uint64` fields are `image_base`, `size_of_stack_reserve`,
`size_of_stack_commit`, `size_of_heap_reserve`, `size_of_heap_commit`, the
overlay members, and the certificate table and record offsets. Every other
numeric field is a JSON number.

`machine`, `characteristics`, `subsystem`, `dll_characteristics`, directory
indexes, and certificate `revision` and `type` are raw values. They are not
mapped to names.

## Members

| Member | Meaning |
|---|---|
| `header` | Validated DOS, PE, and COFF fields, the decoded optional header, and loaded row counts. |
| `data_directories` | One entry per loaded directory slot, in slot order. |
| `sections` | One entry per loaded section header, in table order. |
| `overlay` | Bytes after the headers and the last section raw data, or `null`. |
| `imports` | Import modules and thunks, or `null`. |
| `exports` | Export directory, function slots, and names, or `null`. |
| `resources` | Flattened resource leaves with paths, or `null`. |
| `certificates` | `WIN_CERTIFICATE` record headers, or `null`. |

### Absent, unusable, and empty

`imports`, `exports`, `resources`, and `certificates` are `null` when the
artifact declares no such directory **or** when the reader could not return it.
A present member that decoded nothing uses an empty array.

A `null` member never means "there is nothing there" on its own. When the cause
was a reader limit or a malformed structure, the record has a limitation such
as `import directory unavailable: pe: ...`. When the cause was an absent
directory, the record has no such limitation. Read the limitations before
concluding that a structure is missing from the artifact.

### Header

`dos_magic`, `pe_header_offset`, the COFF fields, and the optional header
fields mirror the validated headers. `loaded_data_directory_count` and
`loaded_section_count` are the rows actually loaded, next to the declared
`number_of_rva_and_sizes` and `number_of_sections`.

`image_base` and the stack and heap sizes are decimal strings. PE32+ carries the
64-bit values; PE32 fields that PE32+ does not define, such as `base_of_data`,
are zero.

### Data directory

`index`, `virtual_address`, and `size` are the raw slot values. In the security
directory, index 4, `virtual_address` is a **file offset**, not an RVA.

### Section

| Field | Meaning |
|---|---|
| `index` | Position in the section table. |
| `name` / `name_available` | Decoded UTF-8 name, and whether decoding succeeded. |
| `name_hex` | Raw eight-byte name field as lowercase hexadecimal. |
| `virtual_size`, `virtual_address`, `size_of_raw_data`, `pointer_to_raw_data` | Raw header values. |
| `pointer_to_relocations`, `pointer_to_linenumbers`, `number_of_relocations`, `number_of_linenumbers`, `characteristics` | Raw header values. |
| `data_sha256` | Digest of the declared raw range, or absent. |

`data_sha256` is omitted for a zero `size_of_raw_data` and when the content
budget could not hash the range. Its absence means "not hashed", not "empty
content". `name_hex` is always present, so an undecodable name still exposes the
raw field.

### Overlay

`offset` and `size` are decimal strings for the byte range after
`SizeOfHeaders` and every section's raw end. The member is `null` when there is
no overlay. Certificate records usually fall inside this range but are reported
under `certificates`, not as overlay content.

### Imports

`imports.modules` holds one entry per descriptor. Each module carries its name,
`name_rva`, the raw descriptor fields, `thunk_source`, its thunks, and a
`truncated` flag.

`thunk_source` is `original_first_thunk` when that array was used and
`first_thunk` when it was zero and the IAT was read instead. A thunk with
`by_ordinal` true has an `ordinal` and no name; a named thunk has a `hint`, a
`name_rva`, and `name_available`.

A module's `truncated` flag is set when the payload budget cut its thunk list.
The enclosing `imports.truncated` flag is also set in that case.

### Exports

`exports` carries the directory name, the raw version and timestamp fields, the
ordinal `base`, the declared function and name counts, the three array addresses,
the function slots, and a `truncated` flag.

| Slot field | Meaning |
|---|---|
| `index` | Position in the export address table. |
| `ordinal` | `base` plus `index`. |
| `rva` | Exported address; zero for an unused slot. |
| `name` / `name_available` / `name_rva` | Name and its RVA. An export may legitimately have none. |
| `forwarder` / `forwarder_available` | Stored forwarder target, never followed. |

### Resources

`resources.resources` is a flat list of leaves in depth-first on-disk order.
Each leaf has a `path` from the type level, the declared `data_rva`,
`data_size`, `code_page`, and `data_available`.

A path level that is a name keeps `is_name` true; `name_available` is false when
the UTF-16 name could not be decoded, and then the empty `name` is not a decoded
value. An integer level keeps `is_name` false and an empty `name`.

Resource bytes are not read, not returned, and not hashed. `data_available`
reports only that the declared range is file-backed, and a resolved leaf makes
the record carry the unknown "resource data is not interpreted".

### Certificates

`certificates` carries the security directory `offset` and `size` and one entry
per record: `index`, `offset`, `length`, `revision`, `type`, `data_offset`, and
`data_size`.

Certificate blobs are not read and not hashed. The record headers describe what
is present, not whether it is valid. A non-empty table makes the record carry
the unknown "certificate signatures are not validated".

## Completeness

Arrays may be prefixes of the artifact's tables when the payload budget is
exhausted. The affected member has `truncated: true` and the record has
`coverage: partial` with a limitation naming how many entries were omitted.

Limitations and unknowns are deduplicated by the evidence encoder. The adapter
caps them at 128 and 32 entries with a final `additional ... omitted` statement.

Unknowns report structures that are present but deliberately not decoded: COFF
symbols, base relocations, debug and PDB references, TLS callbacks, bound
imports, delay-load imports, CLR metadata, certificate signatures, and resource
data.

## Abridged example

The following fragment is abridged for readability and is not a complete
record. Values come from the crafted test fixture.

```json
{
  "provider": {"id": "builtin.pe", "profile": "default", "version": "0.1.0"},
  "authority": "observed",
  "coverage": "partial",
  "limitations": [],
  "unknowns": [
    "certificate signatures are not validated",
    "resource data is not interpreted"
  ],
  "payload": {
    "schema": "ree.payload.pe/1",
    "header": {
      "dos_magic": 23117,
      "pe_header_offset": 128,
      "machine": 332,
      "number_of_sections": 1,
      "size_of_optional_header": 224,
      "characteristics": 258,
      "optional": {
        "magic": 267,
        "image_base": "4194304",
        "section_alignment": 4096,
        "file_alignment": 512,
        "size_of_image": 8192,
        "size_of_headers": 512,
        "subsystem": 3,
        "number_of_rva_and_sizes": 16
      },
      "loaded_data_directory_count": 16,
      "loaded_section_count": 1
    },
    "sections": [
      {
        "index": 0,
        "name": ".rdata",
        "name_available": true,
        "name_hex": "2e72646174610000",
        "virtual_size": 361,
        "virtual_address": 4096,
        "size_of_raw_data": 361,
        "pointer_to_raw_data": 512,
        "characteristics": 1073741888,
        "data_sha256": "da021369a99008071621db6193e876c538fd8db614149083fff93cd9c5c7dab7"
      }
    ],
    "overlay": {"offset": "873", "size": "55"},
    "imports": {
      "modules": [
        {
          "index": 0,
          "name": "KERNEL32.dll",
          "name_available": true,
          "name_rva": 4096,
          "original_first_thunk": 4120,
          "first_thunk": 4120,
          "thunk_source": "original_first_thunk",
          "thunks": [
            {"index": 0, "by_ordinal": false, "ordinal": 0, "hint": 0,
             "name": "Sleep", "name_available": true, "name_rva": 4112},
            {"index": 1, "by_ordinal": true, "ordinal": 12, "hint": 0,
             "name": "", "name_available": false, "name_rva": 0}
          ],
          "truncated": false
        }
      ],
      "truncated": false
    },
    "exports": {
      "name": "sample.dll",
      "name_available": true,
      "base": 1,
      "number_of_functions": 3,
      "number_of_names": 2,
      "exports": [
        {"index": 0, "ordinal": 1, "rva": 8192, "name": "Alpha",
         "name_available": true, "forwarder_available": false},
        {"index": 1, "ordinal": 2, "rva": 4300, "name": "Forwarded",
         "name_available": true, "forwarder": "KERNEL32.Sleep",
         "forwarder_available": true},
        {"index": 2, "ordinal": 3, "rva": 8196, "name": "",
         "name_available": false, "forwarder_available": false}
      ],
      "truncated": false
    },
    "resources": {
      "resources": [
        {
          "path": [
            {"is_name": false, "name": "", "name_available": false, "id": 10},
            {"is_name": true, "name": "RCDATA", "name_available": true, "id": 0},
            {"is_name": false, "name": "", "name_available": false, "id": 1033}
          ],
          "data_rva": 4444,
          "data_size": 13,
          "code_page": 1252,
          "data_available": true
        }
      ],
      "truncated": false
    },
    "certificates": {
      "offset": "880",
      "size": 40,
      "certificates": [
        {"index": 0, "offset": "880", "length": 19, "revision": 512,
         "type": 2, "data_offset": "888", "data_size": 11}
      ],
      "truncated": false
    }
  }
}
```
