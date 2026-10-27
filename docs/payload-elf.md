# ELF payload

This page describes `ree.payload.elf/1`, the payload produced by
`internal/providers/elf` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0007](adr/0007-elf-evidence-adapter.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.elf` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation or unknown was recorded |
| `payload.schema` | `ree.payload.elf/1` |

`Observe` returns an error and no record when the artifact cannot be parsed,
when the subject digest cannot be read, or when any table read fails. A record
is never produced from an unreadable artifact.

## Value encoding

| Kind | Encoding |
|---|---|
| `uint8`, `uint16`, `uint32` | JSON number |
| `uint64` ELF fields | decimal string, so values above 2^53 survive |
| signed `r_addend` | signed decimal string |
| digests, build-id, note descriptors | lowercase hexadecimal |
| names and comments | UTF-8 text validated by the reader |
| `data_sha256` | SHA-256 of the declared file range, or absent |

`data_sha256` is omitted for `SHT_NOBITS` sections and zero-length ranges. Its
absence means "not hashed", not "empty content". A segment that covers the same
bytes as a section carries the same digest.

## Members

| Member | Meaning |
|---|---|
| `header` | Validated file header, declared counts, and loaded row counts. |
| `sections` | One entry per loaded section header, in table order. |
| `segments` | One entry per loaded program header, in table order. |
| `symbols` | Flat list from every loaded symbol table, with `table_index` provenance. |
| `relocations` | Flat list from every loaded relocation section, with `section_index` provenance. |
| `notes` | One entry per `SHT_NOTE` entry. |
| `build_id` | GNU build-id descriptor, or `null`. |
| `comments` | Non-empty NUL-separated `.comment` entries, in section order. |

### Header

`class` is `ELF32` or `ELF64`, `data` is `little-endian` or `big-endian`.
`*_count` fields are the declared values after extended numbering, encoded as
decimal strings. `loaded_*_count` are the rows actually loaded. The
`extended_*` booleans report that extended numbering was used.

`type`, `machine`, `version`, and `flags` are raw ELF values; the adapter does
not map them to names.

### Section

`index`, `type`, `link`, and `info` are raw header values. `flags`, `address`,
`offset`, `size`, `address_align`, and `entry_size` are `uint64` strings.
`name_available` is false when the reader could not resolve the name; the empty
`name` must then not be read as "unnamed".

### Segment

`type`, `flags`, offsets, addresses, sizes, and `align` mirror the program
header. `filesz` covers the hashed range; `memsz` may be larger.

### Symbol

| Field | Meaning |
|---|---|
| `table_index` | Section header index of the symbol table. |
| `index` | Position within that table; index 0 is the null symbol. |
| `name` / `name_offset` | Resolved name and raw `st_name` offset. |
| `info`, `other`, `section_index` | Raw `st_info`, `st_other`, `st_shndx`. |
| `extended_section_index` | `section_index` came from `SHT_SYMTAB_SHNDX`. |
| `value`, `size` | `uint64` strings. |

`table_index` plus `index` is the unique identity. Index spaces are per table.

### Relocation

`section_index` names the relocation section; `target_section_index` is its raw
`sh_info`. `offset` and `info` are `uint64` strings; `symbol_index` and `type`
are the decoded fields. `has_addend` reports whether `addend` came from the
entry. When it is false, `addend` is `"0"` and the real addend lives at the
relocated location, which this schema does not resolve.

### Note and build-id

Every note carries `descriptor_size` and `descriptor_sha256`. `descriptor_hex`
is present only when the descriptor is at most 4 KiB.

`build_id.hex` and `build_id.size` describe the GNU build-id. `null` means the
artifact has none; if the reader could not prove absence, the record carries a
limitation instead.

## Completeness

Arrays may be prefixes of the artifact's tables when the payload budget is
exhausted. The record then has `coverage: partial` and a limitation naming how
many entries were omitted. Consumers must read coverage and limitations before
treating an array as the complete table.

Limitations and unknowns are sorted and deduplicated by the evidence encoder.
The adapter caps them at 128 and 32 entries with a final `additional ...
omitted` statement.

## Abridged example

The following fragment is abridged for readability and is not a complete
record. Values come from the crafted test fixture.

```json
{
  "provider": {"id": "builtin.elf", "profile": "default", "version": "0.1.0"},
  "authority": "observed",
  "coverage": "complete",
  "limitations": [],
  "unknowns": [],
  "payload": {
    "schema": "ree.payload.elf/1",
    "header": {
      "class": "ELF64",
      "data": "little-endian",
      "type": 3,
      "machine": 62,
      "entry": "120",
      "section_header_count": "8",
      "loaded_section_header_count": 8,
      "section_name_index": 7
    },
    "sections": [
      {
        "index": 1,
        "name": ".text",
        "name_available": true,
        "type": 1,
        "flags": "6",
        "offset": "128",
        "size": "8",
        "data_sha256": "c2cee54af4ab2b15bed699ef713a240a57d0296cdf0381bec2401ee28ba0cd9a"
      }
    ],
    "segments": [
      {
        "index": 0,
        "type": 1,
        "flags": 5,
        "offset": "128",
        "file_size": "8",
        "memory_size": "8",
        "data_sha256": "c2cee54af4ab2b15bed699ef713a240a57d0296cdf0381bec2401ee28ba0cd9a"
      }
    ],
    "symbols": [
      {"table_index": 5, "index": 1, "name": "main", "name_offset": 1,
       "info": 18, "other": 0, "section_index": 1,
       "extended_section_index": false, "value": "120", "size": "8"}
    ],
    "relocations": [
      {"section_index": 6, "target_section_index": 1, "index": 0,
       "offset": "8", "info": "4294967297", "symbol_index": 1, "type": 1,
       "addend": "-4", "has_addend": true}
    ],
    "notes": [
      {"section_index": 3, "name": "GNU", "type": 3, "descriptor_size": 8,
       "descriptor_sha256": "8a851ff82ee7048ad09ec3847f1ddf44944104d2cbd17ef4e3db22c6785a0d45",
       "descriptor_hex": "0001020304050607"}
    ],
    "build_id": {"hex": "0001020304050607", "size": 8},
    "comments": ["ree-test 1.0", "second entry"]
  }
}
```
