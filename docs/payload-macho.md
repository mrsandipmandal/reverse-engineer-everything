# Mach-O payload

This page describes `ree.payload.macho/1`, the payload produced by
`internal/providers/macho` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0015](adr/0015-macho-evidence-adapter.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.macho` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation or unknown was recorded |
| `payload.schema` | `ree.payload.macho/1` |

One artifact produces exactly one record. A universal binary is not split into
one record per architecture: `subject.sha256` covers the whole file, and
`slices` lists every architecture it declares.

`Observe` returns an error and no record when the artifact cannot be parsed,
when the subject digest cannot be read, or when a section or load command read
fails with a reader error. A record is never produced from an unreadable
artifact, and a slice that cannot be parsed does not fail the record.

## Value encoding

| Kind | Encoding |
|---|---|
| `uint8`, `uint16`, `uint32` | JSON number |
| 64-bit addresses, offsets, sizes, and values | decimal string, so values above 2^53 survive |
| digests and raw name fields | lowercase hexadecimal |
| names | text validated by the reader; never repaired |
| `data_sha256` | SHA-256 of the stored section bytes, or absent |

The 64-bit decimal strings are `artifact.size`, `slice.offset`, `slice.size`,
`segment.vm_address`, `segment.vm_size`, `segment.file_offset`,
`segment.file_size`, `section.address`, `section.size`, `entry.entry_offset`,
`entry.stack_size`, `symbols.string_bytes`, `symbol.value`,
`code_signature.data_offset`, and `code_signature.data_size`.

## Members

### Artifact

| Member | Meaning |
|---|---|
| `magic`, `magic_name` | canonical magic and its name: `mach-o-32`, `mach-o-64`, `fat-32`, `fat-64` |
| `fat` | the artifact carries a universal header |
| `byte_order` | byte order of the artifact header: `little` or `big` |
| `size` | artifact size in bytes |
| `slice_count` | entries in the universal header, or one for a thin image |
| `loaded_slice_count` | slices that parsed into an image |
| `truncated` | the universal header or slice table is incomplete |

### Slice

`index`, `cpu_type`, `cpu_subtype`, `offset`, `size`, `alignment`, and `status`.

`status` is `parsed` when the slice produced an image, otherwise it names the
sentinel that stopped parsing: `invalid`, `truncated`, `limit`, `unavailable`,
or `read`. A non-`parsed` slice carries the error text in its own
`limitations` and adds a record limitation, so a consumer can tell a universal
binary with one broken architecture from a complete one.

`header`, `segments`, `sections`, `dylibs`, `build`, `entry`, `symbols`, and
`code_signature` are null or empty when the slice did not parse or the command
is absent.

### Header

`magic`, `magic_name`, `is_64`, `byte_order`, `cpu_type`, `cpu_subtype`,
`file_type`, `file_type_name`, `flags`, `reserved`, `declared_command_count`,
`loaded_command_count`, `loaded_segment_count`, `loaded_section_count`,
`size_of_commands`, and `truncated`.

`declared_command_count` and `size_of_commands` are the header values; the
`loaded_*` members are what the reader actually loaded. A difference between
them, or `truncated`, means the view is a prefix.

`file_type_name` is one of `object`, `execute`, `fvmlib`, `core`, `preload`,
`dylib`, `dylinker`, `bundle`, `dylib_stub`, `dsym`, `kext_bundle`, `fileset`,
or empty for an unknown value.

### Segment

`index`, `command`, `name`, `name_available`, `name_hex`, `vm_address`,
`vm_size`, `file_offset`, `file_size`, `max_protection`, `init_protection`,
`flags`, `declared_section_count`, `first_section`, and `section_count`.

`first_section` and `section_count` locate the segment's window in the
slice-level `sections` list, which is numbered across every segment.

### Section

`index`, `segment_index`, `name`, `name_available`, `name_hex`, `address`,
`size`, `offset`, `alignment`, `relocation_offset`, `number_of_relocations`,
`flags`, `reserved1`, `reserved2`, `reserved3`, and `data_sha256`.

`data_sha256` is the digest of the stored bytes. It is absent when the section
is empty, when the content budget is spent, or when the declared range cannot
be read. Relocations are not applied and no section content is interpreted.

### Dylibs

`install_name`, `install_name_available`, `truncated`, and `dylibs`.

`install_name` is the `LC_ID_DYLIB` name and is absent when the image has none.
Each `dylibs` entry carries `index`, `command`, `command_name`, `kind`, `name`,
`name_available`, `name_offset`, `timestamp`, `current_version`, and
`compatibility_version`. `kind` is `id`, `load`, `weak`, `reexport`, `lazy`, or
`upward`.

The whole `dylibs` member is null when the image declares no dylib command.
That is not a limitation: it means the artifact does not link any dylib.

### Build

`command`, `command_name`, `platform`, `platform_available`, `platform_name`,
`minimum_os`, `sdk`, and `tools`.

`platform_available` is false for a legacy `LC_VERSION_MIN_*` command, which
carries no platform; `platform_name` is then empty. `platform_name` is one of
`macos`, `ios`, `tvos`, `watchos`, `bridgeos`, `maccatalyst`,
`ios-simulator`, `tvos-simulator`, `watchos-simulator`, `driverkit`,
`visionos`, `visionos-simulator`, or empty.

Each tool record carries `tool`, `tool_name` (`clang`, `swift`, `ld`, or
empty), and `version`.

### Entry

`entry_offset` and `stack_size`. `entry_offset` is a file offset, not a virtual
address. `LC_UNIXTHREAD` entry points are not decoded and appear as an unknown.

### Symbols

`declared_count`, `loaded_count`, `string_bytes`, `truncated`, and `symbols`.

`declared_count` is the raw `nsyms`, `loaded_count` is what the payload carries,
and `string_bytes` is how much of the string table was read. Each entry carries
`index`, `string_index`, `name`, `name_available`, `type`, `section`,
`description`, and `value`. The null symbol is included as stored.

### Code signature

`data_offset`, `data_size`, `magic`, `length`, `count`, `truncated`, and
`blobs`. Each blob carries `index`, `type`, `offset`, `magic`, and `length`.

Only the `LC_CODE_SIGNATURE` range, the `CSMAGIC_EMBEDDED_SIGNATURE` superblob
header, its index, and each blob header are reported. No signature is verified,
no certificate chain is read, and no entitlement is parsed. Presence of this
member is not a trust signal.

## Completeness

A payload member is null only when the artifact does not declare it. When a
table stops early the member is present, its `truncated` flag is set, and one
record limitation names the reason: the reader's count or byte limit, a payload
budget cut, or a malformed command.

Record limitations are deduplicated and capped. Unknowns record what the
adapter deliberately does not decode:

- `exported symbol trie is not decoded` for `LC_DYLD_INFO`, `LC_DYLD_INFO_ONLY`,
  or `LC_DYLD_EXPORTS_TRIE`;
- `chained fixups are not decoded` for `LC_DYLD_CHAINED_FIXUPS`;
- `section relocations are not decoded` when a section declares relocations;
- `Objective-C metadata is not interpreted` for an `__objc_` section;
- `ARM64e pointer authentication is not interpreted` for the arm64e subtype;
- `code signatures are not validated` and `entitlements are not decoded` when a
  signature is present.

## Abridged example

```json
{
  "schema": "ree.payload.macho/1",
  "artifact": {
    "magic": 3405691582,
    "magic_name": "fat-32",
    "fat": true,
    "byte_order": "big",
    "size": "40960",
    "slice_count": 2,
    "loaded_slice_count": 1,
    "truncated": false
  },
  "slices": [
    {
      "index": 0,
      "cpu_type": 16777223,
      "cpu_subtype": 3,
      "offset": "4096",
      "size": "16384",
      "alignment": 12,
      "status": "parsed",
      "header": {
        "magic": 4277009103,
        "magic_name": "mach-o-64",
        "is_64": true,
        "byte_order": "little",
        "file_type": 2,
        "file_type_name": "execute",
        "declared_command_count": 14,
        "loaded_command_count": 14,
        "truncated": false
      },
      "segments": [],
      "sections": [],
      "dylibs": {
        "install_name_available": false,
        "dylibs": [
          {
            "index": 0,
            "command": 12,
            "command_name": "LC_LOAD_DYLIB",
            "kind": "load",
            "name": "/usr/lib/libSystem.B.dylib",
            "name_available": true,
            "name_offset": 24,
            "timestamp": 2,
            "current_version": 131072,
            "compatibility_version": 65536
          }
        ],
        "truncated": false
      },
      "limitations": []
    }
  ]
}
```

The example is abridged: `segments` and `sections` would carry one entry per
segment and section, and `build`, `entry`, `symbols`, and `code_signature` are
omitted when the artifact or the budget does not provide them.
