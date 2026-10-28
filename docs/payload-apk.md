# APK payload

This page describes `ree.payload.apk/1`, the payload produced by
`internal/providers/apk` for an `ree.evidence/1` record. The Go package is
authoritative; this page explains what the fields mean and which values a
consumer can rely on. Limits and rationale are in
[ADR 0020](adr/0020-apk-reader.md).

## Envelope

The payload is carried inside a normal evidence record:

| Member | Value |
|---|---|
| `schema` | `ree.evidence/1` |
| `subject.sha256` | SHA-256 of exactly `subject.size` artifact bytes |
| `provider.id` | `builtin.apk` |
| `provider.profile` | `default` |
| `provider.version` | caller-supplied adapter version |
| `authority` | `observed` |
| `coverage` | `complete` only when no limitation was recorded |
| `payload.schema` | `ree.payload.apk/1` |

One package produces exactly one record. `Observe` returns an error and no
record when the archive is not a ZIP, the root manifest is missing, or the
signing block contradicts itself.

## Value encoding

| Kind | Encoding |
|---|---|
| counts, indices, booleans | JSON number or boolean |
| 64-bit sizes and the signing offset | decimal string, so values above 2^53 survive |
| raw entry names | lowercase hexadecimal |
| decoded entry names | text validated by the ZIP reader; never repaired |
| absent value | `null` |

The decimal strings are `signing.offset`, `signing.size`, `signing.pairs[].size`,
`entries[].compressed_size`, and `entries[].uncompressed_size`.

## Members

### Artifact

| Member | Meaning |
|---|---|
| `entry_count` | ZIP entries the reader loaded |
| `loaded_entry_count` | entries projected into this payload |
| `truncated` | an entry, signing byte, or signing pair limit was reached |
| `status` | `parsed` when the ZIP directory, the Android layout, and the signing block were decoded |
| `counts` | entries per Android kind |
| `signing` | the APK Signing Block view |
| `limitations` | why the inventory is incomplete |

`entry_count` above `loaded_entry_count` means the payload budget omitted
entries; `truncated` reports that the reader itself stopped early.

### Counts

| Member | Kind |
|---|---|
| `manifest` | `AndroidManifest.xml` |
| `dex` | root `classes*.dex` |
| `resources` | `resources.arsc` |
| `native_library` | `lib/<abi>/*.so` |
| `resource_entry` | anything under `res/` |
| `asset` | anything under `assets/` |
| `signature_file` | `.SF`, `.RSA`, `.DSA`, `.EC` under `META-INF/` |
| `other` | everything else |

The counts summarise the loaded entries; they do not repeat the entries
themselves, and an entry whose name could not be decoded counts as `other`.

### Signing

| Member | Meaning |
|---|---|
| `present` | an APK Signing Block was found before the central directory |
| `offset`, `size` | absolute artifact offset and declared block size, `null` when absent |
| `pair_count` | pairs decoded |
| `truncated` | the pair area or pair count was capped |
| `pairs` | decoded pairs, in block order |
| `limitations` | why the block view is incomplete |

A package signed only with the scheme v1 `META-INF` files has `present: false`
and an empty `pairs` array. Presence is not validity: the payload never claims
that a signature verifies, that a certificate is trusted, or that the package is
installable.

### Pair

| Member | Meaning |
|---|---|
| `id` | 32-bit identifier as `0x` plus eight lowercase hex digits |
| `scheme` | `v2`, `v3`, `v3.1`, `source_stamp`, `verity_padding`, or empty when the identifier is unknown |
| `size` | declared value length in bytes |
| `digest` | SHA-256 of the value, `null` when it could not be read |
| `digest_available` | whether `digest` is a computed digest |

The value itself is not emitted. A consumer that needs to parse a signer
structure must read the block from the artifact.

### Entry

| Member | Meaning |
|---|---|
| `index` | position in the ZIP directory order |
| `name`, `name_available`, `name_hex` | decoded name, its availability, and the raw bytes |
| `unsafe` | why the name cannot be used, empty when it is safe |
| `kind` | `manifest`, `dex`, `resources`, `native_library`, `resource`, `asset`, `signature`, or `other` |
| `abi` | first segment after `lib/` for a native library, empty otherwise |
| `compressed_size`, `uncompressed_size` | declared ZIP sizes, `null` when the header did not declare them |
| `digest`, `digest_available` | SHA-256 of the content for a hashed kind |
| `limitations` | why this entry's view is incomplete |

Only `manifest`, `dex`, and `resources` entries are hashed. A native library,
resource, or asset keeps `digest: null` and `digest_available: false` even when
its content is readable. A skipped or failed digest records a per-entry
limitation such as `content digest skipped: declared size exceeds 67108864 bytes`.

## Completeness

`coverage` is `partial` when the record carries a limitation. That happens when
the reader stopped at an entry or signing limit, when a content digest could not
be computed, or when the payload budget could not hold every entry.

`truncated` in the payload and `payload budget omits entries after N of M` in
the record limitations are independent: a complete but large package can be
truncated by the payload budget without the reader's walk having stopped.

A per-entry limitation such as an unsafe path or a skipped digest stays in the
payload, but it also appends an artifact limitation, because an unhashed
manifest is materially different from a hashed one.

## Example

```json
{
  "schema": "ree.payload.apk/1",
  "artifact": {
    "entry_count": 3,
    "loaded_entry_count": 3,
    "truncated": false,
    "status": "parsed",
    "counts": {
      "manifest": 1,
      "dex": 1,
      "resources": 1,
      "native_library": 0,
      "resource_entry": 0,
      "asset": 0,
      "signature_file": 0,
      "other": 0
    },
    "signing": {
      "present": true,
      "offset": "512",
      "size": "64",
      "pair_count": 1,
      "truncated": false,
      "pairs": [
        {
          "id": "0x7109871a",
          "scheme": "v2",
          "size": "16",
          "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          "digest_available": true
        }
      ],
      "limitations": []
    },
    "limitations": []
  },
  "entries": [
    {
      "index": 0,
      "name": "AndroidManifest.xml",
      "name_available": true,
      "name_hex": "416e64726f69644d616e69666573742e786d6c",
      "unsafe": "",
      "kind": "manifest",
      "abi": "",
      "compressed_size": "120",
      "uncompressed_size": "120",
      "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "digest_available": true,
      "limitations": []
    }
  ]
}
```
