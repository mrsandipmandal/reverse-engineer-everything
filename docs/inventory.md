# Inventory, search, and compare

`ree inventory`, `ree search`, and `ree compare` turn an artifact into a flat
name list and answer questions over it. They analyze the artifact with the same
readers and providers as `ree analyze`, never extract or execute content, and
project the sealed record rather than re-reading the file. Decisions are in
[ADR 0021](adr/0021-phase6-wiring.md).

## Commands

```
ree inventory <path> [--json] [--format F] [--max-bytes N] [--offset N] [--limit N]
ree search    <path> [--json] [--format F] [--max-bytes N] [--query TEXT] [--offset N] [--limit N]
ree compare   <left> <right> [--json] [--offset N] [--limit N]
```

`inventory` lists every entry of an archive, an APK, an ASAR payload, or a
property list. `search` lists the entries whose name contains the query, case
insensitively. `compare` lists what changed between two artifacts of the same
kind.

ELF, PE, and Mach-O artifacts have no entry list and are rejected with exit code
`2`; use `ree analyze` for them.

## Flags

| Flag | Commands | Meaning |
|---|---|---|
| `--json` | all | Emit the view as JSON instead of text |
| `--format` | `inventory`, `search` | `auto` (default), `zip`, `tar`, `gzip`, `apk`, `asar`, or `plist` |
| `--max-bytes` | `inventory`, `search` | Refuse an artifact above this size |
| `--query` | `search` | Case-insensitive substring on the entry name; required |
| `--offset` | all | Skip this many items, default `0` |
| `--limit` | all | Print at most this many items, `1..1000`, default `50` |

An explicit `--format` never falls back. `--format zip` on a tar artifact, or
`--format apk` on a ZIP without a root `AndroidManifest.xml`, fails instead of
being reinterpreted.

## Text output

```
REE Inventory
artifact: bundle.zip
format: zip
schema: ree.payload.archive/1
total: 3
page: offset=0 limit=50 returned=3
  [0] AndroidManifest.xml kind=file size=4
  [1] classes.dex kind=file size=8 sha256=9f2c...
  [2] lib/arm64-v8a/libdemo.so kind=file size=0
limitations: none
```

A page with more items prints the next window before the items:

```
page: offset=0 limit=2 returned=2
next: --offset 2 --limit 2
```

An entry whose name could not be decoded prints `<unavailable #index>` and its
unsafe reason. Depth appears only for nested archive members. A digest appears
only when the provider computed one, which for APK means the manifest, DEX, and
`resources.arsc` members.

`ree compare` prints the two sides, then the three lists:

```
REE Compare
left: old.zip (zip)
right: new.zip (zip)
added: 1
  [2] new.txt kind=file size=5
removed: 1
  [1] old.txt kind=file size=5
changed: 1
  keep.txt
    left: kind=file size=2
    right: kind=file size=7
```

## JSON output

`ree inventory --json` emits:

```json
{
  "artifact": "bundle.zip",
  "format": "zip",
  "schema": "ree.payload.archive/1",
  "page": {
    "offset": 0,
    "limit": 50,
    "total": 2,
    "items": [
      {
        "index": 0,
        "kind": "file",
        "name": "a.txt",
        "name_available": true,
        "unsafe": "",
        "size": 2,
        "digest": "",
        "digest_available": false,
        "depth": 0,
        "limitations": []
      }
    ],
    "next_offset": null
  }
}
```

`ree search --json` adds `query`; `ree compare --json` emits `left` and `right`
side objects plus `added`, `removed`, and `changed` pages, where `changed` items
carry `name`, `left`, and `right`.

`next_offset` is present only when another page exists. A window past the end is
an empty page with a `null` `next_offset`, not an error.

## Semantics

- Archive members keep their flattened order; a nested container member adds its
  own entries at depth one. The provider bounds nesting, so the view cannot
  recurse without limit.
- An archive size is the uncompressed size when it is known and the compressed
  size otherwise. An ASAR size is the declared size. An APK prefers the
  uncompressed size.
- A plist object has no name of its own, so its decoded text is used. A
  non-string object has no name and appears as unavailable.
- `compare` keys items by name, or by `#<index>` when the name is unavailable.
  Two unnamed members can collide across artifacts; the item limitation states
  that the name was unavailable.
- Per-entry limitations stay in the item. Record limitations are copied to the
  collection, so a truncated or abridged payload is visible in every view.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Operational failure: missing artifact, reader failure, write failure, canceled context |
| `2` | Invalid usage: unknown flag, missing or extra path, bad `--format`, negative `--offset`, `--limit` outside `1..1000`, empty `--query`, or a payload with no inventory view |

## See also

- [analyze.md](analyze.md) for `ree analyze`, the summary, and record export.
- [ADR 0021](adr/0021-phase6-wiring.md) for the wiring and view decisions.
- [payload-archive.md](payload-archive.md), [payload-apk.md](payload-apk.md),
  [payload-asar.md](payload-asar.md), and [payload-plist.md](payload-plist.md)
  for the payloads these views read.
