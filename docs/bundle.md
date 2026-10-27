# Bundles

A `ree.bundle/1` document carries evidence records between machines without a
service. The implementation is `internal/contracts/bundle`; decisions and
limits are in [ADR 0003](adr/0003-evidence-core.md).

## Format

```json
{
  "schema": "ree.bundle/1",
  "records": [],
  "integrity": {"algorithm": "sha256", "digest": "<bundle digest>"}
}
```

A bundle is one canonical RFC 8785 JSON document. Phase 1 does not compress,
encrypt, or sign it, and does not use an archive format.

| Member | Meaning |
|---|---|
| `schema` | Always `ree.bundle/1`. |
| `records` | Canonical `ree.evidence/1` records, sorted by record digest. |
| `integrity` | `sha256` and the lowercase hex digest of the canonical bundle with this member omitted. |

## Record order and digests

- Each record is encoded by `evidence.Encode`, so it is canonical and its
  payload digest is sealed.
- The record digest is the SHA-256 digest of the record's canonical bytes.
- Records are sorted by record digest in ascending byte order.
- Duplicate record digests are rejected, both on export and import.
- The bundle digest covers `{"records": [...], "schema": "ree.bundle/1"}` after
  canonicalization, so it binds the schema, the record set, and the record
  order.

The payload digest inside a record covers only its payload. Metadata changes
change the record digest, and therefore the bundle digest.

## Limits

The package enforces the limits in [ADR 0003](adr/0003-evidence-core.md): 64 MiB
per bundle, 10,000 records per bundle, 8 MiB per record, 4 MiB per payload, and
the per-record string, member, element, and nesting limits. Bundle
canonicalization allows three extra nesting levels for the bundle object, the
records array, and the record object.

## Import rules

Import is in-memory and canonical-only:

- the input must be RFC 8785 canonical JSON; non-canonical bytes are rejected
  rather than repaired;
- member names are matched case-sensitively;
- the schema, digest algorithm, digest shape, record count, and bundle digest
  are verified before records are returned;
- every record must pass `evidence.Decode`, including its schema, digest, and
  limits;
- records must be in ascending record-digest order without duplicates;
- nothing is extracted, resolved, written, or executed.

A verified digest proves byte integrity, not trust or authenticity. A bundle
from an untrusted source remains untrusted after a successful import. Signing
and provenance are separate supply-chain controls and are out of scope for
Phase 1.

## Usage

```go
records := []evidence.Evidence{first, second}

data, err := bundle.Export(records)
if err != nil {
    return err
}

imported, err := bundle.Import(data)
if err != nil {
    return err
}
```

`Export` accepts records in any order and sorts them. `Import` returns records
in record-digest order, the same order in which they appear in the bundle.
