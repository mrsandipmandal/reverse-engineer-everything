# Evidence records

This page describes the `ree.evidence/1` wire format implemented in
`internal/contracts/evidence`. The Go package is authoritative; this page
explains the invariants that producers and importers rely on. Limits and the
design rationale are in [ADR 0003](adr/0003-evidence-core.md).

## Format

```json
{
  "schema": "ree.evidence/1",
  "subject": {"sha256": "<64 lowercase hex>", "size": 8},
  "provider": {"id": "builtin.example", "version": "1.0.0", "profile": "default"},
  "authority": "observed",
  "coverage": "partial",
  "limitations": ["fixture covers one artifact only"],
  "unknowns": ["other platforms were not examined"],
  "payload": {"arch": "amd64", "format": "elf"},
  "integrity": {"algorithm": "sha256", "digest": "<payload digest>"}
}
```

| Member | Meaning |
|---|---|
| `schema` | Always `ree.evidence/1`. |
| `subject` | Artifact digest and size. The digest names the artifact, not its path. |
| `provider` | Producer identity: stable ID, version, and named profile. |
| `authority` | `observed`, `derived`, or `inferred`. |
| `coverage` | `complete`, `partial`, or `unknown`. Missing coverage must be stated, not implied. |
| `limitations` | Sorted, unique, non-empty statements about what the evidence does not cover. |
| `unknowns` | Sorted, unique, non-empty open questions. |
| `payload` | Any JSON value, including `null`. Its canonical bytes are hashed. |
| `integrity` | `sha256` and the lowercase hex digest of the canonical payload. |

## Canonical form

Records are exchanged as RFC 8785 canonical JSON:

- object members are sorted by UTF-16 code units;
- numbers use ECMAScript serialization;
- strings are minimally escaped and must be valid UTF-8;
- duplicate member names are rejected;
- no insignificant whitespace is emitted.

`Encode` sorts `limitations` and `unknowns` by byte value and rejects duplicate
entries. It computes the payload digest and refuses to overwrite a supplied
schema or digest that does not match. `Decode` accepts canonical bytes only, so
the bytes that were hashed are exactly the bytes that were supplied.

Member names are matched case-sensitively. Without that rule, `"AuthoritY"`
would decode as `"authority"` and then re-encode under a different spelling,
giving one record two byte representations.

## Integrity scope

The payload digest detects changes to the payload only. Subject, provider,
authority, coverage, and limitation text are covered by the record digest, which
is the SHA-256 digest of the record's canonical bytes and is used to order
records in a bundle. A bundle digest covers the bundle with its own `integrity`
member omitted.

A digest proves byte integrity, not trust. Evidence from an untrusted provider
remains untrusted after a successful import.

## Limits

The package enforces the limits in [ADR 0003](adr/0003-evidence-core.md): 8 MiB
per record, 4 MiB per payload, 1 MiB per string, 10,000 object members, 100,000
array elements, and 128 nesting levels for the payload. The record envelope adds
one level, so record canonicalization allows 129 levels.

## Import rules

Import never executes, extracts, resolves, or writes anything. `Decode` is
in-memory and rejects non-canonical bytes rather than repairing them. Callers
must treat every accepted record as untrusted data.

## Usage

```go
record := evidence.Evidence{
    Subject:     evidence.Subject{SHA256: artifactDigest, Size: size},
    Provider:    evidence.Provider{ID: "builtin.example", Version: "1.0.0", Profile: "default"},
    Authority:   evidence.AuthorityObserved,
    Coverage:    evidence.CoveragePartial,
    Limitations: []string{"only one payload shape was examined"},
    Unknowns:    []string{"other platforms were not examined"},
    Payload:     payload,
}

data, err := evidence.Encode(record)
if err != nil {
    return err
}

decoded, err := evidence.Decode(data)
if err != nil {
    return err
}
digest, err := decoded.Digest()
```

## Payload schemas

The evidence core does not constrain payload members beyond canonical JSON and
the record limits. Each provider documents its payload separately. The first is
[`ree.payload.elf/1`](payload-elf.md) from the built-in ELF provider.
