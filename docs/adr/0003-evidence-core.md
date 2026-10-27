# ADR 0003: Evidence core

- Status: accepted
- Date: 2026-10-27

## Context

Phase 2 providers will emit evidence that must be reproducible, content-addressed, and safe to import. Before any parser exists, the project needs one canonical byte representation, an evidence schema with explicit coverage and unknowns, and an offline bundle format with integrity checks.

Imported bundles are untrusted input. The design must bound work, reject ambiguity, and avoid filesystem or execution side effects.

## Decisions

### Canonical JSON

- Use RFC 8785 (JSON Canonicalization Scheme) through `github.com/gowebpki/jcs` `v1.0.2`.
- Wrap it in `internal/contracts/canonical` to add byte and depth limits, sentinel errors, idempotence guarantees, and the SHA-256 helper.
- Do not implement a local canonicalizer.

Rationale:

- the module is Apache-2.0, the same license as REE;
- it is an actively maintained cleanup of the reference Go implementation, produced with the original author's permission;
- it sorts member names by UTF-16 code units, validates surrogate pairs, rejects duplicate names, rejects non-UTF-8 input, and caps nesting;
- the upstream license metadata for the original `cyberphone/json-canonicalization` module is not machine-recognized, which would require extra license review for the same code.

### Digest

- Hash canonical bytes with SHA-256 and encode the digest as 64 lowercase hexadecimal characters.
- Schemas name the algorithm explicitly; Phase 1 supports only `sha256`.
- A valid digest proves byte integrity, not trustworthiness of the source.
- Signatures are out of scope; release signing remains a separate supply-chain control.

### Evidence schema `ree.evidence/1`

```json
{
  "schema": "ree.evidence/1",
  "subject": {"sha256": "<64 hex>", "size": 123},
  "provider": {"id": "builtin.example", "version": "1", "profile": "default"},
  "authority": "observed",
  "coverage": "partial",
  "limitations": ["..."],
  "unknowns": ["..."],
  "payload": {},
  "integrity": {"algorithm": "sha256", "digest": "<payload digest>"}
}
```

- `authority` is `observed`, `derived`, or `inferred`.
- `coverage` is `complete`, `partial`, or `unknown`.
- `limitations` and `unknowns` are sorted lexicographically on encode so producer ordering cannot change the bytes.
- `payload` is any JSON value; `integrity.digest` covers its canonical bytes.
- Validation is hand-written and strict: required fields, enum values, digest shape, byte and count limits, and rejection of unknown members. Member names are matched case-sensitively so a record cannot decode under one spelling and re-encode under another. A normative JSON Schema document is documentation; Phase 1 does not add a schema-validator dependency.

### Bundle `ree.bundle/1`

```json
{
  "schema": "ree.bundle/1",
  "records": [],
  "integrity": {"algorithm": "sha256", "digest": "<bundle digest>"}
}
```

- A bundle is one canonical JSON document. Phase 1 does not compress or archive it.
- Records are sorted by the SHA-256 digest of their canonical bytes; duplicate record digests are rejected.
- The bundle digest covers the canonical bundle with `integrity` omitted, so it binds the schema, the record set, and the record order.
- Import accepts canonical bytes only. Non-canonical input is rejected rather than repaired, so import cannot silently change what was hashed.
- Member names are matched case-sensitively at every level.
- Import is in-memory: no extraction, no filesystem writes, no network, and no execution.
- No timestamps, host paths, generator versions, or map iteration order appear in hashed content.

### Limits

| Limit | Value |
|---|---:|
| bundle bytes | 64 MiB |
| records per bundle | 10,000 |
| evidence record bytes | 8 MiB |
| payload bytes | 4 MiB |
| nesting depth | 128 |
| single string bytes | 1 MiB |
| object members | 10,000 |
| array elements | 100,000 |

The canonicalizer enforces input bytes and depth. Evidence and bundle validation enforce the remaining limits.

The record limit is 8 MiB while a payload is capped at 4 MiB, because a record also carries subject, provider, coverage, and limitation text. Payload nesting is limited to 128; the record envelope adds one level, so record canonicalization allows 129 levels and payload validation still rejects anything deeper than 128. Bundle canonicalization allows 131 levels: the bundle object, the records array, and the record object add three levels around a payload.

### Package boundaries

```text
internal/contracts/canonical   RFC 8785, limits, SHA-256
internal/contracts/evidence    schema v1 encode, decode, validate
internal/contracts/bundle      manifest, export, import, integrity
```

`canonical` is imported by `evidence`, and `evidence` by `bundle`. `internal/domain`, `internal/app`, CLI, and MCP integration are deferred until a real provider or use case needs them; adding them now would be speculative.

## Consequences

- Identical observations produce identical bytes, and tampering is detectable.
- Import is strict; externally produced bundles must be canonicalized before import. A canonicalization command can be added with the Phase 6 analysis surface.
- JSON numbers follow ECMAScript double serialization. Integers beyond 2^53 lose precision and are unsuitable for evidence payloads; sizes outside payloads use exact integers.
- The project takes a runtime dependency that must be monitored and updated through Dependabot and `govulncheck`.
- Error messages must stay bounded and must not echo payloads.

## Alternatives considered

- Writing a local RFC 8785 implementation: rejected because correctness is subtle and conformance evidence would be harder to establish.
- Using the original `cyberphone` module: rejected for ambiguous license metadata, not for behavior.
- ZIP-based bundles: deferred to Phase 5, where archive extraction and bomb defenses are in scope.
- Adding a JSON Schema validator: deferred until external schema validation is a real requirement.
