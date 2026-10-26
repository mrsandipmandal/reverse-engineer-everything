# ADR 0001: Foundation decisions

- Status: accepted
- Date: 2026-10-26

## Context

REE is a new open-source reverse-engineering platform. It must be safe with untrusted artifacts, produce reproducible evidence, and remain maintainable as formats and providers grow. The first deliverable is a small, CI-gated foundation rather than a broad feature set.

## Decisions

### Name and identity

- Project name: Reverse Engineer Everything.
- Short name: REE.
- Repository: `mrsandipmandal/reverse-engineer-everything`.
- CLI binary: `ree`.

The short name `ree` is used only as a local binary. It is not used as a package or domain name because those names are already taken.

### License

Apache-2.0 with a `NOTICE` file. Contributions require a Developer Certificate of Origin sign-off.

### Language and baseline

Go, with a `go 1.24` module baseline. CI tests Go 1.24, 1.25, and 1.26.

### Scope

Static, read-only analysis first. REE does not execute untrusted artifacts in the foundation. Runtime analysis is deferred and requires explicit authorization.

### Evidence

Evidence is content-addressed, schema-versioned, canonicalized with RFC 8785, and deterministic. Unknowns and limitations are first-class. Bundles are offline and validated on import.

### Compatibility

The MCP surface is REE-native and versioned. A compatibility profile for other tools may be added later.

### Delivery

All changes go through CI-gated pull requests. Releases use GoReleaser with checksums, SBOM, and keyless signing. GitHub Actions are pinned to full commit SHAs. `main` is protected.

### Package layout

```text
cmd/ree
internal/cli
internal/mcp
internal/contracts
internal/domain
internal/app
internal/providers
internal/formats
internal/process
internal/platform
internal/setup
internal/views
pkg/sdk
docs/adr
```

### Independence

REE is independently designed from public specifications and documentation. It does not copy source code, proprietary assets, fixtures, or undocumented implementation details from other projects.

## Consequences

- The foundation is small and reviewable.
- Analysis features arrive later, one format family at a time.
- Evidence contracts must be designed before parsers depend on them.
- Runtime features require additional security design.
- Maintainers must verify every dependency and release artifact.
