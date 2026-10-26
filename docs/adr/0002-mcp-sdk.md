# ADR 0002: MCP Go SDK

- Status: accepted
- Date: 2026-10-26

## Context

Phase 0b adds a Model Context Protocol (MCP) server over stdio. REE needs an MCP implementation that is maintained, supports current protocol revisions, and passes the project's vulnerability gate. The MCP surface is REE-native and must remain small and versioned; compatibility profiles and analysis tools are later work.

The first candidate, `v1.3.1`, preserved a Go 1.24 baseline but `govulncheck` reported three called vulnerabilities in the SDK and ten in the Go 1.26.8 standard library. The SDK issues are fixed in `v1.4.0` and `v1.4.1`; the standard-library issues are fixed in Go 1.26.10.

## Decision

Use the official Go SDK at `github.com/modelcontextprotocol/go-sdk v1.8.0`.

- The SDK module requires Go 1.25. REE uses a `go 1.26.10` baseline so the tested standard library includes the security fixes.
- The SDK supports MCP protocol versions `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26`, and `2024-11-05`.
- The SDK license is transitioning from MIT to Apache-2.0. Both licenses are permissive and compatible with this Apache-2.0 project; third-party attribution is recorded in `THIRD_PARTY_NOTICES.md`.
- REE exposes a server named `ree` with instructions containing surface version `0.1`.
- The initial surface contains only `ree_version` and `ree_doctor`.
- The server uses the SDK's stdio transport. Tests use its in-memory transport.
- Tool inputs and outputs are concrete Go structs, and the SDK derives JSON Schemas for both.
- Tool failures that are not protocol errors are returned as tool results rather than terminating the server.

The earlier `v1.3.1` decision was rejected because it cannot satisfy the vulnerability gate. Keeping an end-of-life Go baseline would also leave called standard-library vulnerabilities unresolved.

## Consequences

- REE raises its minimum Go version to 1.26.10 and CI tests Go 1.26.10 and 1.27.x.
- REE adds one runtime dependency and a small transitive dependency graph, including `golang.org/x/oauth2`, `golang.org/x/sync`, and `golang.org/x/time`.
- The mixed MIT/Apache-2.0 SDK license requires third-party notices in source and release archives.
- Dependabot updates to this module must keep the vulnerability, test, and license checks green.
- The MCP SDK remains an implementation detail behind `internal/mcp`; public REE contracts must not expose SDK types.
- The server has no analysis capability in Phase 0b. `ree_doctor` reports local tool availability but does not run artifact analysis.
- Future protocol upgrades require new tests and may require a new surface version.
