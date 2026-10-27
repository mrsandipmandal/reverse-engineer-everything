# Dependencies

## Policy

Before adding a dependency:

1. verify the license and compatibility with Apache-2.0;
2. verify maintenance activity and security history;
3. record the exact version and source;
4. run vulnerability and license checks;
5. prefer the standard library when the dependency is not clearly justified;
6. pin versions in CI and releases;
7. document significant additions in an ADR.

Third-party analysis engines are not bundled. They are detected and invoked only with explicit authorization in a later phase.

## Phase 0a

The foundation has no Go module dependencies. It uses only the standard library.

## Phase 0b

| Module | Version | License | Purpose |
|---|---|---|---|
| `github.com/modelcontextprotocol/go-sdk` | `v1.8.0` | MIT and Apache-2.0 | Official MCP server, client, and transport implementation |

The SDK requires Go 1.25 and supports MCP protocol versions `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26`, and `2024-11-05`; the client and server negotiate a mutually supported version. REE uses a Go 1.26.10 module baseline because the standard-library vulnerabilities reported by `govulncheck` on Go 1.26.8 are fixed in Go 1.26.10.

The SDK is transitioning from MIT to Apache-2.0. Both licenses are permissive and compatible with this Apache-2.0 project. All modules linked into REE binaries use permissive licenses (MIT, Apache-2.0, or BSD-3-Clause); build-only modules are not redistributed. Attribution and license texts are recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). SDK `v1.3.1` was rejected because it contains called vulnerabilities and requires an older, vulnerable toolchain.

See [ADR 0002](adr/0002-mcp-sdk.md).

## Phase 1

| Module | Version | License | Purpose |
|---|---|---|---|
| `github.com/gowebpki/jcs` | `v1.0.2` | Apache-2.0 | RFC 8785 JSON canonicalization for evidence and bundles |

The module is an actively maintained cleanup of the reference Go implementation, produced with the original author's permission. It rejects duplicate member names and invalid UTF-8, validates surrogate pairs, sorts by UTF-16 code units, and caps nesting. REE wraps it with stricter byte and depth limits. See [ADR 0003](adr/0003-evidence-core.md).

Phase 1 validates the fixed evidence schema in Go instead of adding a JSON Schema validator. A validator will be considered when external schemas must be validated.

## Planned, subject to verification

These are candidates, not commitments. Each must pass the policy above before adoption.

| Area | Candidate | Phase |
|---|---|---|
| Browser automation | `chromedp` | 8 |
| SQLite | `modernc.org/sqlite` | 6 |
| WebAssembly | `wazero` | 8 |
| JavaScript parsing | `goja` or `tdewolff/parse/v2` | 8 |
| Source maps | `go-sourcemap/sourcemap` | 8 |
| Compression | `klauspost/compress` | 5 |
| PTY | `creack/pty` | 9 |

## GitHub Actions

Actions are pinned to full commit SHAs and updated through Dependabot. Workflow linting runs in CI.

## License review

The project is Apache-2.0. Dependencies must not impose incompatible obligations. Any dependency with a non-permissive license requires explicit review and an ADR before use.
