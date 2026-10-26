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

## Planned, subject to verification

These are candidates, not commitments. Each must pass the policy above before adoption.

| Area | Candidate | Phase |
|---|---|---|
| MCP server | `modelcontextprotocol/go-sdk` | 0b |
| JSON Schema | `santhosh-tekuri/jsonschema/v6` | 1 |
| Canonical JSON | `cyberphone/json-canonicalization` | 1 |
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
