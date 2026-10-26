# Contributing

Thank you for helping build Reverse Engineer Everything.

## Ground rules

- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- One phase or one focused feature per pull request.
- Define acceptance criteria and tests before implementation.
- Do not copy source code, proprietary assets, test fixtures, or undocumented implementation details from other projects. Use public specifications and public documentation, then design and test independently.
- Treat every input artifact as untrusted.
- Do not include secrets, personal data, or proprietary binaries in issues, tests, or commits.
- Report security vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Development setup

Requirements:

- Go 1.24 or newer
- Git
- Make (recommended; not required)
- `golangci-lint`, `govulncheck`, and `actionlint` for the full local check

Install the pinned local tools into `bin/`:

```bash
make tools
```

Run the full check:

```bash
make check
```

If the optional tools are not installed, run the checks that are available and report exactly what was not run.

## Pull requests

1. Open or reference an issue with acceptance criteria.
2. Add or update tests first where practical.
3. Keep the change small and reviewable.
4. Run formatting, tests, vet, build, lint, and vulnerability checks.
5. In the PR description, list the exact commands run and their results.
6. Confirm that no secrets or proprietary artifacts are included.
7. Sign off your commits with the Developer Certificate of Origin.

## Developer Certificate of Origin

Contributions are accepted under the Apache License 2.0. Each commit must include a sign-off:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s` to add it. By signing off, you certify the Developer Certificate of Origin 1.1:

<https://developercertificate.org/>

## Commit style

Prefer Conventional Commits:

```text
feat: add version command
fix: reject oversized input
docs: document evidence model
test: cover malformed ELF headers
ci: pin workflow actions
```

## Code style

- Idiomatic Go.
- `context.Context` first for operations that can block or be canceled.
- Clear interfaces at package boundaries.
- Bounded resource usage: size limits, item limits, timeouts, and output caps.
- Useful wrapped errors with stable context.
- No panics for malformed input.
- No hidden network access.
- No execution of untrusted artifacts without explicit authorization.

## Test expectations

- Unit tests for pure logic.
- Golden tests for stable contracts and output.
- Fuzz tests for parsers and decoders.
- Integration tests for CLI and MCP behavior.
- Cross-platform build checks.
- Synthetic or permissively licensed fixtures with provenance recorded.

## Dependency policy

Before adding a dependency:

- verify its license;
- verify its maintenance and security posture;
- record the version and source;
- check for known vulnerabilities;
- avoid dependencies that are unnecessary for the current phase.

See [docs/dependencies.md](docs/dependencies.md).

## Review and merge

- `main` is protected.
- Required checks must pass.
- Conversations must be resolved.
- Squash merging is preferred.
- A maintainer merges the change.
