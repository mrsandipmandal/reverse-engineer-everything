# Reverse Engineer Everything

[![CI](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/ci.yml/badge.svg)](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Evidence-first reverse engineering for binaries, apps, and artifacts.**

> Status: pre-alpha. `ree analyze` reads ELF and PE artifacts into sealed evidence with a path-free summary. The MCP surface still exposes build identity and local diagnostics only.

## Why

Reverse engineering tools often produce confident answers without showing what was observed, what was inferred, and what remains unknown. REE is designed around the opposite:

- content-addressed evidence;
- explicit provenance and coverage;
- first-class unknowns;
- reproducible evidence bundles;
- read-only analysis by default.

## Install

Download a signed archive for linux, darwin, or windows on amd64 or arm64 from [Releases](https://github.com/mrsandipmandal/reverse-engineer-everything/releases), then verify it as described in [docs/release.md](docs/release.md).

Or build from source with Go 1.26.10 or newer:

```bash
go install github.com/mrsandipmandal/reverse-engineer-everything/cmd/ree@latest
```

Module builds report the version from Go module metadata. They do not carry VCS metadata, so `commit` and `built` are `unknown`; release archives report both.

From a checkout:

```bash
go build -o bin/ree ./cmd/ree
./bin/ree version
```

## Usage

```bash
ree version
ree version --json
ree analyze ./artifact
ree analyze ./artifact --json
ree doctor
ree doctor --json
ree mcp
ree help
```

`ree analyze` reads one local ELF or PE artifact, selects the built-in provider by magic, and prints a path-free summary or emits the sealed `ree.evidence/1` record with `--out`. It is read-only and never executes artifact content. See [docs/analyze.md](docs/analyze.md).

`ree doctor` reports whether the local tools used for development and releases are available. Missing optional tools do not fail the command; the JSON form is intended for automation.

## MCP

`ree mcp` serves the REE-native MCP surface over stdin/stdout. In this phase it exposes only:

- `ree_version`: the same build identity as `ree version --json`;
- `ree_doctor`: local tool and environment diagnostics.

It supports MCP protocol versions `2024-11-05` through `2026-07-28`, including stateless discovery. The server exposes no artifact analysis tools and does not read or execute artifacts. Stdout carries MCP protocol messages only; logs and errors go to stderr.

Example client configuration:

```json
{
  "mcpServers": {
    "ree": {
      "command": "/absolute/path/to/ree",
      "args": ["mcp"]
    }
  }
}
```

## Scope

The first milestone is static, read-only analysis of local artifacts. REE does not execute untrusted binaries. Runtime analysis is a later phase and will require explicit authorization.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md). Work is split into one phase per pull request.

## Development

```bash
make tools
make check
```

Every change goes through CI. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately through GitHub Security Advisories. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
