# Reverse Engineer Everything

[![CI](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/ci.yml/badge.svg)](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Evidence-first reverse engineering for binaries, apps, and artifacts.**

> Status: pre-alpha. `ree analyze` reads ELF, PE, Mach-O, ZIP, tar, gzip, APK, ASAR, and property lists into sealed evidence with a path-free summary, and `ree inventory`, `ree search`, and `ree compare` page and diff the entry lists. The MCP surface exposes build identity, local diagnostics, and `ree_analyze` at version `0.3`.

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
ree inventory ./bundle.zip
ree search ./bundle.zip --query lib
ree compare ./old.zip ./new.zip
ree doctor
ree doctor --json
ree mcp
ree help
```

`ree analyze` reads one local ELF, PE, Mach-O, ZIP, tar, gzip, APK, ASAR, or plist artifact, selects the built-in provider by magic, and prints a path-free summary or emits the sealed `ree.evidence/1` record with `--out`. It is read-only and never executes artifact content. `ree inventory`, `ree search`, and `ree compare` page, filter, and diff the entry lists of archives, packages, and property lists. See [docs/analyze.md](docs/analyze.md) and [docs/inventory.md](docs/inventory.md).

`ree doctor` reports whether the local tools used for development and releases are available. Missing optional tools do not fail the command; the JSON form is intended for automation.

## MCP

`ree mcp` serves the REE-native MCP surface over stdin/stdout. Surface `0.3` exposes:

- `ree_version`: the same build identity as `ree version --json`;
- `ree_doctor`: local tool and environment diagnostics;
- `ree_analyze`: read-only analysis of one local ELF, PE, Mach-O, ZIP, tar, gzip, APK, ASAR, or plist artifact. It returns the same path-free summary as `ree analyze --json` and, with `include_record`, the sealed `ree.evidence/1` record when it is at most 1 MiB.

It supports MCP protocol versions `2024-11-05` through `2026-07-28`, including stateless discovery. `ree_analyze` reads only the regular file the caller names, never executes, modifies, or uploads an artifact, and replaces a record above the tool limit with a `record_omitted` explanation; `ree analyze --out` exports a large record. Stdout carries MCP protocol messages only; logs and errors go to stderr.

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
