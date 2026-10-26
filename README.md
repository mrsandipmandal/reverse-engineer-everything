# Reverse Engineer Everything

[![CI](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/ci.yml/badge.svg)](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrsandipmandal/reverse-engineer-everything/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Evidence-first reverse engineering for binaries, apps, and artifacts.**

> Status: pre-alpha. The current foundation exposes `ree version` only. Analysis features are being built in reviewable phases.

## Why

Reverse engineering tools often produce confident answers without showing what was observed, what was inferred, and what remains unknown. REE is designed around the opposite:

- content-addressed evidence;
- explicit provenance and coverage;
- first-class unknowns;
- reproducible evidence bundles;
- read-only analysis by default.

## Install

Requires Go 1.24 or newer.

```bash
go install github.com/mrsandipmandal/reverse-engineer-everything/cmd/ree@latest
```

From a checkout:

```bash
go build -o bin/ree ./cmd/ree
./bin/ree version
```

## Usage

```bash
ree version
ree version --json
ree help
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

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
