# Roadmap

Work is split into small, reviewable phases. Each phase starts with acceptance criteria and tests, lands through CI-gated pull requests, and does not implement unrelated phases.

| Phase | Scope | Status |
|---|---|---|
| 0a | Go module, `ree version`, repository baseline, CI, open-source files | Complete |
| 0b | MCP server, `ree doctor`, security and release workflows | Complete |
| 0c | First release, repository hardening | Complete |
| 1 | Evidence core, canonical JSON, schema validation | Complete |
| 2 | ELF read-only provider | Complete |
| 3 | PE read-only provider | Complete |
| 4 | Analysis surface: `ree analyze`, `ree_analyze` | Complete |
| 5 | Mach-O read-only provider | Complete |
| 6 | Archives, application packages, and inventory | In progress |
| 7 | JavaScript and web artifact analysis | Planned |
| 8 | External provider protocol and engine adapters | Planned |
| 9 | Runtime analysis with authorization and isolation | Planned |

See [docs/roadmap.md](docs/roadmap.md) for phase details and non-goals.
