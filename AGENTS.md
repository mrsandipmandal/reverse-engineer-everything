# AGENTS.md

Instructions for AI agents and contributors working in this repository. `PROJECT_MEMORY.md` holds the current state; this file holds the permanent rules.

## Communication

- Write user-facing plans, progress reports, decisions that need approval, and final reports in natural West Bengal Bengali.
- Use "জল", not "পানি".
- Keep technical identifiers, filenames, commands, code, API names, error messages, and protocol terminology in their original form.
- Be concise but technically complete. Never claim that something was implemented, tested, secured, published, or verified without evidence.

## Start of every task

1. Confirm the repository root and current branch.
2. Read `AGENTS.md`, `PROJECT_MEMORY.md`, `ROADMAP.md`, `docs/roadmap.md`, `CHANGELOG.md`, relevant ADRs, and release documentation.
3. Inspect `git status`, recent commits, the relevant diff, source, tests, and CI configuration.
4. Compare documentation with the actual repository state. Treat memory as a summary, not as proof.
5. Report discrepancies and prefer verified repository evidence.
6. Identify the current milestone, completed work, open issues, and the next planned step.

Do not recreate, rename, or duplicate existing documentation without a concrete reason. Follow established project conventions.

## Approval workflow

A request to inspect, plan, or report does not authorize implementation.

Before starting a new phase, substantial feature, breaking change, release, major refactor, or security-sensitive architectural change:

1. explain the current situation;
2. present scope and explicit out-of-scope items;
3. define measurable acceptance criteria;
4. present the implementation and verification plan;
5. identify dependencies, risks, and unresolved decisions;
6. wait for explicit approval.

Routine steps already covered by an approved scope do not need repeated approval. Stop and ask again if the work materially exceeds that scope.

Never bypass approval by silently changing the roadmap, expanding scope, publishing a release, or making a breaking change.

## Project memory

- `ROADMAP.md` and `docs/roadmap.md`: roadmap and acceptance criteria.
- `CHANGELOG.md` and `docs/releases/`: release history and verification evidence.
- `docs/adr/`: durable architectural decisions.
- `PROJECT_MEMORY.md`: current verified status, open issues, and the next action.

Update `PROJECT_MEMORY.md` after a meaningful milestone, merged PR, or release. Do not duplicate roadmap or changelog content; link to it. Never record planned or unverified work as complete. Do not store secrets, credentials, or personal data.

## Go code quality

- Follow idiomatic Go, existing package boundaries, and the layout in `docs/architecture.md`.
- Prefer the standard library when it is sufficient.
- Introduce interfaces and packages only for a real boundary or requirement.
- Handle errors explicitly; avoid panics for untrusted input or operational failures.
- Bound memory, CPU, recursion, goroutines, file processing, and network use.
- Avoid global mutable state; make ownership, cancellation, and concurrency explicit.
- Do not refactor unrelated code in the same change.
- Record significant architectural decisions in an ADR.

## Tests and verification

- Use conventional `*_test.go` files next to the package they test.
- Prefer deterministic, table-driven tests and minimal fixtures or mocks.
- Add tests for new behavior, errors, boundaries, and regressions.
- Add fuzz tests for parsers, canonicalization, and bundle import.
- Never weaken or delete a test to make CI pass.

Run the applicable checks and report actual outcomes:

```bash
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
golangci-lint run ./...
govulncheck ./...
actionlint
```

Distinguish local verification, CI verification, and checks that were not run.

## Security

- Treat every artifact and imported bundle as untrusted.
- Validate inputs and enforce explicit size, count, depth, and time limits.
- Never execute imported or recovered content.
- Imported bundles must verify schema, integrity, and version before use.
- Do not log secrets, payloads, personal data, or host paths in hashed content.
- Use least privilege and safe defaults.
- Document residual risk honestly.

## Releases

- All changes go through CI-gated pull requests; `main` is protected.
- Tag only after the approved scope is merged and verified.
- Verify working tree, commit, version identity, tests, artifacts, checksums, SBOMs, and signatures.
- Record what was actually verified in `docs/releases/<tag>.md`.
- Never move or re-create a published tag. Ship a patch release instead.

## Definition of done

- Implementation matches the approved scope.
- Tests and verification pass, or remaining gaps are reported.
- Relevant docs, memory, changelog, and ADRs are updated.
- The final diff contains no unrelated changes, secrets, or unsafe behavior.
- A Bengali final report states completed work, changes, verification, limitations, next step, and approval status.
