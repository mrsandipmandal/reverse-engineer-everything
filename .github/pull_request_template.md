## Summary

Describe the change and why it is needed.

## Phase and scope

- Phase:
- Related issue:

## Changes

- 

## Verification

List the exact commands run and their results. Do not mark a check that was not run.

- [ ] `gofmt -l .`
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go build ./...`
- [ ] `golangci-lint run ./...`
- [ ] `govulncheck ./...`
- [ ] `actionlint`
- [ ] cross-build targets

Commands and output:

```text
paste exact results here
```

## Security

- [ ] Inputs are treated as untrusted.
- [ ] Resource limits, timeouts, and cancellation are handled.
- [ ] No secrets, personal data, or proprietary artifacts are included.
- [ ] No new dependency without license and security review.

## DCO

- [ ] Commits are signed off with `git commit -s`.
