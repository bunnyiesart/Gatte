.PHONY: build test vet fmt-check check devtools

build:
	go build -o bin/mcp-gateway ./cmd/mcp-gateway

# -count=1 disables go test's result cache for the whole run. Required for
# internal/fitness to be trustworthy -- see the comment in
# internal/fitness/fitness_test.go for the confirmed caching gap that
# motivates this; a bare `go test ./...` can report a stale pass.
#
# internal/vault/sopsage's tests need `sops`, `age`, and `age-keygen` on
# PATH (design/adr/0005-shell-out-to-sops-cli.md) and SKIP -- not fail --
# when they're missing, so a plain `make test` on a machine without them
# silently runs fewer tests instead of erroring. Run `make devtools` once
# per dev machine/CI image to make sure that never happens quietly: those
# tests include the single most important one in the project (WORKFLOW.md
# Phase 2), the end-to-end proof that a resolved secret never leaks to an
# upstream process's client.
test:
	go test -count=1 ./...

# devtools installs the external, non-Go-module tools this project's own
# code shells out to (design/adr/0005-shell-out-to-sops-cli.md) into
# $(go env GOPATH)/bin. Run once per dev machine/CI image, then make sure
# that directory is on PATH.
devtools:
	go install github.com/getsops/sops/v3/cmd/sops@latest
	go install filippo.io/age/cmd/age@latest
	go install filippo.io/age/cmd/age-keygen@latest

vet:
	go vet ./...

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; echo "$$out"; exit 1; \
	fi

check: fmt-check vet test build
