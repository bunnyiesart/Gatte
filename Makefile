.PHONY: build test vet fmt-check check lab-build lab-probe devtools

build:
	go build -o bin/mcp-gateway ./cmd/mcp-gateway

# Builds the four fake upstream MCP servers and the probe (lab/README.md,
# "Go implementation"). Binaries go to bin/lab/, gitignored like bin/
# itself.
lab-build:
	@mkdir -p bin/lab
	go build -o bin/lab/casemgmt ./lab/servers/casemgmt
	go build -o bin/lab/logsearch ./lab/servers/logsearch
	go build -o bin/lab/docsearch ./lab/servers/docsearch
	go build -o bin/lab/threatintel ./lab/servers/threatintel
	go build -o bin/lab/probe ./lab/probe

# Runs the probe against all four fake servers as real subprocesses (not
# the in-memory transport the unit tests use) -- the actual end-to-end
# credential-injection + leak check, same property WORKFLOW.md Phase 5
# will run against the real gateway.
lab-probe: lab-build
	@for name in casemgmt logsearch docsearch threatintel; do \
		echo "== $$name =="; \
		./bin/lab/probe --tool $${name}_credcheck -- ./bin/lab/$$name || exit 1; \
	done

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
	@missing=""; \
	for tool in sops age age-keygen; do \
		command -v $$tool >/dev/null 2>&1 || missing="$$missing $$tool"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "############################################################"; \
		echo "# WARNING: not on PATH:$$missing"; \
		echo "#"; \
		echo "# internal/vault/sopsage's tests will SKIP, not fail. That"; \
		echo "# includes TestResolveThenSpawnDoesNotLeak -- the end-to-end"; \
		echo "# proof that a resolved secret never leaks to an upstream's"; \
		echo "# client, which WORKFLOW.md Phase 2 calls the single most"; \
		echo "# important test in this project."; \
		echo "#"; \
		echo "# A green 'make test' below does NOT mean that property was"; \
		echo "# verified. Fix with:  make devtools"; \
		echo "#   (then put \$$(go env GOPATH)/bin on your PATH -- installing"; \
		echo "#    them is not enough if the shell can't see them)"; \
		echo "############################################################"; \
	fi
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
