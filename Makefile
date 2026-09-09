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
# `sops`, `age` and `age-keygen` are runtime prerequisites, not Go module
# dependencies (design/adr/0005-shell-out-to-sops-cli.md), so the tests
# that need them SKIP rather than fail. A plain `make test` on a machine
# without them prints `ok` for every package while silently proving less.
#
# Two packages are affected, not one:
#
#   internal/vault/sopsage -- TestResolveThenSpawnDoesNotLeak, which
#     WORKFLOW.md Phase 2 calls the single most important test in the
#     project: the end-to-end proof that a resolved secret never reaches an
#     upstream process's client.
#
#   cmd/mcp-gateway -- five tests in serve_test.go, because buildServer
#     wires the *real* adapters and so needs a real sops-encrypted fixture.
#     Measured: buildServer goes from 0.0% to 90.1% statement coverage
#     depending on nothing but whether sops is on PATH, and both runs say
#     `ok`. What is lost includes TestBuildServer_AuthSeamIsWired -- the
#     only test that authentication is wired into the server at all -- and
#     TestBuildServer_UnreadableRegistryIsFatal, the only boot-level test
#     of ADR-0004's fail-closed rule.
#
# So the banner below names both, and treats the common case specifically:
# `make devtools` installs into $(go env GOPATH)/bin, which is frequently
# not on PATH, and the resulting failure looks identical to not having
# installed them at all. The `test` target prepends that directory to PATH
# itself -- installing them should be enough.
GOPATH_BIN := $(shell go env GOPATH)/bin

test: export PATH := $(GOPATH_BIN):$(PATH)
test:
	@missing=""; \
	for tool in sops age age-keygen; do \
		command -v $$tool >/dev/null 2>&1 || missing="$$missing $$tool"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "############################################################"; \
		echo "# WARNING: not on PATH:$$missing"; \
		echo "# (already searched $(GOPATH_BIN))"; \
		echo "#"; \
		echo "# These tests will SKIP, not fail:"; \
		echo "#"; \
		echo "#   internal/vault/sopsage"; \
		echo "#     TestResolveThenSpawnDoesNotLeak -- the end-to-end proof"; \
		echo "#     that a resolved secret never leaks to an upstream's"; \
		echo "#     client. WORKFLOW.md Phase 2: the single most important"; \
		echo "#     test in this project."; \
		echo "#"; \
		echo "#   cmd/mcp-gateway (serve_test.go, 5 tests)"; \
		echo "#     buildServer drops from 90.1% to 0.0% coverage. Lost:"; \
		echo "#     TestBuildServer_AuthSeamIsWired (the only test that"; \
		echo "#     authentication is wired at all), and"; \
		echo "#     TestBuildServer_UnreadableRegistryIsFatal (the only"; \
		echo "#     boot-level test of ADR-0004 fail-closed). Also"; \
		echo "#     MetadataIsServedUnauthenticated,"; \
		echo "#     OneUnavailableUpstreamIsNotFatal, RunShutsDownCleanly."; \
		echo "#"; \
		echo "# A green 'make test' below does NOT mean any of that was"; \
		echo "# verified. Fix with:  make devtools"; \
		echo "############################################################"; \
	fi
	go test -count=1 ./...

# devtools installs the external, non-Go-module tools this project's own
# code shells out to (design/adr/0005-shell-out-to-sops-cli.md) into
# $(GOPATH_BIN). Run once per dev machine/CI image. `make test` searches
# that directory whether or not it is on your PATH; a bare `go test ./...`
# does not, so put it on PATH anyway if you run go test directly.
#
# Note this installs @latest, so the version here drifts ahead of the
# minimum pinned in deploy/freebsd-jail.md ("sops version").
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
