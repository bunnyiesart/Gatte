.PHONY: build test vet fmt-check check lab-build lab-probe

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
test:
	go test -count=1 ./...

vet:
	go vet ./...

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; echo "$$out"; exit 1; \
	fi

check: fmt-check vet test build
