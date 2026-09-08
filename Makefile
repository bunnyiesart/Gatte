.PHONY: build test vet fmt-check check

build:
	go build -o bin/mcp-gateway ./cmd/mcp-gateway

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
