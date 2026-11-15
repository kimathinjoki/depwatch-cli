# watchdep-cli. `make test lint` is the full suite; `make snapshot` builds every release binary locally.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/kimathinjoki/watchdep-cli/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

.PHONY: build test lint live snapshot clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/watchdep ./cmd/watchdep

# Unit tests and the known incidents corpus, offline.
test:
	go test -race ./...

lint:
	gofmt -l . | (! grep .) || (echo "gofmt needed on the files above" && exit 1)
	go vet ./...
	go vet -tags live ./...
	staticcheck ./...

# Re-runs the corpus against the real sources and reports any difference from the recordings.
live:
	go test -tags live ./internal/corpus -run TestCorpusLive -v

# Six binaries (Linux, macOS, Windows on amd64 and arm64) and a checksums file in dist/. Nothing is published.
snapshot:
	WATCHDEP_COMMIT=$(COMMIT) goreleaser release --snapshot --clean
	./scripts/check-snapshot.sh

clean:
	rm -rf bin dist
