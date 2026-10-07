.PHONY: all build test test-race check clean fmt

BIN := mnagent
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

test:
	go test -v ./...

test-race:
	go test -race -v ./...

fmt:
	gofmt -s -w .

check: test test-race
	go vet ./...

clean:
	rm -f $(BIN) mnagent_* coverage.out coverage.html
	rm -rf dist/
