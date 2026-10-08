.PHONY: all build build-windows test test-race check clean fmt

BIN := mnagent
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)_windows_amd64.exe .
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)_windows_arm64.exe .

test:
	go test -v ./...

test-race:
	go test -race -v ./...

fmt:
	gofmt -s -w .

check: test test-race
	go vet ./...

clean:
	rm -f $(BIN) $(BIN).exe mnagent_* coverage.out coverage.html
	rm -rf dist/
