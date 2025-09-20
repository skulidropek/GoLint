BIN_DIR := bin
LINT_BIN := $(BIN_DIR)/go-lint
TARGET ?= ./...

.PHONY: build lint vet vuln check fmt clean

build: $(BIN_DIR)
	GOCACHE=$(PWD)/.gocache go build -o $(LINT_BIN) ./cmd/lint

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

lint: build
	$(LINT_BIN) $(TARGET)

vet:
	go vet ./...

vuln:
	govulncheck ./...

check: lint vet vuln

fmt:
	gofmt -w $(shell go list -f '{{.Dir}}' ./...)

clean:
	rm -rf $(BIN_DIR) .gocache
