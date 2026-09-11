# dxdfir Go/termui front-end.
GO      ?= go
BIN     ?= dxdfir
PREFIX  ?=

.PHONY: build install check fmt vet tidy clean

build: ## build ./dxdfir
	$(GO) build -o $(BIN) ./cmd/dxdfir

install: ## go install as `dxdfir`
	$(GO) install ./cmd/dxdfir

check: fmt-check vet build ## gofmt -l, go vet, build

fmt: ## gofmt -w the tree
	gofmt -w .

fmt-check: ## fail if any file needs gofmt
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet: ## go vet
	$(GO) vet ./...

tidy: ## go mod tidy
	$(GO) mod tidy

clean: ## remove the built binary
	rm -f $(BIN)
