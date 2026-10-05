# dx Go front-end.
GO      ?= go
BIN     ?= dx
PREFIX  ?=

# `make link` install layout — the SAME as scripts/setup-environment.sh: the
# binary goes into the repo-local .go/bin/ directory (gitignored). Override
# BIN_DIR on the command line if needed.
# (Keep these assignments comment-free: a trailing `# ...` here would leak the
# whitespace before it into the value and corrupt the install paths.)
BIN_DIR    ?= ../.go/bin

.PHONY: build install link check fmt fmt-check vet tidy clean

build: ## build ./dx
	$(GO) build -o $(BIN) ./cmd/dx

install: ## go install as `dx` (into $GOBIN / $GOPATH/bin)
	$(GO) install ./cmd/dx

link: build ## build, then install `dx` into .go/bin/ (same layout as setup-environment.sh)
	install -Dm0755 "$(BIN)" "$(BIN_DIR)/dx"
	@echo "installed: $(BIN_DIR)/dx"

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
