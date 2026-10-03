# dxdfir Go/termui front-end.
GO      ?= go
BIN     ?= dxdfir
PREFIX  ?=

# `make link` install layout — the SAME as scripts/setup-environment.sh, so a
# rebuild after a code edit drops the new binary exactly where the provisioned
# host already runs it: a real file in /usr/local/bin, on every default PATH
# (sudo's secure_path included), no shim and no PATH edit. Override on the
# command line if needed.
# (Keep these assignments comment-free: a trailing `# ...` here would leak the
# whitespace before it into the value and corrupt the install paths.)
BIN_DIR    ?= /usr/local/bin
MAN_DIR    ?= /usr/local/share/man/man1
# Auto-elevate only when not already root (empty $(SUDO) is a no-op prefix).
SUDO       ?= $(shell [ "$$(id -u)" -eq 0 ] || echo sudo)

.PHONY: build install link check fmt fmt-check vet tidy clean

build: ## build ./dxdfir
	$(GO) build -o $(BIN) ./cmd/dxdfir

install: ## go install as `dxdfir` (into $GOBIN / $GOPATH/bin)
	$(GO) install ./cmd/dxdfir

link: build ## build, then install `dxdfir` onto PATH (same layout as setup-environment.sh; uses sudo when not root)
	$(SUDO) install -Dm0755 "$(BIN)" "$(BIN_DIR)/dxdfir"
	$(SUDO) install -Dm644 man/dxdfir.1 "$(MAN_DIR)/dxdfir.1" 2>/dev/null \
		|| echo "note: man page not installed (read: man ./man/dxdfir.1)"
	@echo "installed: $(BIN_DIR)/dxdfir   —   run it anywhere:  dxdfir"

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
