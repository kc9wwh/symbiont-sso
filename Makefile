# Local developer tasks. CI (.github/workflows) is the authority; these
# targets run the same checks so problems show up before a push.
#
#   make check        everything CI gates on, except the image build
#   make fuzz-smoke   run every fuzz target briefly (FUZZTIME=5s by default)
#   make hooks        enable the git hooks in .githooks
#
# Tool versions for govulncheck and actionlint are read from security.yml so
# local runs and CI cannot drift apart.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

WORKFLOW_ENV := .github/workflows/security.yml
GOVULNCHECK_VERSION ?= $(shell sed -n 's/^  GOVULNCHECK_VERSION: //p' $(WORKFLOW_ENV))
ACTIONLINT_VERSION  ?= $(shell sed -n 's/^  ACTIONLINT_VERSION: //p' $(WORKFLOW_ENV))
ZIZMOR_VERSION      ?= $(shell sed -n 's/^  ZIZMOR_VERSION: //p' $(WORKFLOW_ENV))
FUZZTIME            ?= 5s

.DEFAULT_GOAL := help
.PHONY: help fmt fmt-check vet lint test vuln workflow-lint fuzz-smoke check hooks

help: ## List targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

fmt: ## Format all Go files in place
	gofmt -w .

fmt-check: ## Fail if any Go file is not gofmt'ed
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "Not gofmt'ed (run make fmt):"; echo "$$unformatted"; exit 1; fi

vet: ## go vet
	go vet ./...

lint: ## golangci-lint (config: .golangci.yml)
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not found; see the Development section of the README"; exit 1; }
	golangci-lint run

test: ## Race tests (includes every fuzz target's seed corpus)
	go test -race -count=1 ./...

vuln: ## govulncheck (needs network)
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

workflow-lint: ## actionlint, plus zizmor when uvx is installed
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	@if command -v uvx >/dev/null; then \
		uvx zizmor@$(ZIZMOR_VERSION) .github/workflows; \
	else \
		echo "uvx not found: skipped zizmor (CI still runs it)"; \
	fi

fuzz-smoke: ## Run every fuzz target for FUZZTIME (default 5s) each
	@status=0; \
	for pkg in $$(go list ./...); do \
		for target in $$(go test "$$pkg" -list '^Fuzz' | grep '^Fuzz' || true); do \
			echo "== $$pkg $$target ($(FUZZTIME))"; \
			go test "$$pkg" -run '^$$' -fuzz "^$$target\$$" -fuzztime "$(FUZZTIME)" || status=1; \
		done; \
	done; \
	exit $$status

check: fmt-check vet lint test vuln workflow-lint ## Everything CI gates on (except the image build)

hooks: ## Enable the git hooks in .githooks for this clone
	git config core.hooksPath .githooks
	@echo "hooks enabled: pre-commit (gofmt, vet), pre-push (lint, test, vuln)"
