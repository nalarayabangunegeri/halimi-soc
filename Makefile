# HalimiSOC — development and operations entry points.
#
# Every target is safe to run repeatedly. Security-relevant checks (vet,
# vulnerability scan, secret scan) are part of `make check` so they cannot be
# skipped merely by running the tests.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

MODULE      := github.com/halimi/halimisoc
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
BIN         := bin

GO          ?= go
GOFLAGS     ?= -trimpath
DATABASE_URL ?= postgres://halimisoc:halimisoc_dev_pw@127.0.0.1:5432/halimisoc?sslmode=disable
TEST_DATABASE_URL ?= postgres://halimisoc:halimisoc_dev_pw@127.0.0.1:5432/halimisoc_test?sslmode=disable

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

## --- Build ---------------------------------------------------------------

.PHONY: build
build: build-api build-agent ## Build both binaries into ./bin

.PHONY: build-api
build-api: ## Build the API server
	@mkdir -p $(BIN)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/halimisoc-api ./apps/api

.PHONY: build-agent
build-agent: ## Build the collection agent
	@mkdir -p $(BIN)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/halimisoc-agent ./apps/agent

## --- Verify --------------------------------------------------------------

.PHONY: fmt
fmt: ## Format all Go sources
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is not gofmt-clean
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: test
test: ## Run the unit test suite
	$(GO) test ./... -count=1

.PHONY: test-race
test-race: ## Run the unit test suite with the race detector
	$(GO) test ./... -count=1 -race

.PHONY: test-cover
test-cover: ## Run tests and report coverage
	$(GO) test ./... -count=1 -coverprofile=coverage.txt -covermode=atomic
	$(GO) tool cover -func=coverage.txt | tail -1

.PHONY: test-e2e
test-e2e: ## Run the black-box end-to-end test (needs a database)
	HALIMISOC_TEST_DATABASE_URL="$(TEST_DATABASE_URL)" $(GO) test ./tests/ -count=1 -v -timeout 300s

.PHONY: vuln
vuln: ## Scan dependencies for known vulnerabilities
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

.PHONY: secrets
secrets: ## Scan the working tree for committed secrets
	@command -v gitleaks >/dev/null 2>&1 || { \
		echo "install gitleaks: https://github.com/gitleaks/gitleaks"; exit 1; }
	gitleaks detect --no-git --redact -v

.PHONY: check
check: fmt-check vet test ## Everything CI runs, minus the slow scans

## --- Console --------------------------------------------------------------

WEB_DIR := apps/web

.PHONY: web-install
web-install: ## Install the console's npm dependencies
	cd $(WEB_DIR) && npm install

.PHONY: web-check
web-check: ## Typecheck, unit-test and production-build the console
	cd $(WEB_DIR) && npx tsc --noEmit
	cd $(WEB_DIR) && npx vitest run
	cd $(WEB_DIR) && npm run build

.PHONY: web-test
web-test: ## Run the console's unit tests
	cd $(WEB_DIR) && npx vitest run

.PHONY: web-e2e
web-e2e: ## Run the console end-to-end suite (needs a database)
	cd $(WEB_DIR) && \
		HALIMISOC_TEST_DATABASE_URL="$(TEST_DATABASE_URL)" npx playwright test

.PHONY: web-run
web-run: ## Run the console dev server on :3000
	cd $(WEB_DIR) && npm run dev

## --- Database ------------------------------------------------------------

.PHONY: db-create
db-create: ## Create the development role and databases
	sudo -u postgres psql -v ON_ERROR_STOP=1 \
		-c "DO \$$\$$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='halimisoc') THEN CREATE ROLE halimisoc LOGIN PASSWORD 'halimisoc_dev_pw'; END IF; END \$$\$$;" \
		-c "CREATE DATABASE halimisoc OWNER halimisoc;" \
		-c "CREATE DATABASE halimisoc_test OWNER halimisoc;"

.PHONY: db-drop
db-drop: ## Drop the development databases
	sudo -u postgres dropdb --if-exists halimisoc
	sudo -u postgres dropdb --if-exists halimisoc_test

.PHONY: run
run: build-api ## Run the API against the development database
	HALIMISOC_DATABASE_URL="$(DATABASE_URL)" \
	HALIMISOC_RULES_PATH=packages/rules \
	HALIMISOC_ADMIN_PASSWORD=halimisoc-dev-admin \
	HALIMISOC_AGENT_ENROLL_SECRET=halimisoc-dev-enrollment-secret \
	$(BIN)/halimisoc-api

.PHONY: simulate
simulate: build-agent ## Run the synthetic attack scenario against a local API
	$(BIN)/halimisoc-agent \
		-server http://127.0.0.1:8080 \
		-enroll-token halimisoc-dev-enrollment-secret \
		-simulate -insecure \
		-host demo-host \
		-spool-dir data/spool -state-dir data/state

.PHONY: clean
clean: ## Remove build artifacts and local runtime state
	rm -rf $(BIN) coverage.txt data
