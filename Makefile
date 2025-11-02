# Makefile for go-apikeys
# Following CODE_RULES.md standards

# Project metadata
PROJECT_NAME := go-apikeys
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0-dev")
COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
BUILD_USER := $(shell whoami)

# Build flags for version injection
LDFLAGS := -X github.com/itsatony/go-version.GitCommit=$(COMMIT)
LDFLAGS += -X github.com/itsatony/go-version.GitTag=$(VERSION)
LDFLAGS += -X github.com/itsatony/go-version.BuildTime=$(BUILD_TIME)
LDFLAGS += -X github.com/itsatony/go-version.BuildUser=$(BUILD_USER)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
GOFMT=$(GOCMD) fmt

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version: ## Display version information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Build User: $(BUILD_USER)"

.PHONY: tidy
tidy: ## Tidy dependencies
	$(GOMOD) tidy

.PHONY: fmt
fmt: ## Format code
	$(GOFMT) ./...

.PHONY: vet
vet: ## Run go vet
	$(GOVET) ./...

.PHONY: lint
lint: ## Run linter
	@which golangci-lint > /dev/null || (echo "Install golangci-lint: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

.PHONY: vulncheck
vulncheck: ## Run vulnerability check
	@which govulncheck > /dev/null || (echo "Install govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest" && exit 1)
	govulncheck ./...

.PHONY: test
test: ## Run tests
	$(GOTEST) -v -cover ./...

.PHONY: test-race
test-race: ## Run tests with race detector
	$(GOTEST) -v -race ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	$(GOTEST) -v -tags=integration ./...

.PHONY: coverage
coverage: ## Generate coverage report
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: bench
bench: ## Run benchmarks
	$(GOTEST) -bench=. -benchmem ./...

.PHONY: clean
clean: ## Clean build artifacts
	@rm -f coverage.out coverage.html
	@echo "✅ Cleaned build artifacts"

.PHONY: gates
gates: fmt vet test-race coverage vulncheck ## Run all excellence gates
	@echo "✅ All excellence gates passed"

.PHONY: ci
ci: tidy fmt vet test-race ## CI pipeline checks
	@echo "✅ CI checks passed"

.PHONY: all
all: clean tidy fmt vet test-race ## Build everything
	@echo "✅ All tasks completed"

.DEFAULT_GOAL := help
