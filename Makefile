# Delegator Service Makefile

# Variables
BINARY := delegator
BUILD_DIR := bin
PACKAGE := github.com/storacha/delegator

# Build information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS := -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)
BUILD_FLAGS := -ldflags "$(LDFLAGS)"

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOFMT := $(GOCMD) fmt

.PHONY: build
build: ## Build the delegator binary
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY) .
	@echo "Binary built: $(BUILD_DIR)/$(BINARY)"

.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v ./...

.PHONY: test-single
test-single: ## Run a single test
	$(GOTEST) -v ./internal/testing -run TestHappyPath

.PHONY: clean
clean: ## Remove built binaries and temporary files
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f delegation.json coverage.out

.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...

.PHONY: lint
lint: ## Run linter (requires golangci-lint)
	@echo "Running linter..."
	golangci-lint run

.PHONY: quick
quick: fmt ## Quick development cycle
	@echo "Running quick dev cycle..."
	go vet ./...
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY) .

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Docker commands
.PHONY: docker-build
docker-build: ## Build Docker images
	@echo "Building Docker images..."
	docker-compose build

.PHONY: docker-up
docker-up: ## Start Docker containers
	@echo "Starting Docker containers..."
	docker-compose up -d --build

.PHONY: docker-logs
docker-logs: ## View logs for running containers
	@echo "Viewing logs..."
	docker-compose logs -f

.PHONY: docker-down
docker-down: ## Stop Docker containers
	@echo "Stopping Docker containers..."
	docker-compose down

.PHONY: docker-clean
docker-clean: ## Stop and remove Docker containers, volumes, and images
	@echo "Cleaning Docker environment..."
	docker-compose down -v --remove-orphans
	docker-compose rm -f

.PHONY: docker
docker: docker-build docker-up ## Build and start Docker containers

.PHONY: all
all: clean test build ## Run all checks and build

.PHONY: help
help: ## Display this help message
	@echo "Delegator Service"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Default target
.DEFAULT_GOAL := build