.PHONY: build test test-unit test-integration test-coverage clean lint fmt vet security run dev docker-build docker-run help

# Build variables
BINARY_NAME=auth-service
CLIENT_MANAGER_BINARY=client-manager
BINARY_PATH=./bin/$(BINARY_NAME)
CLIENT_MANAGER_PATH=./bin/$(CLIENT_MANAGER_BINARY)
MAIN_PATH=./cmd/server
CLIENT_MANAGER_MAIN_PATH=./cmd/client-manager
GO_FILES=$(shell find . -name "*.go" -type f -not -path "./vendor/*")

# Docker variables
DOCKER_IMAGE=auth-service
DOCKER_TAG=latest

# Coverage variables
COVERAGE_OUT=coverage.out
COVERAGE_HTML=coverage.html

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	go build -ldflags="-w -s" -o $(BINARY_PATH) $(MAIN_PATH)

build-client-manager: ## Build the client manager CLI tool
	@echo "Building $(CLIENT_MANAGER_BINARY)..."
	@mkdir -p bin
	go build -ldflags="-w -s" -o $(CLIENT_MANAGER_PATH) $(CLIENT_MANAGER_MAIN_PATH)

build-all: build build-client-manager ## Build all binaries

run: ## Run the application
	@echo "Running $(BINARY_NAME)..."
	go run $(MAIN_PATH)

dev: ## Run the application in development mode with live reload
	@echo "Running in development mode..."
	go tool github.com/air-verse/air

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -rf tmp/
	@rm -f $(COVERAGE_OUT) $(COVERAGE_HTML)
	@go clean

fmt: ## Format Go code
	@echo "Formatting code..."
	@go fmt ./...
	@go tool golang.org/x/tools/cmd/goimports -w $(GO_FILES)

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

lint: ## Run golangci-lint
	@echo "Running golangci-lint..."
	@golangci-lint run || (echo "golangci-lint not found, install from: https://golangci-lint.run/usage/install/")

security: ## Run security checks
	@echo "Running security checks..."
	@go tool github.com/securego/gosec/v2/cmd/gosec ./...

test: test-unit ## Run all tests

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	@go test -v -race -short ./...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	@go test -v -race ./test/integration/...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./...
	@go tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE):$(DOCKER_TAG)

deps: ## Download and tidy dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

tools: ## Show info about development tools (managed via go.mod + tools.go)
	@echo "Development tools are managed via go.mod and tools.go"
	@echo "They run automatically via 'go tool' (Go 1.24+) - no manual install needed"
	@echo ""
	@echo "Tools available:"
	@echo "  - air (hot reload): used by 'make dev'"
	@echo "  - goimports: used by 'make fmt'"
	@echo "  - gosec: used by 'make security'"

check: fmt vet lint security test ## Run all checks (format, vet, lint, security, test)

## Client Management Commands

register-clients: ## Register backend service clients using the shell script
	./scripts/register-clients.sh

register-clients-cli: build-client-manager ## Register backend service clients using CLI tool (batch mode)
	./$(CLIENT_MANAGER_PATH) -batch

register-clients-config: build-client-manager ## Register clients from config file
	./$(CLIENT_MANAGER_PATH) -config configs/clients.json

client-manager-help: build-client-manager ## Show client manager help
	./$(CLIENT_MANAGER_PATH) -h

get-token: ## Get access token for a client (requires CLIENT_ID and CLIENT_SECRET env vars)
	@if [ -z "$(CLIENT_ID)" ] || [ -z "$(CLIENT_SECRET)" ]; then \
		echo "Usage: make get-token CLIENT_ID=<id> CLIENT_SECRET=<secret>"; \
		exit 1; \
	fi
	./scripts/get-client-token.sh $(CLIENT_ID) $(CLIENT_SECRET)

## Environment Setup

env-setup: ## Create .env.local file with defaults
	@if [ ! -f .env.local ]; then \
		echo "Creating .env.local with default values..."; \
		echo "# Environment variables for local development" > .env.local; \
		echo "JWT_SECRET=$$(openssl rand -base64 32)" >> .env.local; \
		echo ".env.local created with a secure JWT secret"; \
	else \
		echo ".env.local already exists"; \
	fi
