.PHONY: build test test-unit test-integration test-coverage clean lint fmt vet security run dev docker-build docker-run help

# Build variables
BINARY_NAME=auth-service
BINARY_PATH=./bin/$(BINARY_NAME)
MAIN_PATH=./cmd/server
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

run: ## Run the application
	@echo "Running $(BINARY_NAME)..."
	go run $(MAIN_PATH)

dev: ## Run the application in development mode with live reload
	@echo "Running in development mode..."
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -rf tmp/
	@rm -f $(COVERAGE_OUT) $(COVERAGE_HTML)
	@go clean

fmt: ## Format Go code
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w $(GO_FILES) 2>/dev/null || echo "goimports not found, run: go install golang.org/x/tools/cmd/goimports@latest"

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

lint: ## Run golangci-lint
	@echo "Running golangci-lint..."
	@golangci-lint run || (echo "golangci-lint not found, install from: https://golangci-lint.run/usage/install/")

security: ## Run security checks
	@echo "Running security checks..."
	@gosec ./... || (echo "gosec not found, run: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest")

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

tools: ## Install development tools
	@echo "Installing development tools..."
	@go install github.com/cosmtrek/air@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "Tools installed successfully"

check: fmt vet lint security test ## Run all checks (format, vet, lint, security, test)
