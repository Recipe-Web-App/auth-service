# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build & Run

```bash
make build          # Build the application binary
make run            # Run application locally
make dev            # Run with hot reload using air
make clean          # Clean build artifacts
```

### Testing

```bash
make test           # Run all tests (unit + integration)
make test-unit      # Run unit tests only
make test-integration  # Run integration tests with testcontainers
make test-coverage  # Generate HTML coverage report
make benchmark      # Run performance benchmarks
```

### Code Quality

```bash
make fmt            # Format code with gofmt and goimports
make vet            # Run go vet static analysis
make lint           # Run golangci-lint
make security       # Run gosec security checks
make check          # Run all checks (fmt, vet, lint, security, test)
```

### Dependencies

```bash
make deps           # Download and tidy Go modules
make tools          # Install development tools (air, goimports, gosec)
```

### Docker

```bash
make docker-build   # Build Docker image
make docker-run     # Run in Docker container
docker-compose -f docker-compose.dev.yml up -d  # Development environment
docker-compose up -d                             # Production environment
```

### Kubernetes

```bash
./scripts/containerManagement/deploy-container.sh     # Complete deployment
./scripts/containerManagement/get-container-status.sh # Check status
./scripts/containerManagement/update-container.sh     # Rolling update
```

## Architecture Overview

This is an enterprise-grade OAuth2 authentication service built in Go with the following architecture:

### Core Components

- **HTTP Layer**: Gorilla Mux router with comprehensive middleware stack
- **Business Logic**: OAuth2 service supporting Authorization Code Flow with PKCE and Client Credentials Flow
- **Infrastructure**: Redis for session/token storage with fallback to in-memory store
- **Token Services**: JWT generation/validation and PKCE implementation

### Key Packages

- `cmd/server/main.go` - Application entry point with dependency injection
- `internal/auth/` - OAuth2 business logic and client management
- `internal/handlers/` - HTTP handlers for OAuth2 endpoints and health checks
- `internal/middleware/` - Security middleware (CORS, rate limiting, logging)
- `internal/token/` - JWT and PKCE token services
- `internal/redis/` - Redis client with fallback memory store
- `internal/config/` - Environment-based configuration management
- `pkg/logger/` - Enhanced logging with dual output support

### Configuration

- Environment variables with validation and defaults
- `.env.local` file for development (automatically loaded)
- Comprehensive validation including JWT secret length and port ranges
- Support for TLS/HTTPS when certificate paths provided

### Security Features

- PKCE enforcement for Authorization Code Flow
- Rate limiting per client/IP
- CORS protection with configurable origins
- Secure token generation using crypto/rand
- JWT tokens signed with configurable algorithms (HS256/RS256/etc)
- Security headers middleware

### Testing Strategy

- Unit tests for individual components
- Integration tests using testcontainers for Redis
- Comprehensive coverage reporting
- Security scanning with gosec
- Performance benchmarking

### Key Dependencies

- Redis for session storage (with in-memory fallback)
- JWT tokens using golang-jwt/jwt library
- Gorilla Mux for routing
- Prometheus metrics integration
- Structured logging with logrus
- testcontainers for integration testing

### Development Notes

- Uses Go 1.23+ with modules
- Graceful shutdown support
- Health checks (liveness/readiness probes)
- Prometheus metrics at `/api/v1/auth/metrics`
- Sample client automatically created for testing
- Docker multi-stage builds for production
- Kubernetes manifests in `k8s/` directory
