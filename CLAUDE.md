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

# Run a single test
go test -v -run TestFunctionName ./internal/path/to/package/...

# Run tests in a specific file
go test -v ./internal/auth/... -run "TestCrypto"

# Run with race detection
go test -race ./...
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

### Client Management

```bash
make env-setup               # Create .env.local with secure JWT secret
make build-client-manager    # Build client-manager CLI tool
make register-clients-config # Register clients from configs/clients.json
make get-token CLIENT_ID=<id> CLIENT_SECRET=<secret>  # Get access token for testing
```

### Docker

```bash
make docker-build   # Build Docker image
make docker-run     # Run in Docker container
docker-compose -f docker-compose.dev.yml up -d  # Development environment
docker-compose up -d                             # Production environment
```

## Architecture Overview

OAuth2 authentication service built in Go with hybrid storage architecture.

### Core Components

- **HTTP Layer**: Gorilla Mux router with middleware stack (CORS, rate limiting, logging, security headers)
- **Business Logic**: OAuth2 service supporting Authorization Code Flow with PKCE and Client Credentials Flow
- **Storage Layer**:
  - PostgreSQL for persistent user data
  - MySQL for OAuth2 client credentials (primary storage)
  - Redis for sessions/tokens/client cache with graceful degradation

### Key Packages

- `cmd/server/main.go` - Application entry point with dependency injection
- `cmd/client-manager/main.go` - CLI tool for OAuth2 client management
- `internal/auth/` - OAuth2 business logic, client management, and user services
- `internal/handlers/` - HTTP handlers for OAuth2 endpoints, user auth, and health checks
- `internal/middleware/` - Security middleware (CORS, rate limiting, logging)
- `internal/token/` - JWT and PKCE token services
- `internal/database/postgres/` - PostgreSQL connection management with health monitoring
- `internal/database/mysql/` - MySQL connection management for OAuth2 client storage
- `internal/repository/` - Repository interfaces and implementations (cache-aside pattern)
- `internal/redis/` - Redis client with fallback memory store
- `internal/config/` - Environment-based configuration management
- `internal/startup/` - Client auto-registration on service startup
- `pkg/logger/` - Enhanced logging with dual output support

### Configuration

**Hybrid configuration approach** separating connection data from operational settings:

- **Environment variables** (`.env.local`) - Connection data and secrets only (see `.env.example`)
  - `ENVIRONMENT` variable determines which YAML config to load (LOCAL, NONPROD, PROD)
  - JWT_SECRET is REQUIRED (minimum 32 characters)
- **YAML configuration files** (`configs/*.yaml`) - Operational settings (committed to repository)
  - `configs/defaults.yaml` - Base configuration loaded first
  - `configs/local.yaml`, `configs/nonprod.yaml`, `configs/prod.yaml` - Environment-specific overlays
  - Settings: timeouts, pool sizes, JWT expiry, OAuth2 scopes, rate limits, CORS origins, logging
- Use `make env-setup` to create `.env.local` with a secure JWT secret

### Health Check Behavior

- **healthy**: Redis + PostgreSQL + MySQL all available
- **degraded**: Redis available, but PostgreSQL or MySQL unavailable (returns 200 for k8s)
- **unhealthy**: Redis unavailable (returns 503)

### OAuth2 Flows Supported

- **Authorization Code Flow with PKCE** (RFC 7636) - Required for web/mobile clients
- **Client Credentials Flow** - Service-to-service authentication
- **Refresh Token Flow** - Token renewal with rotation support
- **Token Introspection** (RFC 7662) - Token validation endpoint
- **Token Revocation** (RFC 7009) - Secure token invalidation
- **OpenID Connect UserInfo** - User profile endpoint

### API Route Prefix

All API routes are prefixed with `/api/v1/auth`

### Development Notes

- Uses Go 1.24+ with modules
- Graceful shutdown with proper database connection cleanup
- Service startup independent of database availability (graceful degradation)
- Client secrets hashed with bcrypt before storage (never stored plaintext)
- Prometheus metrics at `/api/v1/auth/metrics`
- Sample client auto-created when `CLIENT_AUTO_REGISTER_CREATE_SAMPLE_CLIENT=true`
