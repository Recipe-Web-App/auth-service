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

### Client Management

```bash
make env-setup               # Create .env.local with secure JWT secret
make build-client-manager    # Build client-manager CLI tool
make register-clients        # Register clients via shell script
make register-clients-cli    # Register clients via CLI (batch mode)
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

### Kubernetes

```bash
./scripts/containerManagement/deploy-container.sh     # Complete deployment
./scripts/containerManagement/get-container-status.sh # Check status
./scripts/containerManagement/update-container.sh     # Rolling update
```

## Architecture Overview

This is an enterprise-grade OAuth2 authentication service built in Go with hybrid storage architecture:

### Core Components

- **HTTP Layer**: Gorilla Mux router with comprehensive middleware stack
- **Business Logic**: OAuth2 service supporting Authorization Code Flow with PKCE and Client Credentials Flow
- **Storage Layer**:
  - PostgreSQL for persistent user data
  - MySQL for OAuth2 client credentials (primary storage)
  - Redis for sessions/tokens/client cache with graceful degradation
- **Token Services**: JWT generation/validation and PKCE implementation
- **User Management**: Database-first strategy with Redis caching for performance
- **Client Management**: Hybrid MySQL + Redis architecture with bcrypt secret hashing

### Key Packages

- `cmd/server/main.go` - Application entry point with dependency injection
- `cmd/client-manager/main.go` - CLI tool for OAuth2 client management
- `internal/auth/` - OAuth2 business logic, client management, and user services
- `internal/handlers/` - HTTP handlers for OAuth2 endpoints, user auth, and health checks
- `internal/middleware/` - Security middleware (CORS, rate limiting, logging)
- `internal/token/` - JWT and PKCE token services
- `internal/database/postgres/` - PostgreSQL connection management with health monitoring
- `internal/database/mysql/` - MySQL connection management for OAuth2 client storage
- `internal/repository/` - Repository interfaces and implementations:
  - User data repository (PostgreSQL implementation)
  - Client repository interface (MySQL primary + Redis cache hybrid implementation)
  - Hybrid client repository with cache-aside pattern
- `internal/redis/` - Redis client with fallback memory store
- `internal/config/` - Environment-based configuration management (includes database config)
- `internal/startup/` - Client auto-registration on service startup
- `pkg/logger/` - Enhanced logging with dual output support

### Configuration

- Environment variables with validation and defaults (see `.env.example`)
- MySQL database configuration for OAuth2 client storage (optional - service runs without it)
- `.env.local` file for development (automatically loaded when GO_ENV is not set or is "development")
- Use `make env-setup` to create `.env.local` with a secure JWT secret
- Comprehensive validation including JWT secret length (min 32 chars) and port ranges
- PostgreSQL database configuration (optional - service works without database)
- Support for TLS/HTTPS when certificate paths provided
- Client auto-registration via `configs/clients.json` when `CLIENT_AUTO_REGISTER_ENABLED=true`

### Security Features

- PKCE enforcement for Authorization Code Flow
- Rate limiting per client/IP
- CORS protection with configurable origins
- Secure token generation using crypto/rand
- JWT tokens signed with configurable algorithms (HS256/RS256/etc)
- Security headers middleware
- **Client secret hashing with bcrypt** (cost factor 12)
- **Client secret rotation API** via PUT `/api/v1/auth/oauth/clients/{client_id}/secret`
- Audit trail tracking (created_by field for all clients)

### Testing Strategy

- Unit tests for individual components
- Integration tests using testcontainers for Redis
- Comprehensive coverage reporting
- Security scanning with gosec
- Performance benchmarking

### Key Dependencies

- PostgreSQL for persistent user data storage (with pgx driver for connection pooling)
- **MySQL for OAuth2 client credentials storage** (with go-sql-driver/mysql)
- Redis for session/token storage and client caching (with in-memory fallback)
- JWT tokens using golang-jwt/jwt library
- Gorilla Mux for routing
- Prometheus metrics integration
- Structured logging with logrus
- testcontainers for integration testing
- **bcrypt for secure client secret hashing** (golang.org/x/crypto/bcrypt)

### Development Notes

- Uses Go 1.23+ with modules
- Graceful shutdown support with proper database connection cleanup
- Health checks with degraded status support:
  - **healthy**: Redis + PostgreSQL + MySQL all available
  - **degraded**: Redis available, but PostgreSQL or MySQL unavailable (200 status for k8s deployment)
  - **unhealthy**: Redis unavailable (503 status)
- Prometheus metrics at `/api/v1/auth/metrics`
- Sample client automatically created for testing (when `CLIENT_AUTO_REGISTER_CREATE_SAMPLE_CLIENT=true`)
- **Hybrid client storage architecture:**
  - MySQL as primary source of truth for OAuth2 clients
  - Redis cache layer for performance (cache-aside pattern)
  - Graceful fallback to Redis-only mode if MySQL unavailable
  - Client secrets hashed with bcrypt before storage (never stored plaintext)
- Database-first user storage with Redis caching for performance
- Background database health monitoring with automatic reconnection
- Service startup independent of database availability (graceful degradation)
- Docker multi-stage builds for production
- Kubernetes manifests in `k8s/` directory
- All API routes prefixed with `/api/v1/auth`

### OAuth2 Flows Supported

- **Authorization Code Flow with PKCE** - For web/mobile clients (PKCE is required by default)
- **Client Credentials Flow** - For service-to-service authentication
- **Refresh Token Flow** - Token renewal with rotation support
- **Token Introspection** (RFC 7662) - Token validation endpoint
- **Token Revocation** (RFC 7009) - Secure token invalidation
- **OpenID Connect UserInfo** - User profile endpoint
