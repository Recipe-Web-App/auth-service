# Development Guide

## Getting Started

### Prerequisites

- **Go 1.23+** - [Download](https://golang.org/dl/)
- **Docker** - [Install Docker](https://docs.docker.com/get-docker/)
- **Redis** - Via Docker or [native installation](https://redis.io/download)
- **Git** - [Install Git](https://git-scm.com/downloads)
- **Make** - Usually pre-installed on Unix systems

### Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-org/oauth2-auth-service.git
   cd oauth2-auth-service
   ```

2. **Install dependencies:**

   ```bash
   go mod download
   ```

3. **Set up environment:**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start development environment:**

   Choose one of the following options:

   **Option A: Docker Compose (Recommended)**

   ```bash
   # Start full development environment
   docker-compose -f docker-compose.dev.yml up -d
   ```

   **Option B: Local Redis**

   ```bash
   docker run -d --name redis -p 6379:6379 redis:7-alpine
   ```

5. **Install development tools:**

   ```bash
   # Install pre-commit hooks
   pre-commit install

   # Install additional tools
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   go install golang.org/x/tools/cmd/goimports@latest
   ```

## Development Workflow

### Code Organization

```text
auth-service/
├── cmd/
│   └── server/          # Application entry points
├── internal/            # Private application code
│   ├── auth/           # OAuth2 business logic
│   ├── config/         # Configuration management
│   ├── handlers/       # HTTP handlers
│   ├── middleware/     # HTTP middleware
│   ├── models/         # Data models
│   ├── redis/          # Redis client
│   └── token/          # Token services
├── pkg/                # Public library code
│   └── logger/         # Logging utilities
├── test/               # Test files
│   └── integration/    # Integration tests
├── api/                # API specifications
├── docs/               # Documentation
└── config/             # Deployment configurations
```

### Make Targets

The project includes a comprehensive Makefile:

```bash
# Build the application
make build

# Run the application
make run

# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration

# Run linting
make lint

# Format code
make fmt

# Clean build artifacts
make clean

# Generate code coverage
make coverage

# Build Docker image
make docker-build

# Run security checks
make security

# Show help
make help

# Docker Compose commands
docker-compose -f docker-compose.dev.yml up -d    # Start dev environment
docker-compose -f docker-compose.dev.yml logs -f  # View logs
docker-compose -f docker-compose.dev.yml down     # Stop dev environment
```

### Environment Variables

Create a `.env` file for local development:

```bash
# Server
SERVER_ADDRESS=localhost:8080
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s
SERVER_IDLE_TIMEOUT=120s

# Redis
REDIS_ADDRESS=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_MAX_RETRIES=3
REDIS_POOL_SIZE=10

# JWT
JWT_SECRET_KEY=your-development-secret-key-minimum-256-bits
JWT_ISSUER=http://localhost:8080
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=24h

# OAuth2
OAUTH2_AUTHORIZATION_CODE_EXPIRY=10m

# Security
SECURITY_RATE_LIMIT_REQUESTS=100
SECURITY_RATE_LIMIT_WINDOW=1m
SECURITY_CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
SECURITY_CORS_ALLOWED_METHODS=GET,POST,OPTIONS
SECURITY_CORS_ALLOWED_HEADERS=Content-Type,Authorization
SECURITY_CORS_ALLOW_CREDENTIALS=true

# Logging
LOG_LEVEL=debug
LOG_FORMAT=json
```

### Docker Development Workflow

For containerized development, use Docker Compose:

```bash
# Start development environment with hot reload
docker-compose -f docker-compose.dev.yml up -d

# View application logs
docker-compose -f docker-compose.dev.yml logs -f auth-service

# View all service logs
docker-compose -f docker-compose.dev.yml logs -f

# Execute commands in the container
docker-compose -f docker-compose.dev.yml exec auth-service go test ./...

# Rebuild and restart after Go module changes
docker-compose -f docker-compose.dev.yml build auth-service
docker-compose -f docker-compose.dev.yml restart auth-service

# Stop development environment
docker-compose -f docker-compose.dev.yml down
```

**Benefits of Docker Development:**

- Consistent environment across team members
- Automatic Redis setup and management
- Hot reload for code changes
- Isolated development environment
- Easy cleanup and reset

## Testing Strategy

### Unit Tests

Unit tests focus on individual functions and methods:

```bash
# Run unit tests
make test-unit

# Run with coverage
go test -coverprofile=coverage.out ./internal/...
go tool cover -html=coverage.out
```

**Writing Unit Tests:**

```go
func TestJWTService_GenerateToken(t *testing.T) {
    config := &config.Config{
        JWT: config.JWTConfig{
            SecretKey:           "test-secret-key-256-bits-minimum-length", // pragma: allowlist secret
            Issuer:             "test-issuer",
            AccessTokenExpiry:  15 * time.Minute,
            RefreshTokenExpiry: 24 * time.Hour,
        },
    }

    service := token.NewJWTService(config)

    claims := models.TokenClaims{
        Subject:  "test-user",
        ClientID: "test-client",
        Scope:    "read write",
    }

    tokenString, err := service.GenerateAccessToken(claims)
    assert.NoError(t, err)
    assert.NotEmpty(t, tokenString)

    // Validate token
    parsedClaims, err := service.ValidateAccessToken(tokenString)
    assert.NoError(t, err)
    assert.Equal(t, claims.Subject, parsedClaims.Subject)
}
```

### Integration Tests

Integration tests use testcontainers to test with real dependencies:

```bash
# Run integration tests
make test-integration

# Run with verbose output
go test -v ./test/integration/...
```

**Writing Integration Tests:**

```go
func TestRedisClient_Integration(t *testing.T) {
    ctx := context.Background()

    // Start Redis container
    redisContainer, err := redis.RunContainer(ctx,
        testcontainers.WithImage("redis:7-alpine"),
    )
    require.NoError(t, err)
    defer redisContainer.Terminate(ctx)

    // Get connection details
    host, _ := redisContainer.Host(ctx)
    port, _ := redisContainer.MappedPort(ctx, "6379")

    // Test Redis operations
    client := redis.NewClient(&config.Config{
        Redis: config.RedisConfig{
            Address: fmt.Sprintf("%s:%s", host, port.Port()),
        },
    })

    // Test client operations
    testClient := &models.Client{
        ID:     "test-client",
        Secret: "test-secret", // pragma: allowlist secret
    }

    err = client.SaveClient(ctx, testClient)
    assert.NoError(t, err)

    retrievedClient, err := client.GetClient(ctx, "test-client")
    assert.NoError(t, err)
    assert.Equal(t, testClient.ID, retrievedClient.ID)
}
```

## Code Quality

### Linting Configuration

The project uses golangci-lint with comprehensive configuration:

```yaml
# .golangci.yml
run:
  timeout: 5m
  tests: true

linters:
  enable:
    - gosec       # Security issues
    - govet       # Go vet
    - ineffassign # Ineffectual assignments
    - misspell    # Spelling mistakes
    - gofmt       # Formatting
    - goimports   # Import formatting
    - gocritic    # Code critique
    - revive      # Replacement for golint
    - staticcheck # Static analysis
    - unused      # Unused code
    - errcheck    # Unchecked errors

linters-settings:
  gosec:
    severity: medium
  govet:
    check-shadowing: true
  revive:
    rules:
      - name: exported
        severity: warning
```

### Pre-commit Hooks

The project uses pre-commit hooks for code quality:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: go-fmt
        name: go fmt
        entry: gofmt
        language: system
        args: [-w, -s]
        files: \.go$

      - id: go-imports
        name: go imports
        entry: goimports
        language: system
        args: [-w]
        files: \.go$

      - id: golangci-lint
        name: golangci-lint
        entry: golangci-lint
        language: system
        args: [run, --fix]
        files: \.go$
        pass_filenames: false

      - id: go-sec
        name: go security check
        entry: gosec
        language: system
        args: [-quiet, ./...]
        files: \.go$
        pass_filenames: false
```

## Debugging

### Local Debugging

**VS Code Configuration (.vscode/launch.json):**

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch OAuth2 Service",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "./cmd/server",
      "env": {
        "SERVER_ADDRESS": "localhost:8080",
        "REDIS_ADDRESS": "localhost:6379",
        "LOG_LEVEL": "debug"
      },
      "args": []
    }
  ]
}
```

**Using Delve Debugger:**

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug the application
dlv debug ./cmd/server

# Set breakpoint and run
(dlv) b main.main
(dlv) c
```

### Logging and Observability

**Structured Logging:**

```go
import "github.com/sirupsen/logrus"

logger := logrus.WithFields(logrus.Fields{
    "client_id": clientID,
    "user_id":   userID,
    "action":    "token_generation",
})

logger.Info("Access token generated successfully")
logger.WithError(err).Error("Failed to generate token")
```

**Metrics Collection:**

```go
// Define metrics
var (
    tokenRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "oauth2_token_requests_total",
            Help: "Total number of token requests",
        },
        []string{"grant_type", "status"},
    )
)

// Record metrics
tokenRequests.WithLabelValues("authorization_code", "success").Inc()
```

## Performance Testing

### Load Testing with hey

```bash
# Install hey
go install github.com/rakyll/hey@latest

# Load test token endpoint
hey -n 1000 -c 10 -m POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test&client_secret=test" \
  http://localhost:8080/oauth2/token
```

### Benchmarking

**Writing Benchmarks:**

```go
func BenchmarkJWTGeneration(b *testing.B) {
    config := &config.Config{
        JWT: config.JWTConfig{
            SecretKey: "test-secret-key-256-bits-minimum-length", // pragma: allowlist secret
        },
    }

    service := token.NewJWTService(config)
    claims := models.TokenClaims{
        Subject:  "test-user",
        ClientID: "test-client",
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.GenerateAccessToken(claims)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

**Running Benchmarks:**

```bash
# Run all benchmarks
go test -bench=. ./internal/...

# Run specific benchmark
go test -bench=BenchmarkJWTGeneration ./internal/token/

# With memory allocation stats
go test -bench=. -benchmem ./internal/...
```

## API Development

### Adding New Endpoints

1. **Define the model** in `internal/models/`:

   ```go
   type NewRequest struct {
       Field string `json:"field" validate:"required"`
   }
   ```

2. **Add business logic** in appropriate service:

   ```go
   func (s *Service) HandleNewRequest(ctx context.Context, req *models.NewRequest) error {
       // Implementation
   }
   ```

3. **Create HTTP handler** in `internal/handlers/`:

   ```go
   func (h *Handler) NewEndpoint(w http.ResponseWriter, r *http.Request) {
       // Handler implementation
   }
   ```

4. **Register route** in main router setup
5. **Add tests** for the new functionality
6. **Update API documentation**

### Database Migrations

For Redis schema changes:

```go
// internal/redis/migrations.go
func (c *Client) MigrateSchema(ctx context.Context) error {
    // Check current version
    version, err := c.GetSchemaVersion(ctx)
    if err != nil {
        return err
    }

    // Apply migrations
    switch version {
    case 0:
        if err := c.migrateToV1(ctx); err != nil {
            return err
        }
        fallthrough
    case 1:
        if err := c.migrateToV2(ctx); err != nil {
            return err
        }
    }

    return nil
}
```

## Contributing Guidelines

### Git Workflow

1. **Create feature branch:**

   ```bash
   git checkout -b feature/new-endpoint
   ```

2. **Make changes and commit:**

   ```bash
   git add .
   git commit -m "feat: add new endpoint for user management"
   ```

3. **Run tests and linting:**

   ```bash
   make test
   make lint
   ```

4. **Push and create PR:**

   ```bash
   git push origin feature/new-endpoint
   # Create pull request via GitHub/GitLab
   ```

### Commit Message Format

Follow conventional commits:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Test additions or modifications
- `chore:` - Build process or auxiliary tool changes

### Code Review Checklist

- [ ] Code follows project conventions
- [ ] All tests pass
- [ ] Adequate test coverage
- [ ] Documentation updated
- [ ] Security considerations addressed
- [ ] Performance impact considered
- [ ] Backward compatibility maintained

## Security Considerations

### Secure Development Practices

1. **Input Validation:**

   ```go
   if err := validator.Validate(request); err != nil {
       return NewValidationError(err)
   }
   ```

2. **Secret Management:**

   ```go
   // Use environment variables, not hardcoded values
   secretKey := os.Getenv("JWT_SECRET_KEY")
   if secretKey == "" {
       return errors.New("JWT_SECRET_KEY is required")
   }
   ```

3. **Error Handling:**

   ```go
   // Don't leak sensitive information
   if err != nil {
       logger.WithError(err).Error("Database operation failed")
       return errors.New("internal server error")
   }
   ```

### Security Testing

```bash
# Run security checks
make security

# Manual security scan
gosec ./...

# Check for vulnerabilities
go list -json -m all | nancy sleuth
```

## Troubleshooting

### Common Development Issues

**1. Redis Connection Issues:**

```bash
# Check Redis is running
docker ps | grep redis

# Test connection
redis-cli -h localhost -p 6379 ping
```

**2. Port Already in Use:**

```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>
```

**3. Module Dependencies:**

```bash
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download
```

**4. Test Failures:**

```bash
# Run with verbose output
go test -v ./internal/...

# Run specific test
go test -v -run TestSpecificFunction ./internal/package/
```

### Getting Help

- Check the [API Reference](API_REFERENCE.md) for endpoint documentation
- Review [Architecture](ARCHITECTURE.md) for system design
- Consult [Deployment Guide](DEPLOYMENT.md) for operational issues
- Open an issue on the project repository
