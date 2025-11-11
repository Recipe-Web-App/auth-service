# Contributing to OAuth2 Auth Service

Thank you for your interest in contributing! This comprehensive guide covers everything you need to know about
developing, testing, and contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Code Organization](#code-organization)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Debugging](#debugging)
- [Performance Testing](#performance-testing)
- [API Development](#api-development)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Troubleshooting](#troubleshooting)
- [Security](#security)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report
unacceptable behavior through the project's issue tracker.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/auth-service.git
   cd auth-service
   ```

3. **Add upstream remote**:

   ```bash
   git remote add upstream https://github.com/Recipe-Web-App/auth-service.git
   ```

## Development Setup

### Prerequisites

- Go 1.23 or higher
- Docker and Docker Compose
- PostgreSQL 14+ (for local development)
- Redis 7+ (for local development)
- Make

### Initial Setup

1. **Install dependencies**:

   ```bash
   make deps
   make tools
   ```

2. **Set up environment**:

   ```bash
   cp .env.example .env.local
   # Edit .env.local with your local configuration
   ```

3. **Start development environment**:

   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

4. **Run the service**:

   ```bash
   make dev  # Run with hot reload
   # OR
   make run  # Run without hot reload
   ```

## Development Workflow

### Docker Development

For containerized development with hot reload:

```bash
# Start development environment
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
- Automatic Redis and PostgreSQL setup
- Hot reload for code changes
- Isolated development environment
- Easy cleanup and reset

### Git Workflow

1. **Create a feature branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the code style guidelines

3. **Run tests frequently**:

   ```bash
   make test
   ```

4. **Commit your changes** following commit guidelines

5. **Keep your branch updated**:

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

6. **Push to your fork**:

   ```bash
   git push origin feature/your-feature-name
   ```

## Code Organization

Understanding the project structure helps you navigate and contribute effectively:

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
│   ├── database/       # PostgreSQL connection management
│   ├── repository/     # User data repository
│   ├── redis/          # Redis client
│   └── token/          # Token services
├── pkg/                # Public library code
│   └── logger/         # Logging utilities
├── test/               # Test files
│   └── integration/    # Integration tests
├── docs/               # Documentation
├── k8s/                # Kubernetes manifests
└── scripts/            # Automation scripts
```

### Package Responsibilities

- `cmd/` - Application entry points with dependency injection
- `internal/` - Private application code (not importable by other projects)
- `pkg/` - Public library code (reusable components)
- `internal/handlers/` - HTTP request handlers
- `internal/auth/` - OAuth2 business logic and user services
- `internal/repository/` - Data access layer
- `internal/database/postgres/` - PostgreSQL connection management with health monitoring
- `internal/redis/` - Redis client with fallback memory store

## Testing

### Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# With coverage
make test-coverage

# Benchmarks
make benchmark
```

### Writing Tests

- Write unit tests for all new functionality
- Integration tests for OAuth2 flows and database interactions
- Use testcontainers for integration tests requiring Redis
- Aim for >80% code coverage
- Test edge cases and error conditions

### Test Guidelines

- Table-driven tests are preferred
- Use descriptive test names: `TestFunctionName_Scenario_ExpectedBehavior`
- Mock external dependencies
- Clean up resources in test teardown

### Unit Test Example

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

### Integration Test Example

Integration tests use testcontainers for real dependencies:

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

### Go Code Standards

```bash
# Format code
make fmt

# Run linter
make lint

# Run static analysis
make vet

# Run security checks
make security

# Run all checks
make check
```

### Style Guidelines

- Follow standard Go conventions
- Use meaningful variable and function names
- Keep functions small and focused
- Document exported functions and types
- Add comments for complex logic
- Use error wrapping with context

### Package Organization

- `cmd/` - Application entry points
- `internal/` - Private application code
- `pkg/` - Public library code
- `internal/handlers/` - HTTP handlers
- `internal/auth/` - Business logic
- `internal/repository/` - Data access

### Linting Configuration

The project uses golangci-lint with comprehensive checks:

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

Install and use pre-commit hooks for automatic code quality checks:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install
```

The project uses these hooks (`.pre-commit-config.yaml`):

```yaml
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

### Load Testing

Use `hey` for load testing:

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

## Commit Guidelines

### Commit Message Format

```text
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes
- `security`: Security fixes
- `deps`: Dependency updates

### Examples

```text
feat(oauth2): add support for refresh token rotation

Implements RFC 6749 refresh token rotation for enhanced security.
Tokens are automatically rotated on each refresh request.

Fixes #123
```

```text
fix(token): prevent race condition in token validation

Added mutex to protect concurrent access to token cache.

Fixes #456
```

## Pull Request Process

### Before Submitting

1. **Run all checks**:

   ```bash
   make check
   make test
   ```

2. **Update documentation** if needed:
   - README.md
   - CLAUDE.md
   - API documentation
   - Code comments

3. **Ensure no secrets** are committed:
   - Check for API keys, tokens, passwords
   - Review `.env` files
   - Use `.gitignore` appropriately

### PR Requirements

- [ ] Clear description of changes
- [ ] Related issue linked
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] All CI checks passing
- [ ] No merge conflicts
- [ ] Commits follow convention
- [ ] No sensitive data committed

### PR Template

The project uses a PR template. Fill it out completely:

- Description of changes
- Type of change
- Security implications
- Breaking changes
- Testing performed
- Configuration changes

### Review Process

1. Maintainers will review your PR
2. Address feedback and requested changes
3. Keep PR updated with main branch
4. Once approved, maintainer will merge

### CI/CD Pipeline

PRs must pass:

- Go build
- Unit tests
- Integration tests
- Linting (golangci-lint)
- Security scanning (gosec)
- Code formatting checks

## Troubleshooting

### Common Development Issues

**1. Redis Connection Issues:**

```bash
# Check Redis is running
docker ps | grep redis

# Test connection
redis-cli -h localhost -p 6379 ping
```

**2. PostgreSQL Connection Issues:**

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
psql -h localhost -p 5432 -U auth_user -d recipe_manager
```

**3. Port Already in Use:**

```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>
```

**4. Module Dependencies:**

```bash
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download
```

**5. Test Failures:**

```bash
# Run with verbose output
go test -v ./internal/...

# Run specific test
go test -v -run TestSpecificFunction ./internal/package/
```

**6. Docker Build Issues:**

```bash
# Clean Docker build cache
docker builder prune

# Rebuild without cache
docker build --no-cache -t auth-service .
```

**7. Kubernetes Deployment Issues:**

```bash
# Check pod status
kubectl get pods -n auth-service

# View pod logs
kubectl logs -n auth-service <pod-name>

# Describe pod for events
kubectl describe pod -n auth-service <pod-name>
```

### Getting Help

- Check the [README](../README.md) for feature documentation
- Review [ARCHITECTURE](../docs/ARCHITECTURE.md) for system design
- Consult [DEPLOYMENT](../docs/DEPLOYMENT.md) for operational issues
- See [API_REFERENCE](../docs/API_REFERENCE.md) for endpoint documentation
- Open an issue on the project repository
- Start a discussion in GitHub Discussions

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Use [GitHub Security Advisories](https://github.com/Recipe-Web-App/auth-service/security/advisories/new) to
report security issues privately.

### Security Guidelines

- Never commit secrets or credentials
- Follow OAuth2 security best practices
- Validate all inputs
- Use parameterized queries
- Enable PKCE for authorization code flow
- Use secure random generation for tokens
- Implement proper rate limiting

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

## Questions?

- Check the [README](../README.md)
- Review existing [issues](https://github.com/Recipe-Web-App/auth-service/issues)
- Start a [discussion](https://github.com/Recipe-Web-App/auth-service/discussions)
- See [SUPPORT.md](SUPPORT.md) for help resources

Thank you for contributing!
