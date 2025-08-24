# OAuth2 Authentication Service

[![CI](https://github.com/your-org/oauth2-auth-service/workflows/CI/badge.svg)](https://github.com/your-org/oauth2-auth-service/actions)
[![Security](https://github.com/your-org/oauth2-auth-service/workflows/Security/badge.svg)](https://github.com/your-org/oauth2-auth-service/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/your-org/oauth2-auth-service)](https://goreportcard.com/report/github.com/your-org/oauth2-auth-service)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade OAuth2 authentication service built in Go, supporting Authorization Code Flow with
PKCE and Client Credentials Flow for secure microservices authentication.

## 🚀 Features

- **OAuth2 Compliance**: Full support for Authorization Code Flow with PKCE and Client Credentials Flow
- **JWT Access Tokens**: Signed with RS256, configurable expiration
- **Opaque Refresh Tokens**: Secure, cryptographically random refresh tokens with rotation
- **Redis Integration**: Session management, rate limiting, and token storage
- **Security First**: Rate limiting, CORS, security headers, input validation
- **Production Ready**: Health checks, metrics, graceful shutdown, Docker support
- **Comprehensive Testing**: Unit tests, integration tests with testcontainers
- **Enterprise Infrastructure**: Pre-commit hooks, CI/CD, security scanning

## 📋 Table of Contents

- [🏃 Quick Start](#-quick-start)
- [🔐 OAuth2 Flows](#-oauth2-flows)
- [🛠 API Endpoints](#-api-endpoints)
- [⚙️ Configuration](#️-configuration)
- [🧪 Development](#-development)
- [🚢 Deployment](#-deployment)
- [📚 Documentation](#-documentation)
- [🤝 Contributing](#-contributing)

## 🏃 Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- Redis (or use Docker)

### Local Development

1. **Clone and setup:**

   ```bash
   git clone https://github.com/your-org/oauth2-auth-service.git
   cd oauth2-auth-service
   cp .env.example .env.local
   ```

2. **Start dependencies:**

   ```bash
   docker run -d --name redis -p 6379:6379 redis:7-alpine
   ```

3. **Run the service:**

   ```bash
   make run
   ```

### Docker Compose

```bash
docker-compose up -d
```

### Verify Installation

```bash
curl http://localhost:8080/health
```

## 🔐 OAuth2 Flows

### Authorization Code Flow with PKCE

For web applications and SPAs:

```bash
# 1. Generate PKCE parameters
code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
code_challenge=$(echo -n $code_verifier | shasum -a 256 | cut -d " " -f1 | xxd -r -p | base64 | tr -d "=+/" | cut -c1-43)

# 2. Authorization URL
https://auth.example.com/oauth2/authorize?response_type=code&client_id=your-client&redirect_uri=https://yourapp.com/callback&code_challenge=$code_challenge&code_challenge_method=S256

# 3. Exchange code for tokens
curl -X POST https://auth.example.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://yourapp.com/callback&client_id=your-client&code_verifier=$code_verifier"
```

### Client Credentials Flow

For service-to-service authentication:

```bash
curl -X POST https://auth.example.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d "grant_type=client_credentials&scope=read write"
```

## 🛠 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/authorize` | GET | Authorization endpoint (PKCE flow) |
| `/oauth2/token` | POST | Token endpoint (all flows) |
| `/oauth2/introspect` | POST | Token introspection |
| `/oauth2/revoke` | POST | Token revocation |
| `/oauth2/userinfo` | GET | User information |
| `/health` | GET | Health check |
| `/health/ready` | GET | Readiness probe |
| `/metrics` | GET | Prometheus metrics |

See [API Reference](docs/API_REFERENCE.md) for detailed documentation.

## ⚙️ Configuration

Configuration via environment variables:

```bash
# Server
SERVER_ADDRESS=0.0.0.0:8080

# Redis
REDIS_ADDRESS=localhost:6379
REDIS_PASSWORD=""

# JWT
JWT_SECRET_KEY=your-256-bit-secret-key
JWT_ISSUER=https://auth.example.com
JWT_ACCESS_TOKEN_EXPIRY=15m

# Security
SECURITY_RATE_LIMIT_REQUESTS=100
SECURITY_CORS_ALLOWED_ORIGINS=https://example.com

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

Create `.env.local` from the example file:

```bash
cp .env.example .env.local
```

See [.env.example](.env.example) for all configuration options.

## 🧪 Development

### Make Commands

```bash
make build          # Build the application
make run             # Run locally
make test            # Run all tests
make test-unit       # Unit tests only
make test-integration # Integration tests only
make lint            # Run linting
make fmt             # Format code
make coverage        # Generate coverage report
make docker-build    # Build Docker image
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Integration tests with testcontainers
make test-integration
```

See [Development Guide](docs/DEVELOPMENT.md) for detailed development workflow.

## 🚢 Deployment

### Docker

```bash
# Build image
docker build -t oauth2-auth-service .

# Run container
docker run -d \
  --name oauth2-auth \
  -p 8080:8080 \
  --env-file .env.local \
  oauth2-auth-service
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f config/
```

### Monitoring

- **Health Checks**: `/health` and `/health/ready`
- **Metrics**: Prometheus metrics at `/metrics`
- **Logging**: Structured JSON logs

See [Deployment Guide](docs/DEPLOYMENT.md) for production deployment.

## 📚 Documentation

- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[Architecture Overview](docs/ARCHITECTURE.md)** - System design and components
- **[Development Guide](docs/DEVELOPMENT.md)** - Development workflow and testing
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[OpenAPI Specification](api/openapi.yaml)** - Machine-readable API spec

## 🔒 Security

- **PKCE Enforcement**: Required for Authorization Code Flow
- **Rate Limiting**: Configurable per-IP and per-client limits
- **Input Validation**: All requests validated and sanitized
- **Secure Tokens**: Cryptographically secure token generation
- **Security Headers**: CORS, CSP, and other security headers
- **Audit Logging**: Security events and authentication attempts

## 📊 Monitoring

### Metrics

The service exposes Prometheus metrics:

- HTTP request metrics (rate, duration, status codes)
- OAuth2 business metrics (token issuance, validation)
- Redis connection health and performance
- Rate limiting metrics

### Health Checks

- **Liveness**: `/health` - Overall service health
- **Readiness**: `/health/ready` - Ready to serve traffic

## 🏗 Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Client    │    │  Mobile Client  │    │  Backend Service│
│  (PKCE Flow)    │    │  (PKCE Flow)    │    │ (Client Creds)  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  OAuth2 Auth Service    │
                    │                         │
                    │  ┌─────────────────┐    │
                    │  │   HTTP Layer    │    │
                    │  ├─────────────────┤    │
                    │  │ Business Logic  │    │
                    │  ├─────────────────┤    │
                    │  │ Infrastructure  │    │
                    │  └─────────────────┘    │
                    └────────────┬────────────┘
                                 │
                      ┌──────────▼──────────┐
                      │       Redis         │
                      │ (Sessions, Tokens,  │
                      │  Rate Limiting)     │
                      └─────────────────────┘
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

See [Development Guide](docs/DEVELOPMENT.md) for detailed setup instructions.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/oauth2-auth-service/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/oauth2-auth-service/discussions)
- **Documentation**: [docs/](docs/)

## 🏷️ Version

Current version: **1.0.0**

See [CHANGELOG.md](CHANGELOG.md) for release history.
