# OAuth2 Authentication Service

[![CI](https://github.com/your-org/oauth2-auth-service/workflows/CI/badge.svg)](https://github.com/your-org/oauth2-auth-service/actions)
[![Security](https://github.com/your-org/oauth2-auth-service/workflows/Security/badge.svg)](https://github.com/your-org/oauth2-auth-service/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/your-org/oauth2-auth-service)](https://goreportcard.com/report/github.com/your-org/oauth2-auth-service)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade OAuth2 authentication service built in Go, supporting Authorization Code Flow with
PKCE and Client Credentials Flow for secure microservices authentication.

## 🚀 Features

### 🔐 Complete OAuth2 Implementation

- **Authorization Code Flow with PKCE** (RFC 7636) - Secure flow for web and mobile clients
- **Client Credentials Flow** - Service-to-service authentication
- **Refresh Token Flow** - Token renewal with rotation support
- **Token Introspection** (RFC 7662) - Token validation endpoint
- **Token Revocation** (RFC 7009) - Secure token invalidation
- **OpenID Connect UserInfo** - User profile endpoint

### 🛡️ Enterprise Security

- **PKCE Enforcement** - Required for Authorization Code Flow
- **JWT Access Tokens** - Cryptographically signed with configurable algorithms
- **Opaque Refresh Tokens** - Secure random generation with blacklisting
- **Rate Limiting** - Per-IP and per-client protection
- **CORS Protection** - Configurable cross-origin policies
- **Security Headers** - CSP, HSTS, and other protective headers
- **Input Validation** - Comprehensive request sanitization

### 🏗️ Production Infrastructure

- **Redis Storage** - Session management with in-memory fallback
- **Health Monitoring** - Liveness and readiness probes
- **Prometheus Metrics** - Comprehensive observability
- **Structured Logging** - JSON logs with correlation IDs
- **Graceful Shutdown** - Clean service termination
- **Auto-scaling** - Kubernetes HPA support

### 🔧 Client Management

- **Dynamic Registration** - Runtime client creation via API
- **Batch Registration** - Auto-registration from config files
- **CLI Management Tool** - Command-line client administration
- **Discovery Endpoint** - OAuth2 authorization server metadata

### 📦 Deployment Ready

- **Docker Support** - Multi-stage builds for production
- **Kubernetes Manifests** - Complete K8s deployment specs
- **Automation Scripts** - Deploy, update, and monitor services
- **Environment Configuration** - Flexible config via environment variables

## 📋 Table of Contents

- [🏃 Quick Start](#-quick-start)
- [✅ Implementation Status](#-implementation-status)
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

### Docker Compose (Production)

```bash
# Production setup with Redis
docker-compose up -d

# Development setup with hot reload
docker-compose -f docker-compose.dev.yml up -d
```

### Kubernetes (Production)

```bash
# Quick deployment to Minikube
./scripts/containerManagement/deploy-container.sh

# Manual deployment
kubectl apply -f k8s/namespace.yaml
envsubst < k8s/configmap-template.yaml | kubectl apply -f -
envsubst < k8s/secret-template.yaml | kubectl apply -f -
kubectl apply -f k8s/
```

### Verify Installation

```bash
# Local/Docker
curl http://localhost:8080/api/v1/auth/health

# Kubernetes
curl http://auth-service.local/api/v1/auth/health
```

## ✅ Implementation Status

### 🎉 This OAuth2 authentication service is FEATURE COMPLETE and PRODUCTION READY! 🎉

### Core OAuth2 Specification Compliance

| OAuth2/OIDC Feature | RFC | Implementation | Status |
|---------------------|-----|----------------|--------|
| **Authorization Code Flow** | RFC 6749 | Full implementation with user consent | ✅ |
| **PKCE Extension** | RFC 7636 | Required for Authorization Code Flow | ✅ |
| **Client Credentials Flow** | RFC 6749 | Service-to-service authentication | ✅ |
| **Refresh Token Flow** | RFC 6749 | Token renewal with rotation | ✅ |
| **Token Introspection** | RFC 7662 | Token validation endpoint | ✅ |
| **Token Revocation** | RFC 7009 | Secure token invalidation | ✅ |
| **Authorization Server Metadata** | RFC 8414 | Discovery endpoint | ✅ |
| **OpenID Connect UserInfo** | OIDC Core | User profile endpoint | ✅ |

### Infrastructure & Production Readiness

| Component | Feature | Status |
|-----------|---------|--------|
| **Storage** | Redis with in-memory fallback | ✅ |
| **Security** | Rate limiting, CORS, security headers | ✅ |
| **Monitoring** | Health checks, Prometheus metrics | ✅ |
| **Logging** | Structured JSON logs with correlation IDs | ✅ |
| **Configuration** | Environment-based with validation | ✅ |
| **Deployment** | Docker, Kubernetes, automation scripts | ✅ |
| **Client Management** | Dynamic registration, CLI tools | ✅ |
| **Documentation** | API docs, OpenAPI spec, deployment guides | ✅ |

### Security Implementation

| Security Control | Implementation | Status |
|------------------|----------------|--------|
| **Authentication** | JWT access tokens, opaque refresh tokens | ✅ |
| **Authorization** | Scope-based access control | ✅ |
| **PKCE** | Code challenge validation | ✅ |
| **Token Security** | Blacklisting, expiry, rotation | ✅ |
| **Transport Security** | TLS/HTTPS support | ✅ |
| **Input Validation** | Comprehensive request sanitization | ✅ |
| **Rate Protection** | Per-client and per-IP limiting | ✅ |
| **CORS** | Configurable cross-origin policies | ✅ |

**🚀 No additional implementation work needed - ready for production deployment!**

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

### OAuth2 & OpenID Connect

| Endpoint | Method | Description | Status |
|----------|--------|-------------|--------|
| `/api/v1/auth/oauth2/authorize` | GET/POST | Authorization endpoint (PKCE flow) | ✅ |
| `/api/v1/auth/oauth2/token` | POST | Token endpoint (all flows) | ✅ |
| `/api/v1/auth/oauth2/introspect` | POST | Token introspection (RFC 7662) | ✅ |
| `/api/v1/auth/oauth2/revoke` | POST | Token revocation (RFC 7009) | ✅ |
| `/api/v1/auth/oauth2/userinfo` | GET/POST | OpenID Connect UserInfo | ✅ |
| `/api/v1/auth/.well-known/oauth-authorization-server` | GET | OAuth2 discovery metadata | ✅ |

### Client Management

| Endpoint | Method | Description | Status |
|----------|--------|-------------|--------|
| `/api/v1/auth/oauth/clients` | POST | Register new OAuth2 client | ✅ |
| `/api/v1/auth/oauth/clients/{id}` | GET | Get client information | ✅ |

### Monitoring & Health

| Endpoint | Method | Description | Status |
|----------|--------|-------------|--------|
| `/api/v1/auth/health` | GET | Overall health check | ✅ |
| `/api/v1/auth/health/ready` | GET | Readiness probe | ✅ |
| `/api/v1/auth/health/live` | GET | Liveness probe | ✅ |
| `/api/v1/auth/metrics` | GET | Prometheus metrics | ✅ |

**Legend**: ✅ Implemented and Production Ready

See [API Reference](docs/API_REFERENCE.md) for detailed documentation and examples.

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
docker build -t auth-service .

# Run container
docker run -d \
  --name auth-service \
  -p 8080:8080 \
  --env-file .env.local \
  auth-service
```

### Docker Compose

```bash
# Production deployment
docker-compose up -d

# Development deployment
docker-compose -f docker-compose.dev.yml up -d
```

### Kubernetes

```bash
# Complete automated deployment
./scripts/containerManagement/deploy-container.sh

# Check deployment status
./scripts/containerManagement/get-container-status.sh

# Update running service
./scripts/containerManagement/update-container.sh
```

### Management Scripts

- **deploy-container.sh** - Complete deployment automation
- **start-container.sh** - Start/scale up service
- **stop-container.sh** - Stop/scale down service
- **update-container.sh** - Rolling updates
- **get-container-status.sh** - Status monitoring
- **cleanup-container.sh** - Complete cleanup

### Monitoring

- **Health Checks**: `/health`, `/health/ready`, `/health/live`
- **Metrics**: Prometheus metrics at `/metrics`
- **Logging**: Structured JSON logs
- **Auto-scaling**: HPA with CPU/memory targets (2-10 replicas)

See [Deployment Guide](docs/DEPLOYMENT.md) and [k8s/README.md](k8s/README.md) for detailed deployment instructions.

## 📚 Documentation

- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[Architecture Overview](docs/ARCHITECTURE.md)** - System design and components
- **[Development Guide](docs/DEVELOPMENT.md)** - Development workflow and testing
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[Kubernetes Deployment](k8s/README.md)** - Kubernetes manifests and configuration
- **[Management Scripts](scripts/containerManagement/README.md)** - Container management automation
- **[OpenAPI Specification](api/openapi.yaml)** - Machine-readable API spec

## 🔒 Security Features

### ✅ Implemented Security Controls

| Security Feature | Implementation | Status |
|------------------|----------------|--------|
| **PKCE (RFC 7636)** | Required for Authorization Code Flow | ✅ |
| **Token Blacklisting** | Revoked tokens tracked in Redis | ✅ |
| **Rate Limiting** | Per-IP and per-client limits | ✅ |
| **CORS Protection** | Configurable cross-origin policies | ✅ |
| **Security Headers** | CSP, HSTS, X-Frame-Options, etc. | ✅ |
| **Input Validation** | All requests validated and sanitized | ✅ |
| **JWT Signing** | Configurable algorithms (HS256, RS256, etc.) | ✅ |
| **Secure Random** | Cryptographically secure token generation | ✅ |
| **TLS Support** | HTTPS with configurable certificates | ✅ |
| **Audit Logging** | Security events and authentication attempts | ✅ |

### Security Best Practices

- **No client secrets in logs** - Sensitive data excluded from logging
- **Token expiry enforcement** - All tokens have configurable expiration
- **Refresh token rotation** - Enhanced security for long-lived tokens
- **Authorization validation** - Scope and client permission checks
- **Path traversal protection** - Config file access validation
- **Redis connection security** - Password authentication and TLS support

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
