# Deployment Guide

## Overview

This service provides multiple deployment options:

1. **Docker Compose** - For development and simple production deployments
2. **Kubernetes** - For production deployments with full automation
3. **Manual Docker** - For custom containerized deployments

## Prerequisites

- Go 1.23+ for local development
- Docker and Docker Compose for containerized deployment
- Kubernetes cluster (or Minikube for local development)
- Redis instance (standalone or cluster)
- kubectl and envsubst (for Kubernetes deployments)

## Environment Configuration

The service uses a **hybrid configuration approach** to separate sensitive connection data from operational settings:

- **Environment Variables** (`.env.local`, `.env.prod`) - Connection data and secrets (never committed)
- **YAML Files** (`configs/*.yaml`) - Operational settings (committed to repository)

### Environment Variables (Connection Data & Secrets)

Environment variables contain **only** connection data and secrets:

```bash
# Environment - determines which YAML config to load (LOCAL, NONPROD, PROD)
ENVIRONMENT=LOCAL

# Server connection
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# JWT Secret (REQUIRED - minimum 32 characters, NEVER commit this)
JWT_SECRET=your-jwt-secret-minimum-32-characters-long

# Redis connection (required)
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=""
REDIS_DB=0

# PostgreSQL connection (optional - for persistent user storage)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=recipe_database
POSTGRES_SCHEMA=recipe_manager
AUTH_DB_USER=auth_user
AUTH_DB_PASSWORD=auth_password

# MySQL connection (optional - for OAuth2 client storage)
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=client_manager
MYSQL_CLIENT_DB_USER=client_db_user
MYSQL_CLIENT_DB_PASSWORD=client_db_password

# Auth service client credentials
AUTH_SERVICE_CLIENT_ID=auth-service-client-id
AUTH_SERVICE_CLIENT_SECRET=auth-service-client-secret
```

### YAML Configuration Files (Operational Settings)

Operational settings are managed in YAML configuration files:

- **`configs/defaults.yaml`** - Base configuration for all environments
- **`configs/local.yaml`** - Local development overrides
- **`configs/nonprod.yaml`** - Non-production environment overrides
- **`configs/prod.yaml`** - Production environment overrides

The `ENVIRONMENT` environment variable determines which YAML file is loaded. The service loads `defaults.yaml`
first, then overlays the environment-specific file.

**Operational settings configured in YAML files:**

- JWT token expiry durations, issuers, and algorithms
- Server timeouts (read, write, idle)
- Database connection pool sizes, timeouts, SSL modes
- Redis connection pool settings and timeouts
- OAuth2 configuration (PKCE enforcement, scopes, authorization code expiry)
- Security settings (rate limits, CORS origins, allowed methods)
- Logging configuration (level, format, dual output support)
- Client auto-registration settings

#### Example: Customizing for production

Edit `configs/prod.yaml` to override defaults for production:

```yaml
server:
  read_timeout: 15s
  write_timeout: 15s

security:
  rate_limit_rps: 1000
  allowed_origins:
    - https://app.example.com
    - https://api.example.com

logging:
  level: warn
  format: json
```

### Development Environment Setup

Create a `.env.local` file from the example:

```bash
cp .env.example .env.local
# Edit .env.local with your connection data and secrets
```

## Local Development

### Using Go Directly

```bash
# Install dependencies
go mod download

# Run tests
make test

# Start the service
make run
```

### Using Docker Compose

```bash
# Production deployment
docker-compose up -d

# Development deployment with hot reload
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down
```

## Production Deployment

### Docker Deployment

#### 1. Build Production Image

```bash
# Build multi-stage Docker image
docker build -t oauth2-auth-service:latest .

# Tag for registry
docker tag oauth2-auth-service:latest your-registry/oauth2-auth-service:v1.0.0

# Push to registry
docker push your-registry/oauth2-auth-service:v1.0.0
```

#### 2. Run with Docker

```bash
docker run -d \
  --name oauth2-auth-service \
  -p 8080:8080 \
  --env-file .env \
  --restart unless-stopped \
  your-registry/oauth2-auth-service:v1.0.0
```

### Kubernetes Deployment

#### Automated Deployment (Recommended)

The service includes comprehensive Kubernetes deployment automation:

```bash
# Set required environment variables
export JWT_SECRET="your-jwt-secret-minimum-32-characters-long" # pragma: allowlist secret
export REDIS_PASSWORD="your-redis-password" # pragma: allowlist secret

# Complete automated deployment
./scripts/containerManagement/deploy-container.sh

# Check deployment status
./scripts/containerManagement/get-container-status.sh

# Update service after code changes
./scripts/containerManagement/update-container.sh
```

#### Manual Deployment

For custom deployments, use the Kubernetes manifests directly:

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Set environment variables and apply configuration
envsubst < k8s/configmap-template.yaml | kubectl apply -f -
envsubst < k8s/secret-template.yaml | kubectl apply -f -

# Deploy all resources
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/horizontalpodautoscaler.yaml
kubectl apply -f k8s/poddisruptionbudget.yaml
kubectl apply -f k8s/networkpolicy.yaml
kubectl apply -f k8s/servicemonitor.yaml

# Check deployment status
kubectl get all -n auth-service
```

#### Production Features

The Kubernetes deployment includes:

- **Auto-scaling**: HPA with CPU/memory targets (2-10 replicas)
- **Security**: Network policies, security contexts, non-root execution
- **Monitoring**: Prometheus metrics, health checks, startup/readiness/liveness probes
- **High Availability**: Pod anti-affinity, disruption budgets
- **Zero-downtime updates**: Rolling deployments with proper configuration

#### Environment Variables

See [k8s/README.md](../k8s/README.md) for complete configuration reference including:

- Server configuration (host, port, timeouts)
- JWT settings (secret, expiry, issuer)
- OAuth2 parameters (PKCE, scopes, grant types)
- Security settings (CORS, rate limiting)
- Redis configuration (connection, pooling)
- Logging configuration (level, format)

#### Management Commands

```bash
# Start service (scale up)
./scripts/containerManagement/start-container.sh

# Stop service (scale down)
./scripts/containerManagement/stop-container.sh

# Complete cleanup
./scripts/containerManagement/cleanup-container.sh
```

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'oauth2-auth-service'
    static_configs:
      - targets: ['oauth2-auth-service:8080']
    metrics_path: '/api/v1/auth/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

Import the provided Grafana dashboard (`config/grafana-dashboard.json`) for comprehensive monitoring.

## Backup and Recovery

### Redis Data Backup

```bash
# Create Redis backup
redis-cli --rdb /backup/redis-backup-$(date +%Y%m%d-%H%M%S).rdb

# Restore from backup
redis-cli --rdb /path/to/backup.rdb
```

### Configuration Backup

```bash
# Backup Kubernetes configs
kubectl get configmap oauth2-auth-config -n auth -o yaml > config-backup.yaml
kubectl get secret oauth2-auth-secrets -n auth -o yaml > secrets-backup.yaml
```

## Performance Tuning

### Redis Configuration

```conf
# redis.conf optimizations
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### Application Tuning

```bash
# Environment variables for production
REDIS_POOL_SIZE=50
REDIS_MAX_RETRIES=5
SERVER_READ_TIMEOUT=15s
SERVER_WRITE_TIMEOUT=15s
SECURITY_RATE_LIMIT_REQUESTS=1000
```

## Security Hardening

### TLS Configuration

```bash
# Generate TLS certificates
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout tls.key -out tls.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=auth.example.com"
```

### Network Security

- Enable TLS for all communications
- Use private container registries
- Implement network policies in Kubernetes
- Regular security scanning of container images

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**

   ```bash
   # Check Redis connectivity
   redis-cli -h redis -p 6379 ping
   ```

2. **High Memory Usage**

   ```bash
   # Monitor Redis memory
   redis-cli info memory
   ```

3. **Token Validation Errors**

   ```bash
   # Check JWT secret configuration
   kubectl get secret oauth2-auth-secrets -n auth -o yaml
   ```

### Health Check Endpoints

- **Health**: `GET /api/v1/auth/health` - Overall service health
- **Readiness**: `GET /api/v1/auth/health/ready` - Service readiness for traffic
- **Liveness**: `GET /api/v1/auth/health/live` - Service liveness check
- **Metrics**: `GET /api/v1/auth/metrics` - Prometheus metrics
