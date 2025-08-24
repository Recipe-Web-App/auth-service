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

### Required Environment Variables

```bash
# Server Configuration
SERVER_ADDRESS=0.0.0.0:8080
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s
SERVER_IDLE_TIMEOUT=120s

# Redis Configuration
REDIS_ADDRESS=redis:6379
REDIS_PASSWORD=""
REDIS_DB=0
REDIS_MAX_RETRIES=3
REDIS_POOL_SIZE=10

# JWT Configuration
JWT_SECRET_KEY=your-256-bit-secret-key
JWT_ISSUER=https://auth.example.com
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=24h

# OAuth2 Configuration
OAUTH2_AUTHORIZATION_CODE_EXPIRY=10m

# Security Configuration
SECURITY_RATE_LIMIT_REQUESTS=100
SECURITY_RATE_LIMIT_WINDOW=1m
SECURITY_CORS_ALLOWED_ORIGINS=https://example.com,https://app.example.com
SECURITY_CORS_ALLOWED_METHODS=GET,POST,OPTIONS
SECURITY_CORS_ALLOWED_HEADERS=Content-Type,Authorization
SECURITY_CORS_ALLOW_CREDENTIALS=true

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
```

### Development Environment (.env.example)

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
# Edit .env with your configuration
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
