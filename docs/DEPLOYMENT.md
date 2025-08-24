# Deployment Guide

## Prerequisites

- Go 1.23+ for local development
- Docker and Docker Compose for containerized deployment
- Kubernetes cluster for production deployment
- Redis instance (standalone or cluster)
- Load balancer (nginx, HAProxy, or cloud LB)

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
# Build and start services
docker-compose up -d

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

#### 1. ConfigMap and Secrets

```yaml
# config/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-auth-config
  namespace: auth
data:
  SERVER_ADDRESS: "0.0.0.0:8080"
  REDIS_ADDRESS: "redis:6379"
  REDIS_DB: "0"
  JWT_ISSUER: "https://auth.example.com"
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
---
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-auth-secrets
  namespace: auth
type: Opaque
data:
  JWT_SECRET_KEY: <base64-encoded-secret>
  REDIS_PASSWORD: <base64-encoded-password>
```

#### 2. Deployment

```yaml
# config/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-auth-service
  namespace: auth
  labels:
    app: oauth2-auth-service
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1
  selector:
    matchLabels:
      app: oauth2-auth-service
  template:
    metadata:
      labels:
        app: oauth2-auth-service
    spec:
      containers:
      - name: oauth2-auth-service
        image: your-registry/oauth2-auth-service:v1.0.0
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: oauth2-auth-secrets
              key: JWT_SECRET_KEY
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: oauth2-auth-secrets
              key: REDIS_PASSWORD
        envFrom:
        - configMapRef:
            name: oauth2-auth-config
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
```

#### 3. Service and Ingress

```yaml
# config/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: oauth2-auth-service
  namespace: auth
  labels:
    app: oauth2-auth-service
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: oauth2-auth-service
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-auth-ingress
  namespace: auth
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - auth.example.com
    secretName: oauth2-auth-tls
  rules:
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: oauth2-auth-service
            port:
              number: 8080
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace auth

# Apply configurations
kubectl apply -f config/configmap.yaml
kubectl apply -f config/deployment.yaml
kubectl apply -f config/service.yaml

# Check deployment status
kubectl get pods -n auth
kubectl logs -f deployment/oauth2-auth-service -n auth
```

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'oauth2-auth-service'
    static_configs:
      - targets: ['oauth2-auth-service:8080']
    metrics_path: '/metrics'
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

- **Health**: `GET /health` - Overall service health
- **Readiness**: `GET /health/ready` - Service readiness for traffic
- **Metrics**: `GET /metrics` - Prometheus metrics
