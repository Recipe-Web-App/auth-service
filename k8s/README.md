# Kubernetes Deployment for OAuth2 Authentication Service

This directory contains Kubernetes manifests for deploying the Go-based OAuth2 authentication service in a
production-ready configuration.

## Overview

The deployment includes:

- **Deployment**: Application pods with security hardening, resource limits, and health checks
- **Service**: ClusterIP service for internal communication
- **Ingress**: NGINX ingress with SSL termination and rate limiting
- **ConfigMap**: Non-sensitive configuration data
- **Secret**: Sensitive configuration data (JWT secrets, Redis passwords)
- **NetworkPolicy**: Network security policies
- **PodDisruptionBudget**: Ensures availability during updates
- **HorizontalPodAutoscaler**: Automatic scaling based on CPU/memory usage
- **ServiceMonitor**: Prometheus monitoring configuration
- **Namespace**: Isolated namespace for the service

## Features

### Security

- Non-root user execution (UID/GID 10001)
- Read-only root filesystem
- Dropped ALL capabilities
- SecComp profile enabled
- Network policies for ingress/egress control
- Secure secret management

### Reliability

- Pod anti-affinity for high availability
- Health checks (readiness, liveness, startup probes)
- Resource requests and limits
- Graceful shutdown (30s termination grace period)
- Pod disruption budget to maintain availability

### Scalability

- Horizontal pod autoscaler (2-10 replicas)
- CPU and memory-based scaling
- Smart scaling policies with stabilization windows

### Monitoring

- Prometheus metrics endpoint
- ServiceMonitor for automatic discovery
- Health check endpoints for Kubernetes probes

## Prerequisites

1. Kubernetes cluster (1.21+)
2. NGINX Ingress Controller
3. cert-manager (for SSL certificates)
4. Prometheus Operator (for monitoring)
5. Metrics Server (for HPA)

## Configuration

### Environment Variables

Before deployment, you need to set the following environment variables in your shell or CI/CD system:

```bash
# JWT Configuration
export JWT_SECRET="your-jwt-secret-key-minimum-32-characters-long" # pragma: allowlist secret

# Redis Configuration
export REDIS_PASSWORD="your-redis-password" # pragma: allowlist secret

# Security Configuration
export SECURITY_ALLOWED_ORIGINS="https://yourdomain.com,https://api.yourdomain.com"

# Server Configuration (optional, defaults provided)
export GO_ENV="production"
export SERVER_HOST="0.0.0.0"
export SERVER_PORT="8080"

# OAuth2 Configuration (optional, defaults provided)
export OAUTH2_PKCE_REQUIRED="true"
export OAUTH2_DEFAULT_SCOPES="openid,profile"
export OAUTH2_SUPPORTED_SCOPES="openid,profile,email,read,write"

# Rate Limiting (optional, defaults provided)
export SECURITY_RATE_LIMIT_RPS="100"
export SECURITY_RATE_LIMIT_BURST="200"
```

### Applying Templates

The ConfigMap and Secret templates use environment variable substitution. Use `envsubst` to replace variables:

```bash
# Create ConfigMap
envsubst < k8s/configmap-template.yaml | kubectl apply -f -

# Create Secret
envsubst < k8s/secret-template.yaml | kubectl apply -f -
```

## Deployment

### Quick Deployment

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Apply all configurations (after setting environment variables)
./scripts/containerManagement/deploy-container.sh
```

### Manual Deployment

```bash
# 1. Create namespace
kubectl apply -f k8s/namespace.yaml

# 2. Create ConfigMap and Secret (with environment variables set)
envsubst < k8s/configmap-template.yaml | kubectl apply -f -
envsubst < k8s/secret-template.yaml | kubectl apply -f -

# 3. Apply network policy (optional, if network policies are enabled)
kubectl apply -f k8s/networkpolicy.yaml

# 4. Deploy the application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# 5. Configure ingress
kubectl apply -f k8s/ingress.yaml

# 6. Add monitoring and scaling
kubectl apply -f k8s/servicemonitor.yaml
kubectl apply -f k8s/horizontalpodautoscaler.yaml
kubectl apply -f k8s/poddisruptionbudget.yaml
```

## Verification

### Check Deployment Status

```bash
# Check all resources
kubectl get all -n auth-service

# Check pod logs
kubectl logs -n auth-service -l app=auth-service

# Check health endpoints
kubectl port-forward -n auth-service svc/auth-service 8080:8080

# Test health endpoints
curl http://localhost:8080/api/v1/auth/health
curl http://localhost:8080/api/v1/auth/health/ready
curl http://localhost:8080/api/v1/auth/health/live
```

### Monitoring Commands

```bash
# Check HPA status
kubectl get hpa -n auth-service

# Check PDB status
kubectl get pdb -n auth-service

# Check network policy
kubectl describe networkpolicy -n auth-service
```

## OAuth2 Endpoints

Once deployed, the service provides the following OAuth2 endpoints:

- **Authorization**: `/api/v1/auth/oauth2/authorize`
- **Token**: `/api/v1/auth/oauth2/token`
- **Token Introspection**: `/api/v1/auth/oauth2/introspect`
- **User Info**: `/api/v1/auth/oauth2/userinfo`
- **Token Revocation**: `/api/v1/auth/oauth2/revoke`
- **Health Check**: `/api/v1/auth/health`
- **Readiness Probe**: `/api/v1/auth/health/ready`
- **Liveness Probe**: `/api/v1/auth/health/live`
- **Metrics**: `/api/v1/auth/metrics`

## Scaling

The service automatically scales based on CPU and memory usage:

- **Min replicas**: 2
- **Max replicas**: 10
- **CPU target**: 70%
- **Memory target**: 80%

Manual scaling:

```bash
kubectl scale deployment auth-service -n auth-service --replicas=5
```

## Troubleshooting

### Common Issues

1. **Pods not starting**: Check resource limits and node capacity
2. **Health checks failing**: Verify health endpoints are working
3. **Network connectivity**: Check network policies and service discovery
4. **Configuration issues**: Verify ConfigMap and Secret values
5. **JWT secret too short**: Ensure JWT secret is at least 32 characters

### Debug Commands

```bash
# Describe pod for events
kubectl describe pod -n auth-service -l app=auth-service

# Check resource usage
kubectl top pods -n auth-service

# Check configuration
kubectl get configmap -n auth-service auth-service-config -o yaml
kubectl get secret -n auth-service auth-service-secrets -o yaml

# Check logs with more detail
kubectl logs -n auth-service -l app=auth-service --tail=100 -f
```

## Security Considerations

1. **Secrets Management**: Use external secret management systems like HashiCorp Vault or AWS Secrets Manager in production
2. **Network Policies**: Ensure network policies are enabled in your cluster
3. **RBAC**: Implement proper role-based access control
4. **Image Scanning**: Scan container images for vulnerabilities
5. **SSL/TLS**: Use proper certificates for ingress
6. **JWT Secret**: Use a cryptographically secure random string of at least 32 characters

## Performance Tuning

1. **Resource Limits**: Adjust based on actual usage patterns
2. **Go Runtime**: Tune GOMAXPROCS and garbage collection settings if needed
3. **Redis Connections**: Optimize connection pool settings
4. **Rate Limiting**: Adjust rate limits based on expected load

## Updates and Rollbacks

```bash
# Rolling update
kubectl set image deployment/auth-service \
  auth-service=auth-service:v2 \
  -n auth-service

# Rollback
kubectl rollout undo deployment/auth-service -n auth-service

# Check rollout status
kubectl rollout status deployment/auth-service -n auth-service
```

## Configuration Reference

### Required Environment Variables

- `JWT_SECRET`: JWT signing secret (minimum 32 characters)
- `REDIS_PASSWORD`: Redis authentication password

### Optional Environment Variables

All configuration options have sensible defaults. See `configmap-template.yaml` for the complete list of
available configuration options.

### Resource Requirements

- **CPU**: 100m request, 500m limit
- **Memory**: 128Mi request, 512Mi limit
- **Storage**: 50Mi ephemeral storage request, 200Mi limit
