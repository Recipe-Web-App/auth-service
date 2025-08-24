# Container Management Scripts

This directory contains shell scripts for managing the OAuth2 Authentication Service deployment in Kubernetes/Minikube.

## Prerequisites

Before using these scripts, ensure you have the following tools installed:

- Docker
- Minikube
- kubectl
- jq
- envsubst (usually part of gettext package)

## Scripts Overview

### `deploy-container.sh`

**Purpose**: Complete deployment of the OAuth2 Authentication Service to Minikube
**What it does**:

- Checks prerequisites (Docker, Minikube, kubectl, jq)
- Starts Minikube and enables ingress addon if needed
- Creates namespace if it doesn't exist
- Loads environment variables from `.env.prod` (if present)
- Builds Docker image inside Minikube
- Creates/updates ConfigMap and Secret
- Deploys all Kubernetes resources (deployment, service, ingress, network policy, pod disruption budget, HPA)
- Sets up `/etc/hosts` entry for local access
- Provides access information

**Usage**: `./scripts/containerManagement/deploy-container.sh`

### `start-container.sh`

**Purpose**: Start the service (scale up to 1 replica)
**What it does**:

- Scales the deployment to 1 replica
- Waits for pods to be ready

**Usage**: `./scripts/containerManagement/start-container.sh`

### `stop-container.sh`

**Purpose**: Stop the service (scale down to 0 replicas)
**What it does**:

- Scales the deployment to 0 replicas
- Waits for pods to terminate

**Usage**: `./scripts/containerManagement/stop-container.sh`

### `update-container.sh`

**Purpose**: Update the running service with new code changes
**What it does**:

- Rebuilds Docker image with latest code
- Updates ConfigMap and Secret
- Performs rolling restart of deployment
- Waits for new pods to be ready

**Usage**: `./scripts/containerManagement/update-container.sh`

### `get-container-status.sh`

**Purpose**: Get comprehensive status of the deployment
**What it does**:

- Checks prerequisites
- Shows namespace, deployment, pod, service, and ingress status
- Displays resource usage and recent events
- Provides access information

**Usage**: `./scripts/containerManagement/get-container-status.sh`

### `cleanup-container.sh`

**Purpose**: Complete cleanup of all resources
**What it does**:

- Removes all Kubernetes resources
- Deletes namespace
- Removes `/etc/hosts` entry
- Removes Docker image from Minikube

**Usage**: `./scripts/containerManagement/cleanup-container.sh`

## Typical Workflow

1. **Initial deployment**:

   ```bash
   ./scripts/containerManagement/deploy-container.sh
   ```

2. **Check status**:

   ```bash
   ./scripts/containerManagement/get-container-status.sh
   ```

3. **Access the application**:
   - Health check: <http://auth-service.local/api/v1/auth/health>
   - Readiness check: <http://auth-service.local/api/v1/auth/health/ready>
   - OAuth2 authorize: <http://auth-service.local/api/v1/auth/oauth2/authorize>
   - OAuth2 token: <http://auth-service.local/api/v1/auth/oauth2/token>
   - Metrics: <http://auth-service.local/api/v1/auth/metrics>

4. **Update after code changes**:

   ```bash
   ./scripts/containerManagement/update-container.sh
   ```

5. **Stop service** (when needed):

   ```bash
   ./scripts/containerManagement/stop-container.sh
   ```

6. **Start service** (after stopping):

   ```bash
   ./scripts/containerManagement/start-container.sh
   ```

7. **Complete cleanup** (when done):

   ```bash
   ./scripts/containerManagement/cleanup-container.sh
   ```

## Environment Variables

The deployment script looks for a `.env.prod` file in the project root to load environment variables.
Create this file with your production environment variables if needed.

Example `.env.prod`:

```bash
# Required variables
JWT_SECRET="your-jwt-secret-key-minimum-32-characters-long" # pragma: allowlist secret
REDIS_PASSWORD="your-redis-password" # pragma: allowlist secret

# Optional variables with examples
GO_ENV="production"
SECURITY_ALLOWED_ORIGINS="https://yourdomain.com,https://api.yourdomain.com"
SECURITY_RATE_LIMIT_RPS="100"
SECURITY_RATE_LIMIT_BURST="200"
OAUTH2_PKCE_REQUIRED="true"
OAUTH2_DEFAULT_SCOPES="openid,profile"
LOGGING_LEVEL="info"
LOGGING_FORMAT="json"
```

## Configuration

The scripts are configured for:

- **Namespace**: `auth-service`
- **Service name**: `auth-service`
- **Image name**: `auth-service:latest`
- **Local domain**: `auth-service.local`
- **Port**: `8080`

## Service Endpoints

Once deployed, the following endpoints are available:

- **Health Check**: `GET /api/v1/auth/health` - Overall service health
- **Readiness Probe**: `GET /api/v1/auth/health/ready` - Ready to serve traffic
- **Liveness Probe**: `GET /api/v1/auth/health/live` - Service is alive
- **Metrics**: `GET /api/v1/auth/metrics` - Prometheus metrics
- **OAuth2 Authorize**: `GET /api/v1/auth/oauth2/authorize` - OAuth2 authorization endpoint
- **OAuth2 Token**: `POST /api/v1/auth/oauth2/token` - OAuth2 token endpoint
- **OAuth2 Introspect**: `POST /api/v1/auth/oauth2/introspect` - Token introspection
- **OAuth2 User Info**: `GET /api/v1/auth/oauth2/userinfo` - User information
- **OAuth2 Revoke**: `POST /api/v1/auth/oauth2/revoke` - Token revocation

## Troubleshooting

1. **Minikube not starting**: Ensure Docker is running and you have sufficient resources
2. **Image not found**: Make sure the Docker build completed successfully
3. **Ingress not working**: Verify the ingress addon is enabled in Minikube
4. **Service not accessible**: Check if `/etc/hosts` entry exists and pods are running
5. **Permission denied**: Ensure scripts are executable (`chmod +x scripts/containerManagement/*.sh`)
6. **JWT secret validation fails**: Ensure JWT secret is at least 32 characters long
7. **Redis connection fails**: Check Redis password and connection settings

## Security Notes

- Scripts automatically set secure defaults if environment variables are not provided
- The JWT secret must be at least 32 characters for security
- Redis password is required for production deployments
- CORS origins should be explicitly configured for production

## Development vs Production

- **Development**: Use `docker-compose.dev.yml` for local development with hot reload
- **Production**: Use the Kubernetes deployment for production-like environment
- Scripts are optimized for local development and testing with Minikube

## Monitoring and Observability

The deployed service includes:

- Prometheus metrics at `/api/v1/auth/metrics`
- Health checks for Kubernetes probes
- Structured logging (JSON format in production)
- Resource usage monitoring via `kubectl top`

## Notes

- These scripts are designed for local development with Minikube
- The Docker image is built inside Minikube's Docker daemon for efficiency
- All scripts include colored output and status indicators for better user experience
- Scripts use `set -euo pipefail` for strict error handling
- The service supports OAuth2 authorization code flow with PKCE, client credentials, and refresh tokens
