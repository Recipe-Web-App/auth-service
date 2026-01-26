#!/bin/bash
# scripts/containerManagement/update-container.sh

set -euo pipefail

NAMESPACE="auth-service"
IMAGE_NAME="auth-service"
IMAGE_TAG="latest"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🔄 Updating Auth Service...${NC}"

echo -e "${YELLOW}🔍 Building new Docker image...${NC}"
eval "$(minikube docker-env)"
docker build -t "$FULL_IMAGE_NAME" .
echo -e "${GREEN}✅ Docker image built successfully.${NC}"

echo -e "${YELLOW}📝 Updating ConfigMap and Secret...${NC}"
if [ -f .env.prod ]; then
    set -o allexport
    # shellcheck source=.env.prod disable=SC1091
    source .env.prod
    set +o allexport
fi

# Set default values for auth-service specific variables
export JWT_SECRET="${JWT_SECRET:-auth-service-default-jwt-secret-change-this-in-production}"
export REDIS_PASSWORD="${REDIS_PASSWORD:-auth-service-redis-password}"
export SECURITY_ALLOWED_ORIGINS="${SECURITY_ALLOWED_ORIGINS:-http://localhost:3000,http://localhost:8080}"

# All the configuration defaults (same as deploy script)
export GO_ENV="${GO_ENV:-production}"
export SERVER_HOST="${SERVER_HOST:-0.0.0.0}"
export SERVER_PORT="${SERVER_PORT:-8080}"
export SERVER_READ_TIMEOUT="${SERVER_READ_TIMEOUT:-15s}"
export SERVER_WRITE_TIMEOUT="${SERVER_WRITE_TIMEOUT:-15s}"
export SERVER_IDLE_TIMEOUT="${SERVER_IDLE_TIMEOUT:-60s}"
export SERVER_SHUTDOWN_TIMEOUT="${SERVER_SHUTDOWN_TIMEOUT:-30s}"
export REDIS_URL="${REDIS_URL:-redis://redis-service.auth-service.svc.cluster.local:6379}"
export REDIS_DB="${REDIS_DB:-0}"
export REDIS_MAX_RETRIES="${REDIS_MAX_RETRIES:-3}"
export REDIS_POOL_SIZE="${REDIS_POOL_SIZE:-10}"
export REDIS_MIN_IDLE_CONN="${REDIS_MIN_IDLE_CONN:-5}"
export REDIS_DIAL_TIMEOUT="${REDIS_DIAL_TIMEOUT:-5s}"
export REDIS_READ_TIMEOUT="${REDIS_READ_TIMEOUT:-3s}"
export REDIS_WRITE_TIMEOUT="${REDIS_WRITE_TIMEOUT:-3s}"
export REDIS_POOL_TIMEOUT="${REDIS_POOL_TIMEOUT:-4s}"
export REDIS_IDLE_TIMEOUT="${REDIS_IDLE_TIMEOUT:-300s}"
export JWT_ACCESS_TOKEN_EXPIRY="${JWT_ACCESS_TOKEN_EXPIRY:-15m}"
export JWT_REFRESH_TOKEN_EXPIRY="${JWT_REFRESH_TOKEN_EXPIRY:-168h}"
export JWT_ISSUER="${JWT_ISSUER:-auth-service}"
export JWT_ALGORITHM="${JWT_ALGORITHM:-HS256}"
export OAUTH2_AUTHORIZATION_CODE_EXPIRY="${OAUTH2_AUTHORIZATION_CODE_EXPIRY:-10m}"
export OAUTH2_CLIENT_CREDENTIALS_EXPIRY="${OAUTH2_CLIENT_CREDENTIALS_EXPIRY:-1h}"
export OAUTH2_PKCE_REQUIRED="${OAUTH2_PKCE_REQUIRED:-true}"
export OAUTH2_DEFAULT_SCOPES="${OAUTH2_DEFAULT_SCOPES:-openid,profile}"
export OAUTH2_SUPPORTED_SCOPES="${OAUTH2_SUPPORTED_SCOPES:-openid,profile,email,read,write,media:read,media:write,user:read,user:write,admin,notification:admin,notification:user}"
export OAUTH2_SUPPORTED_GRANT_TYPES="${OAUTH2_SUPPORTED_GRANT_TYPES:-authorization_code,client_credentials,refresh_token}"
export OAUTH2_SUPPORTED_RESPONSE_TYPES="${OAUTH2_SUPPORTED_RESPONSE_TYPES:-code}"
export SECURITY_RATE_LIMIT_RPS="${SECURITY_RATE_LIMIT_RPS:-100}"
export SECURITY_RATE_LIMIT_BURST="${SECURITY_RATE_LIMIT_BURST:-200}"
export SECURITY_RATE_LIMIT_WINDOW="${SECURITY_RATE_LIMIT_WINDOW:-1m}"
export SECURITY_ALLOWED_METHODS="${SECURITY_ALLOWED_METHODS:-GET,POST,PUT,DELETE,OPTIONS}"
export SECURITY_ALLOWED_HEADERS="${SECURITY_ALLOWED_HEADERS:-*}"
export SECURITY_ALLOW_CREDENTIALS="${SECURITY_ALLOW_CREDENTIALS:-true}"
export SECURITY_MAX_AGE="${SECURITY_MAX_AGE:-86400}"
export SECURITY_SECURE_COOKIES="${SECURITY_SECURE_COOKIES:-true}"
export SECURITY_SAME_SITE_COOKIES="${SECURITY_SAME_SITE_COOKIES:-strict}"
export LOGGING_LEVEL="${LOGGING_LEVEL:-info}"
export LOGGING_FORMAT="${LOGGING_FORMAT:-json}"
export LOGGING_OUTPUT="${LOGGING_OUTPUT:-stdout}"
export SERVER_TLS_CERT="${SERVER_TLS_CERT:-}"
export SERVER_TLS_KEY="${SERVER_TLS_KEY:-}"

envsubst < k8s/configmap-template.yaml | kubectl apply -f -
kubectl delete secret auth-service-secrets -n "$NAMESPACE" --ignore-not-found
envsubst < k8s/secret-template.yaml | kubectl apply -f -

echo -e "${YELLOW}🔁 Performing rolling restart...${NC}"
kubectl rollout restart deployment/auth-service -n "$NAMESPACE"

echo -e "${YELLOW}⏳ Waiting for rollout to complete...${NC}"
kubectl rollout status deployment/auth-service -n "$NAMESPACE" --timeout=120s

echo -e "${GREEN}✅ Auth Service updated successfully!${NC}"

# Show new pods
echo -e "${CYAN}New pods:${NC}"
kubectl get pods -n "$NAMESPACE" -l app=auth-service
