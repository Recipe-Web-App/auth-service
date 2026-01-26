#!/bin/bash
# scripts/containerManagement/get-container-status.sh

set -euo pipefail

NAMESPACE="auth-service"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_separator() {
  local char="${1:-=}"
  local width="${2:-80}"
  printf '%*s\n' "$width" '' | tr ' ' "$char"
}

echo -e "${CYAN}📊 Auth Service Status${NC}"
print_separator "="

echo -e "${YELLOW}📋 Namespace Status:${NC}"
kubectl get namespace "$NAMESPACE" || echo "Namespace not found"
print_separator "-"

echo -e "${YELLOW}📦 Deployment Status:${NC}"
kubectl get deployment -n "$NAMESPACE" || echo "No deployments found"
print_separator "-"

echo -e "${YELLOW}🐝 Pod Status:${NC}"
kubectl get pods -n "$NAMESPACE" -o wide || echo "No pods found"
print_separator "-"

echo -e "${YELLOW}🌐 Service Status:${NC}"
kubectl get svc -n "$NAMESPACE" || echo "No services found"
print_separator "-"

echo -e "${YELLOW}📈 HPA Status:${NC}"
kubectl get hpa -n "$NAMESPACE" || echo "No HPA found"
print_separator "-"

echo -e "${YELLOW}🛡️ PDB Status:${NC}"
kubectl get pdb -n "$NAMESPACE" || echo "No PDB found"
print_separator "-"

echo -e "${YELLOW}📊 Resource Usage:${NC}"
kubectl top pods -n "$NAMESPACE" 2>/dev/null || echo "Metrics not available (metrics-server may not be installed)"
print_separator "-"

echo -e "${YELLOW}⚠️ Recent Events:${NC}"
kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp | tail -10
print_separator "-"

if kubectl get pods -n "$NAMESPACE" -l app=auth-service >/dev/null 2>&1; then
    MINIKUBE_IP=$(minikube ip 2>/dev/null || echo "minikube not running")
    echo -e "${GREEN}🌍 Access URLs:${NC}"
    echo "  Health: http://sous-chef-proxy.local/api/v1/auth/health"
    echo "  Readiness: http://sous-chef-proxy.local/api/v1/auth/health/ready"
    echo "  Metrics: http://sous-chef-proxy.local/api/v1/auth/metrics"
    echo "  OAuth2 Authorize: http://sous-chef-proxy.local/api/v1/auth/oauth2/authorize"
    echo "  OAuth2 Token: http://sous-chef-proxy.local/api/v1/auth/oauth2/token"
    echo "  Minikube IP: $MINIKUBE_IP"
fi

print_separator "="
