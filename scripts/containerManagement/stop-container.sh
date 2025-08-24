#!/bin/bash
# scripts/containerManagement/stop-container.sh

set -euo pipefail

NAMESPACE="auth-service"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🛑 Stopping Auth Service...${NC}"

# Scale down to 0 replicas
kubectl scale deployment auth-service -n "$NAMESPACE" --replicas=0

echo -e "${YELLOW}⏳ Waiting for pods to terminate...${NC}"
kubectl wait --namespace="$NAMESPACE" \
  --for=delete pod \
  --selector=app=auth-service \
  --timeout=60s

echo -e "${RED}🚑 Auth Service stopped successfully!${NC}"

# Show status
kubectl get pods -n "$NAMESPACE" -l app=auth-service
