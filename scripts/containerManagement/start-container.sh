#!/bin/bash
# scripts/containerManagement/start-container.sh

set -euo pipefail

NAMESPACE="auth-service"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🚀 Starting Auth Service...${NC}"

# Scale up to 1 replica
kubectl scale deployment auth-service -n "$NAMESPACE" --replicas=1

echo -e "${YELLOW}⏳ Waiting for pods to be ready...${NC}"
kubectl wait --namespace="$NAMESPACE" \
  --for=condition=Ready pod \
  --selector=app=auth-service \
  --timeout=60s

echo -e "${GREEN}✅ Auth Service started successfully!${NC}"

# Show status
kubectl get pods -n "$NAMESPACE" -l app=auth-service
