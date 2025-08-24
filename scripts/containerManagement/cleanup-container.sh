#!/bin/bash
# scripts/containerManagement/cleanup-container.sh

set -euo pipefail

NAMESPACE="auth-service"
IMAGE_NAME="auth-service"
IMAGE_TAG="latest"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}🗑️ Cleaning up Auth Service deployment...${NC}"

echo -e "${YELLOW}📄 Removing Kubernetes resources...${NC}"
kubectl delete namespace "$NAMESPACE" --ignore-not-found
echo -e "${GREEN}✅ Kubernetes resources removed.${NC}"

echo -e "${YELLOW}🚫 Removing /etc/hosts entry...${NC}"
if grep -q "auth-service.local" /etc/hosts 2>/dev/null; then
    sed -i "/auth-service.local/d" /etc/hosts
    echo -e "${GREEN}✅ /etc/hosts entry removed.${NC}"
else
    echo -e "${YELLOW}⚠️ No /etc/hosts entry found.${NC}"
fi

echo -e "${YELLOW}📦 Removing Docker image from Minikube...${NC}"
if command -v minikube >/dev/null 2>&1 && minikube status >/dev/null 2>&1; then
    eval "$(minikube docker-env)"
    if docker images -q "$FULL_IMAGE_NAME" >/dev/null 2>&1; then
        docker rmi "$FULL_IMAGE_NAME" 2>/dev/null || true
        echo -e "${GREEN}✅ Docker image removed.${NC}"
    else
        echo -e "${YELLOW}⚠️ Docker image not found.${NC}"
    fi
else
    echo -e "${YELLOW}⚠️ Minikube not running, skipping Docker image cleanup.${NC}"
fi

echo -e "${RED}🗑️ Auth Service cleanup completed!${NC}"
