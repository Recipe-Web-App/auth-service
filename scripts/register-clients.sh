#!/bin/bash

# Script to register OAuth2 clients for backend services
# Usage: ./scripts/register-clients.sh [auth-service-url]

set -e

AUTH_SERVICE_URL=${1:-"http://localhost:8080"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 Registering OAuth2 clients for backend services"
echo "Auth Service URL: $AUTH_SERVICE_URL"
echo

# Function to register a single client
register_client() {
    local name="$1"
    local redirect_uris="$2"
    local scopes="$3"
    local grant_types="$4"

    echo "Registering client: $name"

    response=$(curl -s -X POST "$AUTH_SERVICE_URL/api/v1/auth/oauth/clients" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$name\",
            \"redirect_uris\": [$redirect_uris],
            \"scopes\": [$scopes],
            \"grant_types\": [$grant_types]
        }" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.id' > /dev/null 2>&1; then
        client_id=$(echo "$response" | jq -r '.id')
        client_secret=$(echo "$response" | jq -r '.secret')
        echo "  ✅ Success!"
        echo "  Client ID: $client_id"
        echo "  Client Secret: $client_secret"
        echo

        # Save to environment file
        echo "# $name" >> "$PROJECT_ROOT/.env.clients"
        echo "${name// /_}_CLIENT_ID=$client_id" >> "$PROJECT_ROOT/.env.clients"
        echo "${name// /_}_CLIENT_SECRET=$client_secret" >> "$PROJECT_ROOT/.env.clients"
        echo "" >> "$PROJECT_ROOT/.env.clients"
    else
        echo "  ❌ Failed to register $name"
        echo "  Response: $response"
        echo
    fi
}

# Check if auth service is running
echo "Checking if auth service is running..."
if ! curl -s "$AUTH_SERVICE_URL/api/v1/auth/health" > /dev/null; then
    echo "❌ Auth service is not running at $AUTH_SERVICE_URL"
    echo "Please start the auth service first:"
    echo "  make run"
    exit 1
fi
echo "✅ Auth service is running"
echo

# Initialize clients environment file
> "$PROJECT_ROOT/.env.clients"
echo "# OAuth2 Client Credentials for Backend Services" >> "$PROJECT_ROOT/.env.clients"
echo "# Generated on $(date)" >> "$PROJECT_ROOT/.env.clients"
echo "" >> "$PROJECT_ROOT/.env.clients"

# Register all backend services
register_client "Recipe Service" \
    "\"http://recipe-service:8080/callback\"" \
    "\"read\", \"write\", \"profile\"" \
    "\"client_credentials\""

register_client "User Service" \
    "\"http://user-service:8080/callback\"" \
    "\"read\", \"write\", \"profile\", \"email\"" \
    "\"client_credentials\""

register_client "Inventory Service" \
    "\"http://inventory-service:8080/callback\"" \
    "\"read\", \"write\"" \
    "\"client_credentials\""

register_client "Order Service" \
    "\"http://order-service:8080/callback\"" \
    "\"read\", \"write\", \"profile\"" \
    "\"client_credentials\""

register_client "Payment Service" \
    "\"http://payment-service:8080/callback\"" \
    "\"read\", \"write\"" \
    "\"client_credentials\""

register_client "Notification Service" \
    "\"http://notification-service:8080/callback\"" \
    "\"read\", \"write\", \"email\"" \
    "\"client_credentials\""

register_client "Analytics Service" \
    "\"http://analytics-service:8080/callback\"" \
    "\"read\"" \
    "\"client_credentials\""

register_client "Search Service" \
    "\"http://search-service:8080/callback\"" \
    "\"read\", \"write\"" \
    "\"client_credentials\""

register_client "API Gateway" \
    "\"http://api-gateway:8080/callback\", \"http://localhost:3000/callback\"" \
    "\"read\", \"write\", \"profile\", \"email\", \"openid\"" \
    "\"client_credentials\", \"authorization_code\", \"refresh_token\""

echo "🎉 Client registration complete!"
echo "Client credentials have been saved to: $PROJECT_ROOT/.env.clients"
echo
echo "You can source this file in your backend services:"
echo "  source .env.clients"
