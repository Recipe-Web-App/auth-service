#!/bin/bash

# Script to get access tokens using client credentials flow
# Usage: ./scripts/get-client-token.sh <client_id> <client_secret> [auth-service-url] [scopes]

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <client_id> <client_secret> [auth-service-url] [scopes]"
    echo
    echo "Examples:"
    echo "  $0 abc123 def456"
    echo "  $0 abc123 def456 http://localhost:8080 \"read write\""
    exit 1
fi

CLIENT_ID="$1"
CLIENT_SECRET="$2"
AUTH_SERVICE_URL=${3:-"http://localhost:8080"}
SCOPES=${4:-"read write"}

echo "🔑 Getting access token using client credentials flow"
echo "Client ID: $CLIENT_ID"
echo "Auth Service URL: $AUTH_SERVICE_URL"
echo "Requested Scopes: $SCOPES"
echo

# Make token request
response=$(curl -s -X POST "$AUTH_SERVICE_URL/api/v1/auth/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=$SCOPES" 2>/dev/null)

if [ $? -eq 0 ] && echo "$response" | jq -e '.access_token' > /dev/null 2>&1; then
    access_token=$(echo "$response" | jq -r '.access_token')
    token_type=$(echo "$response" | jq -r '.token_type')
    expires_in=$(echo "$response" | jq -r '.expires_in')
    scope=$(echo "$response" | jq -r '.scope')

    echo "✅ Token obtained successfully!"
    echo
    echo "Access Token: $access_token"
    echo "Token Type: $token_type"
    echo "Expires In: $expires_in seconds"
    echo "Granted Scopes: $scope"
    echo
    echo "Authorization Header:"
    echo "Authorization: $token_type $access_token"
    echo

    # Save token to file for easy reuse
    echo "$access_token" > .access_token
    echo "Token saved to .access_token file for easy reuse"
    echo
    echo "Test the token with:"
    echo "  curl -H \"Authorization: $token_type $access_token\" $AUTH_SERVICE_URL/api/v1/auth/oauth/introspect -d \"token=$access_token\""
else
    echo "❌ Failed to get access token"
    echo "Response: $response"
    exit 1
fi
