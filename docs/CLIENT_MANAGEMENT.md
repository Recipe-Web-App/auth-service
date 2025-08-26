# OAuth2 Client Management Guide

This guide explains how to register and manage OAuth2 clients for your backend services in the Recipe Web App
authentication service.

## Overview

The auth service supports multiple methods for client registration and management:

1. **Automatic Registration** - From configuration files during startup
2. **CLI Tool** - Command-line interface for client management
3. **Shell Scripts** - Bash scripts for batch operations
4. **HTTP API** - REST endpoints for programmatic access
5. **Make Commands** - Convenient make targets for common operations

## Quick Start

### 1. Register All Backend Services (Recommended)

```bash
# Option A: Using shell script (creates .env.clients file)
make register-clients

# Option B: Using CLI tool in batch mode
make register-clients-cli

# Option C: Using configuration file
make register-clients-config
```

### 2. Get Access Tokens for Testing

```bash
# Export your client credentials
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret" # pragma: allowlist secret

# Get an access token
make get-token CLIENT_ID=$CLIENT_ID CLIENT_SECRET=$CLIENT_SECRET
```

## Automatic Registration

### Configuration File Method

Enable automatic client registration in your environment:

```bash
# .env.local
CLIENT_AUTO_REGISTER_ENABLED=true
CLIENT_AUTO_REGISTER_CONFIG_PATH=configs/clients.json
CLIENT_AUTO_REGISTER_CREATE_SAMPLE_CLIENT=false
```

The service will automatically register clients from `configs/clients.json` on startup.

### Client Configuration Format

```json
[
  {
    "name": "Recipe Service",
    "redirect_uris": ["http://recipe-service:8080/callback"],
    "scopes": ["read", "write", "profile"],
    "grant_types": ["client_credentials"]
  },
  {
    "name": "API Gateway",
    "redirect_uris": [
      "http://api-gateway:8080/callback",
      "http://localhost:3000/callback"
    ],
    "scopes": ["read", "write", "profile", "email", "openid"],
    "grant_types": ["client_credentials", "authorization_code", "refresh_token"]
  }
]
```

## CLI Tool Usage

### Build the Client Manager

```bash
make build-client-manager
```

### Register Clients

```bash
# Batch register predefined backend services
./bin/client-manager -batch

# Register from configuration file
./bin/client-manager -config configs/clients.json

# Register single client
./bin/client-manager -action register \
  -name "My Service" \
  -redirects "http://my-service:8080/callback" \
  -scopes "read,write" \
  -grants "client_credentials"
```

### Get Client Information

```bash
# Get client details
./bin/client-manager -action get -client-id "your-client-id"
```

### CLI Options

```bash
./bin/client-manager -h
```

- `-url`: Auth service base URL (default: <http://localhost:8080>)
- `-action`: Action to perform (register, get, list, delete)
- `-config`: Path to client configuration file
- `-batch`: Register predefined backend services
- `-name`: Client name for single registration
- `-redirects`: Comma-separated redirect URIs
- `-scopes`: Comma-separated scopes
- `-grants`: Comma-separated grant types
- `-client-id`: Client ID for get/delete operations

## Shell Scripts

### Register All Clients

```bash
# Register all backend services and save credentials
./scripts/register-clients.sh

# Register with custom auth service URL
./scripts/register-clients.sh http://auth-service:8080
```

This script:

- Registers 9 predefined backend services
- Saves client credentials to `.env.clients`
- Provides formatted output with IDs and secrets

### Get Access Token

```bash
# Get token for a specific client
./scripts/get-client-token.sh <client_id> <client_secret>

# With custom URL and scopes
./scripts/get-client-token.sh <client_id> <client_secret> http://auth-service:8080 "read write admin"
```

This script:

- Performs client credentials flow
- Shows token details and expiration
- Saves token to `.access_token` file
- Provides curl example for testing

## HTTP API

### Register Client

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Recipe Service",
    "redirect_uris": ["http://recipe-service:8080/callback"],
    "scopes": ["read", "write", "profile"],
    "grant_types": ["client_credentials"]
  }'
```

### Get Client

```bash
curl -X GET http://localhost:8080/api/v1/auth/oauth/clients/{client_id}
```

### Get Access Token via API

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=your-id&client_secret=your-secret&scope=read write"
```

## Backend Service Integration

### Environment Variables

After registration, use the generated credentials in your backend services:

```bash
# Source the generated credentials file
source .env.clients

# Or set individual variables
export RECIPE_SERVICE_CLIENT_ID="abc123"
export RECIPE_SERVICE_CLIENT_SECRET="def456" # pragma: allowlist secret
```

### Client Credentials Flow Example

```go
// Go example for getting access token
func getAccessToken(clientID, clientSecret, authURL string) (string, error) {
    data := url.Values{}
    data.Set("grant_type", "client_credentials")
    data.Set("client_id", clientID)
    data.Set("client_secret", clientSecret)
    data.Set("scope", "read write")

    resp, err := http.PostForm(authURL+"/api/v1/auth/oauth/token", data)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var tokenResp struct {
        AccessToken string `json:"access_token"`
        TokenType   string `json:"token_type"`
        ExpiresIn   int    `json:"expires_in"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return "", err
    }

    return tokenResp.AccessToken, nil
}

// Use token in requests
func makeAuthenticatedRequest(token, url string) error {
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return err
    }

    req.Header.Set("Authorization", "Bearer "+token)

    // Make request...
    return nil
}
```

### JavaScript/Node.js Example

```javascript
// Node.js example
const axios = require('axios');

async function getAccessToken(clientId, clientSecret, authUrl) {
    const data = new URLSearchParams();
    data.append('grant_type', 'client_credentials');
    data.append('client_id', clientId);
    data.append('client_secret', clientSecret);
    data.append('scope', 'read write');

    const response = await axios.post(`${authUrl}/api/v1/auth/oauth/token`, data);
    return response.data.access_token;
}

// Use token in requests
async function makeAuthenticatedRequest(token, url) {
    const response = await axios.get(url, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    return response.data;
}
```

## Predefined Backend Services

The system comes with predefined configurations for these services:

1. **Recipe Service** - Recipe management and operations
2. **User Service** - User authentication and profile management
3. **Inventory Service** - Ingredient and inventory tracking
4. **Order Service** - Order processing and management
5. **Payment Service** - Payment processing
6. **Notification Service** - Email and push notifications
7. **Analytics Service** - Usage analytics and reporting
8. **Search Service** - Recipe and ingredient search
9. **API Gateway** - Main API gateway with full OAuth2 support

Each service is configured with appropriate scopes and grant types for its functionality.

## Grant Types and Scopes

### Grant Types

- **client_credentials**: For service-to-service authentication
- **authorization_code**: For user authentication flows
- **refresh_token**: For token renewal

### Available Scopes

- **read**: Read access to resources
- **write**: Write access to resources
- **profile**: Access to user profile information
- **email**: Access to user email information
- **openid**: OpenID Connect functionality

## Security Best Practices

1. **Store Secrets Securely**: Never commit client secrets to version control
2. **Use Environment Variables**: Store credentials in environment variables
3. **Rotate Credentials**: Regularly rotate client secrets
4. **Minimal Scopes**: Only request necessary scopes
5. **Token Expiration**: Handle token expiration and renewal
6. **HTTPS Only**: Always use HTTPS in production

## Troubleshooting

### Common Issues

1. **Client Not Found**: Ensure client is registered and ID is correct
2. **Invalid Client Secret**: Verify secret matches registered value
3. **Unauthorized Grant Type**: Ensure client supports requested grant type
4. **Invalid Scope**: Ensure requested scopes are allowed for client
5. **Connection Refused**: Verify auth service is running and accessible

### Debug Commands

```bash
# Check if auth service is running
curl http://localhost:8080/api/v1/auth/health

# Validate token
curl -X POST http://localhost:8080/api/v1/auth/oauth/introspect \
  -d "token=your-access-token"

# Check client configuration
curl http://localhost:8080/api/v1/auth/oauth/clients/your-client-id
```

## Make Targets Reference

```bash
make register-clients          # Register all backend services (shell script)
make register-clients-cli      # Register all backend services (CLI tool)
make register-clients-config   # Register from config file
make client-manager-help       # Show CLI tool help
make get-token CLIENT_ID=<id> CLIENT_SECRET=<secret>  # Get access token
make build-client-manager      # Build CLI tool
make env-setup                 # Create .env.local with defaults
```
