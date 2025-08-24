# API Reference

## Overview

The OAuth2 Authentication Service provides RESTful APIs for authentication,
authorization, and token management. All endpoints follow OAuth2 and OpenID
Connect specifications.

## Base URL

- **Development**: `http://localhost:8080/api/v1/auth`
- **Production**: `https://auth.example.com/api/v1/auth`

## Authentication

Most endpoints require authentication using one of the following methods:

- **Bearer Token**: `Authorization: Bearer <access_token>`
- **Client Credentials**: `Authorization: Basic <base64(client_id:client_secret)>`

## Health Endpoints

### Health Check

Check the overall health of the service and its dependencies.

**Request:**

```http
GET /api/v1/auth/health
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "checks": {
    "redis": "up"
  },
  "version": "1.0.0"
}
```

**Status Codes:**

- `200 OK` - Service is healthy
- `503 Service Unavailable` - Service is unhealthy

### Readiness Check

Check if the service is ready to accept requests.

**Request:**

```http
GET /api/v1/auth/health/ready
```

**Response:**

```json
{
  "ready": true,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Status Codes:**

- `200 OK` - Service is ready
- `503 Service Unavailable` - Service is not ready

## OAuth2 Endpoints

### Authorization Endpoint

Initiates the OAuth2 Authorization Code Flow with PKCE.

**Request:**

```http
GET /api/v1/auth/oauth2/authorize?response_type=code&client_id=<client_id>&redirect_uri=<redirect_uri>&scope=<scope>&state=<state>&code_challenge=<code_challenge>&code_challenge_method=S256
```

**Parameters:**

- `response_type` (required) - Must be "code"
- `client_id` (required) - Client identifier
- `redirect_uri` (required) - Client redirect URI
- `scope` (optional) - Requested scope(s)
- `state` (recommended) - CSRF protection value
- `code_challenge` (required) - PKCE code challenge
- `code_challenge_method` (optional) - Must be "S256" (default)

**Success Response:**

```http
HTTP/1.1 302 Found
Location: https://client.example.com/callback?code=<authorization_code>&state=<state>
```

**Error Response:**

```http
HTTP/1.1 302 Found
Location: https://client.example.com/callback?error=invalid_request&error_description=<description>&state=<state>
```

### Token Endpoint

Exchange authorization codes for tokens or perform client credentials flow.

#### Authorization Code Grant

**Request:**

```http
POST /api/v1/auth/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<code>&redirect_uri=<redirect_uri>&client_id=<client_id>&code_verifier=<code_verifier>
```

#### Client Credentials Grant

**Request:**

```http
POST /api/v1/auth/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=client_credentials&scope=<scope>
```

#### Refresh Token Grant

**Request:**

```http
POST /api/v1/auth/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>&scope=<scope>
```

**Success Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "8xLOxBtZp8",
  "scope": "read write"
}
```

**Error Response:**

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code is invalid or expired"
}
```

**Status Codes:**

- `200 OK` - Token issued successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Invalid client credentials

### Token Introspection

Returns metadata about a token including its validity and claims.

**Request:**

```http
POST /api/v1/auth/oauth2/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<token>&token_type_hint=access_token
```

**Parameters:**

- `token` (required) - The token to introspect
- `token_type_hint` (optional) - "access_token" or "refresh_token"

**Response:**

```json
{
  "active": true,
  "scope": "read write",
  "client_id": "my-client",
  "sub": "user123",
  "exp": 1640995200,
  "iat": 1640991600,
  "aud": ["https://api.example.com"]
}
```

**Status Codes:**

- `200 OK` - Introspection successful
- `401 Unauthorized` - Invalid client credentials

### Token Revocation

Revokes an access token or refresh token.

**Request:**

```http
POST /api/v1/auth/oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<token>&token_type_hint=refresh_token
```

**Parameters:**

- `token` (required) - The token to revoke
- `token_type_hint` (optional) - "access_token" or "refresh_token"

**Response:**

```http
HTTP/1.1 200 OK
```

**Status Codes:**

- `200 OK` - Token revoked successfully
- `401 Unauthorized` - Invalid client credentials

### User Information

Returns information about the authenticated user.

**Request:**

```http
GET /api/v1/auth/oauth2/userinfo
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "sub": "user123",
  "email": "user@example.com",
  "name": "John Doe",
  "preferred_username": "johndoe"
}
```

**Status Codes:**

- `200 OK` - User information retrieved
- `401 Unauthorized` - Invalid or expired token

## Monitoring Endpoints

### Prometheus Metrics

Returns Prometheus-formatted metrics for monitoring.

**Request:**

```http
GET /api/v1/auth/metrics
```

**Response:**

```text
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/health",status="200"} 42
...
```

**Status Codes:**

- `200 OK` - Metrics retrieved successfully

## Error Handling

All OAuth2 errors follow the standard OAuth2 error format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description",
  "error_uri": "https://tools.ietf.org/html/rfc6749#section-4.1.2.1",
  "state": "original_state_value"
}
```

### OAuth2 Error Codes

- `invalid_request` - The request is missing a required parameter
- `invalid_client` - Client authentication failed
- `invalid_grant` - The authorization grant is invalid, expired, or revoked
- `unauthorized_client` - The client is not authorized to request tokens
- `unsupported_grant_type` - The authorization grant type is not supported
- `invalid_scope` - The requested scope is invalid, unknown, or malformed
- `access_denied` - The resource owner denied the request
- `unsupported_response_type` - The authorization server does not support the response type
- `server_error` - The authorization server encountered an unexpected condition
- `temporarily_unavailable` - The authorization server is currently unable to handle the request

## Rate Limiting

The service implements rate limiting to prevent abuse:

- **Default Limit**: 100 requests per minute per IP
- **Headers**: Rate limit information is included in response headers:
  - `X-RateLimit-Limit` - Request limit per window
  - `X-RateLimit-Remaining` - Requests remaining in current window
  - `X-RateLimit-Reset` - Time when the rate limit resets

**Rate Limit Exceeded Response:**

```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

**Status Code:** `429 Too Many Requests`

## CORS Support

The service supports Cross-Origin Resource Sharing (CORS) with configurable origins:

**Preflight Request:**

```http
OPTIONS /api/v1/auth/oauth2/token
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization
```

**Preflight Response:**

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

## Client Integration Examples

### JavaScript (Authorization Code Flow)

```javascript
// Generate PKCE parameters
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Redirect to authorization endpoint
const authUrl = new URL('https://auth.example.com/api/v1/auth/oauth2/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'my-client');
authUrl.searchParams.set('redirect_uri', 'https://app.example.com/callback');
authUrl.searchParams.set('scope', 'read write');
authUrl.searchParams.set('state', generateState());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();

// Exchange code for tokens (in callback handler)
const tokenResponse = await fetch('https://auth.example.com/api/v1/auth/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://app.example.com/callback',
    client_id: 'my-client',
    code_verifier: codeVerifier,
  }),
});

const tokens = await tokenResponse.json();
```

### cURL (Client Credentials Flow)

```bash
# Request access token
curl -X POST https://auth.example.com/api/v1/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d "grant_type=client_credentials&scope=read"

# Use access token
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  https://api.example.com/protected-resource
```

## SDK and Libraries

### Go Client Library

```go
import "github.com/your-org/oauth2-client-go"

client := oauth2client.New(oauth2client.Config{
    ClientID:     "my-client",
    ClientSecret: "my-secret", // pragma: allowlist secret
    TokenURL:     "https://auth.example.com/api/v1/auth/oauth2/token",
})

token, err := client.ClientCredentials(ctx, "read write")
if err != nil {
    log.Fatal(err)
}

// Use token in API calls
req.Header.Set("Authorization", "Bearer "+token.AccessToken)
```

### Node.js Client Library

```javascript
const OAuth2Client = require('@your-org/oauth2-client-node');

const client = new OAuth2Client({
  clientId: 'my-client',
  clientSecret: 'my-secret', // pragma: allowlist secret
  tokenUrl: 'https://auth.example.com/api/v1/auth/oauth2/token',
});

const token = await client.clientCredentials(['read', 'write']);
console.log('Access Token:', token.accessToken);
```
