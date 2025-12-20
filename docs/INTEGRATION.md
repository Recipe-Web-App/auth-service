# OAuth2 Authentication Service - Integration Guide

A comprehensive guide for integrating with this enterprise-grade OAuth2 authentication service built in Go with
PKCE support, JWT tokens, and Redis storage.

## Table of Contents

- [Service Overview](#service-overview)
- [Quick Start](#quick-start)
- [OAuth2 Flows](#oauth2-flows)
- [API Endpoints](#api-endpoints)
- [Token Management](#token-management)
- [Client Registration](#client-registration)
- [Configuration](#configuration)
- [Integration Examples](#integration-examples)
- [Security & Best Practices](#security--best-practices)
- [Troubleshooting](#troubleshooting)

## Service Overview

### Architecture

- **HTTP Layer**: Gorilla Mux router with comprehensive middleware stack
- **Business Logic**: OAuth2 service supporting Authorization Code Flow with PKCE and Client Credentials Flow
- **Storage**: PostgreSQL for persistent user data + Redis for sessions/tokens with graceful degradation
- **Token Services**: JWT generation/validation and PKCE implementation
- **Security**: Rate limiting, CORS, security headers, and TLS support

### Supported Standards

- OAuth 2.0 (RFC 6749)
- OAuth 2.0 PKCE (RFC 7636)
- OpenID Connect Core 1.0
- JWT (RFC 7519)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)

### Key Features

- ✅ Authorization Code Flow with PKCE
- ✅ Client Credentials Flow
- ✅ Refresh Token Flow
- ✅ OpenID Connect ID Tokens
- ✅ JWT Access Tokens
- ✅ Token Introspection & Revocation
- ✅ Rate Limiting & Security Headers
- ✅ PostgreSQL + Redis Hybrid Storage with Graceful Degradation
- ✅ Health Checks & Metrics with Degraded Status Support
- ✅ Graceful Shutdown

## Quick Start

### 1. Service Deployment

**Using Docker:**

```bash
# Development environment
docker-compose -f docker-compose.dev.yml up -d

# Production environment
docker-compose up -d
```

**Using Make:**

```bash
# Install dependencies and tools
make deps && make tools

# Run with hot reload (development)
make dev

# Build and run (production)
make build && make run
```

### 2. Environment Configuration

Create a `.env.local` file for development:

```env
# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0

# JWT Configuration (REQUIRED - minimum 32 characters)
JWT_SECRET=your-super-secret-jwt-signing-key-here-32-chars-minimum  # pragma: allowlist secret
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=168h

# OAuth2 Configuration
OAUTH2_PKCE_REQUIRED=true
OAUTH2_DEFAULT_SCOPES=openid,profile
OAUTH2_SUPPORTED_SCOPES=openid,profile,email,read,write,media:read,media:write,user:read,user:write,admin,notification:admin,notification:user

# Redis Configuration (required for OAuth2 sessions)
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# PostgreSQL Configuration (optional - for persistent user storage)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=recipe_manager
POSTGRES_SCHEMA=recipe_manager
POSTGRES_USER=auth_user
POSTGRES_PASSWORD=auth_password

# Security Configuration
SECURITY_RATE_LIMIT_RPS=100
SECURITY_ALLOWED_ORIGINS=*
SECURITY_ALLOW_CREDENTIALS=true

# Client Auto-Registration
CLIENT_AUTO_REGISTER_CREATE_SAMPLE_CLIENT=true
```

### 3. Sample Client Setup

The service automatically creates a sample client for testing when `CREATE_SAMPLE_CLIENT=true`:

```json
{
  "client_id": "generated-uuid",
  "client_secret": "generated-secret",  # pragma: allowlist secret
  "name": "Sample Client",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "http://localhost:8080/callback"
  ],
  "scopes": ["openid", "profile", "email", "read", "write"],
  "grant_types": ["authorization_code", "client_credentials", "refresh_token"]
}
```

### 4. Health Check

Verify the service is running:

```bash
curl http://localhost:8080/api/v1/auth/health
```

Expected response:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "components": {
    "redis": {
      "status": "healthy",
      "message": "Redis is healthy"
    },
    "database": {
      "status": "healthy",
      "message": "PostgreSQL is healthy"
    },
    "configuration": {
      "status": "healthy",
      "message": "Configuration is valid"
    }
  }
}
```

**Degraded Status Example** (PostgreSQL unavailable):

```json
{
  "status": "degraded",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "components": {
    "redis": {
      "status": "healthy",
      "message": "In-Memory is healthy"
    },
    "database": {
      "status": "unhealthy",
      "message": "PostgreSQL connection failed: database is not available"
    },
    "configuration": {
      "status": "healthy",
      "message": "Configuration is valid"
    }
  }
}
```

## OAuth2 Flows

### Authorization Code Flow with PKCE (Recommended)

This is the most secure flow, recommended for all client types including SPAs and mobile apps.

#### Step 1: Generate PKCE Parameters

```javascript
// Generate code verifier (43-128 characters, URL-safe)
const codeVerifier = generateRandomString(128);

// Generate code challenge (SHA256 hash of verifier, base64url encoded)
const codeChallenge = base64UrlEncode(sha256(codeVerifier));
const codeChallengeMethod = "S256";
```

#### Step 2: Authorization Request

Redirect user to authorization endpoint:

```http
GET /api/v1/auth/oauth2/authorize?
  response_type=code&
  client_id=your-client-id&
  redirect_uri=http://localhost:3000/callback&
  scope=openid profile email&
  state=random-state-value&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256
```

#### Step 3: Handle Authorization Response

After user authorization, you'll receive:

```text
http://localhost:3000/callback?
  code=authorization-code&
  state=random-state-value
```

#### Step 4: Exchange Code for Tokens

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "code=authorization-code" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=CODE_VERIFIER"
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "opaque-refresh-token",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Client Credentials Flow (Service-to-Service)

For machine-to-machine authentication:

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "client-id:client-secret" \
  -d "grant_type=client_credentials" \
  -d "scope=read write"
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### Refresh Token Flow

To obtain new access tokens:

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "client-id:client-secret" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=your-refresh-token" \
  -d "scope=openid profile"  # Optional: must be subset of original
```

## API Endpoints

### Base URL

All OAuth2 endpoints are prefixed with `/api/v1/auth`

### Authorization Endpoint

```http
GET /api/v1/auth/oauth2/authorize
```

**Query Parameters:**

- `response_type` (required): `code`
- `client_id` (required): Your client identifier
- `redirect_uri` (required): Must match registered URI
- `scope` (optional): Space-delimited scopes (default: `openid profile`)
- `state` (recommended): CSRF protection
- `nonce` (optional): OpenID Connect replay protection
- `code_challenge` (required for PKCE): Base64url-encoded SHA256 hash
- `code_challenge_method` (optional): `plain` or `S256` (default: `plain`)

**Responses:**

- `302 Found`: Redirect to `redirect_uri` with code and state
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Invalid client

### Token Endpoint

```http
POST /api/v1/auth/oauth2/token
```

**Content-Type:** `application/x-www-form-urlencoded`

**Authentication:** Client credentials via Basic Auth or form parameters

**Parameters (Authorization Code Grant):**

- `grant_type`: `authorization_code`
- `code`: Authorization code from authorization endpoint
- `redirect_uri`: Must match authorization request
- `code_verifier`: PKCE code verifier
- `client_id`: Client identifier
- `client_secret`: Client secret (if confidential client)

**Parameters (Client Credentials Grant):**

- `grant_type`: `client_credentials`
- `scope`: Requested scopes (space-delimited)
- `client_id`: Client identifier
- `client_secret`: Client secret

**Parameters (Refresh Token Grant):**

- `grant_type`: `refresh_token`
- `refresh_token`: Valid refresh token
- `scope`: Requested scopes (must be subset of original)
- `client_id`: Client identifier
- `client_secret`: Client secret

**Success Response (200 OK):**

```json
{
  "access_token": "jwt-access-token",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "opaque-refresh-token",
  "scope": "openid profile email",
  "id_token": "jwt-id-token"
}
```

### Token Introspection

```http
POST /api/v1/auth/oauth2/introspect
```

**Parameters:**

- `token`: Token to introspect
- `token_type_hint`: `access_token` or `refresh_token`
- Client authentication required

**Response:**

```json
{
  "active": true,
  "client_id": "your-client-id",
  "username": "user123",
  "scope": "openid profile email",
  "token_type": "Bearer",
  "exp": 1705315800,
  "iat": 1705314900,
  "sub": "user123",
  "aud": ["your-client-id"],
  "iss": "auth-service"
}
```

### Token Revocation

```http
POST /api/v1/auth/oauth2/revoke
```

**Parameters:**

- `token`: Token to revoke
- `token_type_hint`: `access_token` or `refresh_token`
- Client authentication required

**Response:** `200 OK` (empty body)

### UserInfo Endpoint (OpenID Connect)

```http
GET /api/v1/auth/oauth2/userinfo
Authorization: Bearer ACCESS_TOKEN
```

**Response:**

```json
{
  "sub": "user123",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "picture": "https://example.com/profile.jpg"
}
```

### Discovery Endpoint

```http
GET /api/v1/auth/.well-known/oauth-authorization-server
```

### Health Endpoints

```http
GET /api/v1/auth/health         # General health
GET /api/v1/auth/health/live    # Liveness probe
GET /api/v1/auth/health/ready   # Readiness probe
```

### Metrics

```http
GET /api/v1/auth/metrics        # Prometheus metrics
```

## Token Management

### JWT Access Tokens

Access tokens are signed JWTs containing:

**Header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**

```json
{
  "iss": "auth-service",
  "aud": ["client-id"],
  "sub": "user123",
  "client_id": "client-id",
  "user_id": "user123",
  "scopes": ["openid", "profile", "email"],
  "type": "access_token",
  "exp": 1705315800,
  "iat": 1705314900,
  "nbf": 1705314900,
  "jti": "unique-token-id"
}
```

### Token Validation

**Server-side validation:**

1. Verify JWT signature using shared secret
2. Check token expiry (`exp` claim)
3. Verify token type (`type` claim)
4. Validate issuer (`iss` claim)
5. Check audience (`aud` claim)

**Client-side validation example (Node.js):**

```javascript
const jwt = require("jsonwebtoken");

function validateAccessToken(token, secret) {
  try {
    const decoded = jwt.verify(token, secret);

    if (decoded.type !== "access_token") {
      throw new Error("Invalid token type");
    }

    return decoded;
  } catch (error) {
    throw new Error("Token validation failed: " + error.message);
  }
}
```

### Refresh Token Strategy

- **Opaque Tokens**: Refresh tokens are secure random strings, not JWTs
- **Long-lived**: Default 7 days (configurable)
- **Rotation Supported**: Track usage with rotation counter
- **Revocable**: Can be revoked immediately via storage removal

### Token Storage Recommendations

**Client-side (Browser):**

- Store access tokens in memory or sessionStorage
- Store refresh tokens in httpOnly cookies
- Never store tokens in localStorage for sensitive applications

**Client-side (Mobile):**

- Use secure keychain/keystore for token storage
- Implement token refresh logic with retry mechanisms

**Server-side:**

- Cache access token validation results (with TTL)
- Use Redis for high-performance token storage
- Implement token cleanup for expired tokens

## Client Registration

### Static Registration (Recommended for Production)

Create a `configs/clients.json` file:

```json
[
  {
    "name": "My Web App",
    "redirect_uris": [
      "https://myapp.com/auth/callback",
      "https://myapp.com/silent-refresh"
    ],
    "scopes": ["openid", "profile", "email", "read"],
    "grant_types": ["authorization_code", "refresh_token"]
  },
  {
    "name": "My API Service",
    "redirect_uris": ["https://api.myapp.com/callback"],
    "scopes": ["read", "write"],
    "grant_types": ["client_credentials"]
  }
]
```

Set environment variables:

```env
CLIENT_AUTO_REGISTER_ENABLED=true
CLIENT_AUTO_REGISTER_CONFIG_PATH=configs/clients.json
```

### Dynamic Registration (Development)

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My New App",
    "redirect_uris": ["http://localhost:3000/callback"],
    "scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code", "refresh_token"]
  }'
```

Response:

```json
{
  "id": "generated-client-id",
  "name": "My New App",
  "redirect_uris": ["http://localhost:3000/callback"],
  "scopes": ["openid", "profile", "email"],
  "grant_types": ["authorization_code", "refresh_token"],
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "is_active": true
}
```

**Note:** The client secret is only returned during registration and cannot be retrieved later.

## Configuration

### Environment Variables Reference

#### Server Configuration

```env
SERVER_PORT=8080                    # HTTP port (1-65535)
SERVER_HOST=0.0.0.0                 # Bind address
SERVER_READ_TIMEOUT=15s             # Request read timeout
SERVER_WRITE_TIMEOUT=15s            # Response write timeout
SERVER_IDLE_TIMEOUT=60s             # Keep-alive timeout
SERVER_SHUTDOWN_TIMEOUT=30s         # Graceful shutdown timeout
SERVER_TLS_CERT=/path/to/cert.pem   # TLS certificate path
SERVER_TLS_KEY=/path/to/key.pem     # TLS private key path
```

#### JWT Configuration

```env
JWT_SECRET=your-secret-key          # REQUIRED: min 32 chars  # pragma: allowlist secret
JWT_ACCESS_TOKEN_EXPIRY=15m         # Access token lifetime
JWT_REFRESH_TOKEN_EXPIRY=168h       # Refresh token lifetime (7 days)
JWT_ISSUER=auth-service             # JWT issuer claim
JWT_ALGORITHM=HS256                 # Signing algorithm
```

**Supported JWT algorithms:**

- HS256, HS384, HS512 (HMAC)
- RS256, RS384, RS512 (RSA)
- ES256, ES384, ES512 (ECDSA)

#### OAuth2 Configuration

```env
OAUTH2_AUTHORIZATION_CODE_EXPIRY=10m      # Auth code lifetime
OAUTH2_CLIENT_CREDENTIALS_EXPIRY=1h       # Client credentials token lifetime
OAUTH2_PKCE_REQUIRED=true                 # Enforce PKCE for all clients
OAUTH2_DEFAULT_SCOPES=openid,profile      # Default scopes when none specified
OAUTH2_SUPPORTED_SCOPES=openid,profile,email,read,write,media:read,media:write,user:read,user:write,admin,notification:admin,notification:user
OAUTH2_SUPPORTED_GRANT_TYPES=authorization_code,client_credentials,refresh_token
OAUTH2_SUPPORTED_RESPONSE_TYPES=code
```

#### Security Configuration

```env
SECURITY_RATE_LIMIT_RPS=100         # Requests per second limit
SECURITY_RATE_LIMIT_BURST=200       # Burst capacity
SECURITY_RATE_LIMIT_WINDOW=1m       # Rate limit window
SECURITY_ALLOWED_ORIGINS=*          # CORS allowed origins
SECURITY_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
SECURITY_ALLOWED_HEADERS=*          # CORS allowed headers
SECURITY_ALLOW_CREDENTIALS=true     # CORS credentials support
SECURITY_MAX_AGE=86400              # CORS preflight cache time
SECURITY_SECURE_COOKIES=true        # Mark cookies as secure
SECURITY_SAME_SITE_COOKIES=strict   # SameSite cookie attribute
```

##### PostgreSQL Configuration

```env
POSTGRES_HOST=localhost             # PostgreSQL server hostname
POSTGRES_PORT=5432                  # PostgreSQL server port
POSTGRES_DB=recipe_manager          # PostgreSQL database name
POSTGRES_SCHEMA=recipe_manager      # PostgreSQL schema name
POSTGRES_USER=auth_user             # Database username
POSTGRES_PASSWORD=auth_password     # Database password
POSTGRES_SSL_MODE=require           # SSL connection mode
POSTGRES_MAX_CONN=25                # Maximum connections in pool
POSTGRES_MIN_CONN=5                 # Minimum connections in pool
POSTGRES_MAX_CONN_LIFETIME=1h       # Maximum connection lifetime
POSTGRES_MAX_CONN_IDLE_TIME=30m     # Maximum idle time for connections
POSTGRES_HEALTH_CHECK_PERIOD=30s    # Database health check interval
POSTGRES_CONNECT_TIMEOUT=10s        # Connection timeout
```

#### Redis Configuration

```env
REDIS_URL=redis://localhost:6379    # Redis connection URL
REDIS_PASSWORD=                     # Redis password (optional)
REDIS_DB=0                          # Redis database number
REDIS_MAX_RETRIES=3                 # Connection retry attempts
REDIS_POOL_SIZE=10                  # Connection pool size
REDIS_MIN_IDLE_CONN=5               # Minimum idle connections
REDIS_DIAL_TIMEOUT=5s               # Connection timeout
REDIS_READ_TIMEOUT=3s               # Read operation timeout
REDIS_WRITE_TIMEOUT=3s              # Write operation timeout
REDIS_POOL_TIMEOUT=4s               # Pool wait timeout
REDIS_IDLE_TIMEOUT=300s             # Idle connection timeout
```

#### Logging Configuration

```env
LOGGING_LEVEL=info                  # Log level: debug, info, warn, error
LOGGING_FORMAT=json                 # Log format: json, text
LOGGING_OUTPUT=stdout               # Output: stdout, stderr, file path
LOGGING_CONSOLE_FORMAT=text         # Console output format
LOGGING_FILE_FORMAT=json            # File output format
LOGGING_FILE_PATH=/var/log/auth.log # Log file path (for dual output)
LOGGING_ENABLE_DUAL_OUTPUT=false    # Enable both console and file output
```

### Production Deployment Considerations

#### TLS/HTTPS Setup

Configure TLS paths in `configs/prod.yaml`:

```yaml
# configs/prod.yaml
server:
  tls_cert_path: /etc/ssl/certs/auth.crt
  tls_key_path: /etc/ssl/private/auth.key

security:
  secure_cookies: true
```

#### Redis High Availability

Connection URL in `.env.prod`:

```env
REDIS_URL=redis://redis-master:6379
REDIS_PASSWORD=production-password
```

Pool settings in `configs/prod.yaml`:

```yaml
redis:
  pool_size: 20
  max_retries: 5
```

#### Security Hardening

Security settings in `configs/prod.yaml`:

```yaml
oauth2:
  pkce_required: true

security:
  rate_limit_rps: 50
  allowed_origins:
    - https://yourdomain.com
    - https://app.yourdomain.com
  allow_credentials: true
  secure_cookies: true
  same_site_cookies: strict
```

JWT secret in `.env.prod`:

```env
JWT_SECRET=very-long-random-secret-key-for-production-use-minimum-32-characters  # pragma: allowlist secret
```

## Integration Examples

### JavaScript/Node.js (Frontend)

**PKCE Helper Functions:**

```javascript
// crypto-utils.js
import crypto from "crypto";

export function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(96));
}

export function generateCodeChallenge(verifier) {
  return base64UrlEncode(crypto.createHash("sha256").update(verifier).digest());
}

function base64UrlEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
```

**OAuth2 Client:**

```javascript
// auth-client.js
class OAuth2Client {
  constructor(config) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.authBaseUrl = config.authBaseUrl;
  }

  async startAuthFlow() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = crypto.randomBytes(16).toString('hex');

    // Store for later use
    sessionStorage.setItem('code_verifier', codeVerifier);
    sessionStorage.setItem('auth_state', state);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid profile email',
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });

    window.location.href = `${this.authBaseUrl}/oauth2/authorize?${params}`;
  }

  async handleCallback(code, state) {
    const savedState = sessionStorage.getItem('auth_state');
    if (state !== savedState) {
      throw new Error('Invalid state parameter');
    }

    const codeVerifier = sessionStorage.getItem('code_verifier');
    if (!codeVerifier) {
      throw new Error('Code verifier not found');
    }

    const response = await fetch(`${this.authBaseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code: code,
        redirect_uri: this.redirectUri,
        code_verifier: codeVerifier
      })
    });

    if (!response.ok) {
      throw new Error('Token exchange failed');
    }

    const tokens = await response.json();

    // Clean up
    sessionStorage.removeItem('code_verifier');
    sessionStorage.removeItem('auth_state');

    return tokens;
  }

  async refreshToken(refreshToken) {
    const response = await fetch(`${this.authBaseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        refresh_token: refreshToken
      })
    });

    if (!response.ok) {
      throw new Error('Token refresh failed');
    }

    return await response.json();
  }
}

// Usage
const authClient = new OAuth2Client({
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',  # pragma: allowlist secret
  redirectUri: 'http://localhost:3000/callback',
  authBaseUrl: 'http://localhost:8080/api/v1/auth'
});

// Start auth flow
authClient.startAuthFlow();

// Handle callback
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');
if (code) {
  const tokens = await authClient.handleCallback(code, state);
  console.log('Tokens received:', tokens);
}
```

### React Integration

```jsx
// AuthProvider.jsx
import React, { createContext, useContext, useState, useEffect } from "react";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [tokens, setTokens] = useState(null);
  const [loading, setLoading] = useState(true);

  const authClient = new OAuth2Client({
    clientId: process.env.REACT_APP_CLIENT_ID,
    clientSecret: process.env.REACT_APP_CLIENT_SECRET,
    redirectUri: `${window.location.origin}/callback`,
    authBaseUrl: process.env.REACT_APP_AUTH_BASE_URL,
  });

  useEffect(() => {
    // Check for stored tokens on mount
    const storedTokens = localStorage.getItem("auth_tokens");
    if (storedTokens) {
      setTokens(JSON.parse(storedTokens));
    }
    setLoading(false);
  }, []);

  const login = () => {
    authClient.startAuthFlow();
  };

  const logout = async () => {
    if (tokens?.access_token) {
      // Revoke tokens
      await fetch(`${process.env.REACT_APP_AUTH_BASE_URL}/oauth2/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          token: tokens.access_token,
          client_id: process.env.REACT_APP_CLIENT_ID,
          client_secret: process.env.REACT_APP_CLIENT_SECRET,
        }),
      });
    }

    setTokens(null);
    localStorage.removeItem("auth_tokens");
  };

  const refreshAccessToken = async () => {
    if (!tokens?.refresh_token) return null;

    try {
      const newTokens = await authClient.refreshToken(tokens.refresh_token);
      setTokens(newTokens);
      localStorage.setItem("auth_tokens", JSON.stringify(newTokens));
      return newTokens.access_token;
    } catch (error) {
      console.error("Token refresh failed:", error);
      logout();
      return null;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        tokens,
        loading,
        login,
        logout,
        refreshAccessToken,
        isAuthenticated: !!tokens?.access_token,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
```

### Python Integration

```python
# oauth2_client.py
import requests
import secrets
import hashlib
import base64
from urllib.parse import urlencode, parse_qs

class OAuth2Client:
    def __init__(self, client_id, client_secret, redirect_uri, auth_base_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_base_url = auth_base_url

    def generate_pkce_params(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(96)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def get_auth_url(self, scopes=['openid', 'profile', 'email']):
        """Generate authorization URL with PKCE"""
        code_verifier, code_challenge = self.generate_pkce_params()
        state = secrets.token_urlsafe(32)

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(scopes),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        # Store for later (in production, use secure session storage)
        self._code_verifier = code_verifier
        self._state = state

        return f"{self.auth_base_url}/oauth2/authorize?{urlencode(params)}"

    def exchange_code_for_tokens(self, code, state):
        """Exchange authorization code for tokens"""
        if state != getattr(self, '_state', None):
            raise ValueError("Invalid state parameter")

        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': self._code_verifier
        }

        response = requests.post(
            f"{self.auth_base_url}/oauth2/token",
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")

        return response.json()

    def refresh_token(self, refresh_token):
        """Refresh access token"""
        data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        response = requests.post(
            f"{self.auth_base_url}/oauth2/token",
            data=data
        )

        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")

        return response.json()

    def get_client_credentials_token(self, scopes=['read', 'write']):
        """Get client credentials token for service-to-service"""
        data = {
            'grant_type': 'client_credentials',
            'scope': ' '.join(scopes)
        }

        response = requests.post(
            f"{self.auth_base_url}/oauth2/token",
            data=data,
            auth=(self.client_id, self.client_secret)
        )

        if response.status_code != 200:
            raise Exception(f"Client credentials failed: {response.text}")

        return response.json()

# Usage example
if __name__ == "__main__":
    client = OAuth2Client(
        client_id="your-client-id",
        client_secret="your-client-secret",  # pragma: allowlist secret
        redirect_uri="http://localhost:8000/callback",
        auth_base_url="http://localhost:8080/api/v1/auth"
    )

    # Get authorization URL
    auth_url = client.get_auth_url()
    print(f"Visit: {auth_url}")

    # After user authorization, exchange code for tokens
    # code = input("Enter authorization code: ")
    # state = input("Enter state parameter: ")
    # tokens = client.exchange_code_for_tokens(code, state)
    # print("Tokens:", tokens)
```

### Go Integration

```go
// oauth2_client.go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type OAuth2Client struct {
    ClientID     string
    ClientSecret string
    RedirectURI  string
    AuthBaseURL  string
    HTTPClient   *http.Client
}

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    Scope        string `json:"scope"`
    IDToken      string `json:"id_token"`
}

func NewOAuth2Client(clientID, clientSecret, redirectURI, authBaseURL string) *OAuth2Client {
    return &OAuth2Client{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        RedirectURI:  redirectURI,
        AuthBaseURL:  authBaseURL,
        HTTPClient:   &http.Client{Timeout: 30 * time.Second},
    }
}

func (c *OAuth2Client) GeneratePKCE() (verifier, challenge string, err error) {
    verifierBytes := make([]byte, 96)
    if _, err = rand.Read(verifierBytes); err != nil {
        return "", "", err
    }

    verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

    h := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(h[:])

    return verifier, challenge, nil
}

func (c *OAuth2Client) GetAuthURL(scopes []string) (string, string, string, error) {
    verifier, challenge, err := c.GeneratePKCE()
    if err != nil {
        return "", "", "", err
    }

    stateBytes := make([]byte, 32)
    if _, err = rand.Read(stateBytes); err != nil {
        return "", "", "", err
    }
    state := base64.RawURLEncoding.EncodeToString(stateBytes)

    params := url.Values{
        "response_type":         {"code"},
        "client_id":             {c.ClientID},
        "redirect_uri":          {c.RedirectURI},
        "scope":                 {strings.Join(scopes, " ")},
        "state":                 {state},
        "code_challenge":        {challenge},
        "code_challenge_method": {"S256"},
    }

    authURL := fmt.Sprintf("%s/oauth2/authorize?%s", c.AuthBaseURL, params.Encode())
    return authURL, verifier, state, nil
}

func (c *OAuth2Client) ExchangeCodeForTokens(ctx context.Context, code, verifier, state string) (*TokenResponse, error) {
    data := url.Values{
        "grant_type":     {"authorization_code"},
        "client_id":      {c.ClientID},
        "client_secret":  {c.ClientSecret},
        "code":           {code},
        "redirect_uri":   {c.RedirectURI},
        "code_verifier":  {verifier},
    }

    req, err := http.NewRequestWithContext(ctx, "POST",
        fmt.Sprintf("%s/oauth2/token", c.AuthBaseURL),
        strings.NewReader(data.Encode()),
    )
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("token exchange failed: %s", string(body))
    }

    var tokens TokenResponse
    if err = json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
        return nil, err
    }

    return &tokens, nil
}

func (c *OAuth2Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
    data := url.Values{
        "grant_type":     {"refresh_token"},
        "client_id":      {c.ClientID},
        "client_secret":  {c.ClientSecret},
        "refresh_token":  {refreshToken},
    }

    req, err := http.NewRequestWithContext(ctx, "POST",
        fmt.Sprintf("%s/oauth2/token", c.AuthBaseURL),
        strings.NewReader(data.Encode()),
    )
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("token refresh failed: %s", string(body))
    }

    var tokens TokenResponse
    if err = json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
        return nil, err
    }

    return &tokens, nil
}

func (c *OAuth2Client) GetClientCredentialsToken(ctx context.Context, scopes []string) (*TokenResponse, error) {
    data := url.Values{
        "grant_type": {"client_credentials"},
        "scope":      {strings.Join(scopes, " ")},
    }

    req, err := http.NewRequestWithContext(ctx, "POST",
        fmt.Sprintf("%s/oauth2/token", c.AuthBaseURL),
        strings.NewReader(data.Encode()),
    )
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.SetBasicAuth(c.ClientID, c.ClientSecret)

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("client credentials failed: %s", string(body))
    }

    var tokens TokenResponse
    if err = json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
        return nil, err
    }

    return &tokens, nil
}

// Usage example
func main() {
    client := NewOAuth2Client(
        "your-client-id",
        "your-client-secret",
        "http://localhost:8000/callback",
        "http://localhost:8080/api/v1/auth",
    )

    // Get authorization URL
    authURL, verifier, state, err := client.GetAuthURL([]string{"openid", "profile", "email"})
    if err != nil {
        panic(err)
    }

    fmt.Printf("Visit: %s\n", authURL)

    // After user authorization, exchange code for tokens
    // Replace with actual code and state from callback
    ctx := context.Background()
    // tokens, err := client.ExchangeCodeForTokens(ctx, "auth-code", verifier, state)
    // if err != nil {
    //     panic(err)
    // }
    // fmt.Printf("Tokens: %+v\n", tokens)
}
```

## Security & Best Practices

### PKCE Implementation

**Why PKCE is Required:**

- Protects against authorization code interception attacks
- Essential for public clients (SPAs, mobile apps)
- Recommended for all OAuth2 clients

**PKCE Flow Security:**

1. Generate cryptographically secure code verifier (128 characters recommended)
2. Create code challenge using SHA256 hash
3. Send challenge with authorization request
4. Send verifier with token request
5. Server validates verifier matches challenge

**Code Verifier Requirements:**

- Length: 43-128 characters
- Characters: A-Z, a-z, 0-9, `-`, `.`, `_`, `~`
- Entropy: Minimum 256 bits recommended

### Token Security

**Access Token Best Practices:**

- Short expiry times (15 minutes recommended)
- Store in memory or sessionStorage (browsers)
- Never log full tokens (log only first 8 characters)
- Validate on every API request
- Use secure transport (HTTPS) always

**Refresh Token Best Practices:**

- Longer expiry times (7 days recommended)
- Store in httpOnly cookies (browsers)
- Implement rotation for enhanced security
- Revoke on logout or security events
- Monitor for unusual usage patterns

**ID Token Security:**

- Client-side consumption only
- Never send to resource servers
- Validate nonce if provided
- Short expiry matching access tokens

### CORS Configuration

**Production CORS Setup:**

```env
# Specific origins instead of wildcard
SECURITY_ALLOWED_ORIGINS=https://app.yourdomain.com,https://admin.yourdomain.com

# Restrictive methods
SECURITY_ALLOWED_METHODS=GET,POST,OPTIONS

# Specific headers
SECURITY_ALLOWED_HEADERS=Authorization,Content-Type

# Enable credentials for cookie-based auth
SECURITY_ALLOW_CREDENTIALS=true
```

### Rate Limiting Strategy

**Default Configuration:**

- 100 requests per second per IP
- Burst capacity of 200 requests
- 1-minute sliding window

**Production Tuning:**

```env
# Lower limits for production
SECURITY_RATE_LIMIT_RPS=50
SECURITY_RATE_LIMIT_BURST=100

# Per-client rate limiting (implement custom)
# Different limits for different endpoint types
```

### Error Handling Best Practices

**OAuth2 Error Responses:**

- Always return proper OAuth2 error codes
- Include error_description for debugging
- Log detailed errors server-side only
- Never expose sensitive information in errors

**Common Error Codes:**

- `invalid_request`: Malformed request
- `invalid_client`: Client authentication failed
- `invalid_grant`: Invalid authorization code/refresh token
- `unauthorized_client`: Client not authorized for grant type
- `unsupported_grant_type`: Grant type not supported
- `invalid_scope`: Requested scope invalid

### Monitoring and Alerting

**Key Metrics to Monitor:**

- Token issuance rate
- Token validation failures
- Failed authentication attempts
- Rate limit violations
- PKCE validation failures
- Refresh token usage patterns

**Alerting Scenarios:**

- Unusual token issuance spikes
- High rate of validation failures
- Repeated failed client authentication
- Suspicious refresh token usage
- Health check failures

## Troubleshooting

### Common Integration Issues

#### 1. PKCE Validation Failures

**Error:** `Invalid code_verifier`

**Causes:**

- Code verifier doesn't match challenge
- Wrong challenge method (plain vs S256)
- Code verifier not URL-safe base64 encoded
- Challenge calculation incorrect

**Solutions:**

```javascript
// Correct PKCE implementation
function generateCodeVerifier() {
  const array = new Uint8Array(96);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  return crypto.subtle
    .digest("SHA-256", data)
    .then((hash) => base64UrlEncode(new Uint8Array(hash)));
}

function base64UrlEncode(array) {
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
```

#### 2. JWT Validation Errors

**Error:** `Invalid JWT token`

**Common Issues:**

```javascript
// ❌ Wrong: Using different secret
jwt.verify(token, "wrong-secret");

// ✅ Correct: Using same secret as server
jwt.verify(token, process.env.JWT_SECRET);

// ❌ Wrong: Not checking token type
const decoded = jwt.verify(token, secret);

// ✅ Correct: Validating token type
const decoded = jwt.verify(token, secret);
if (decoded.type !== "access_token") {
  throw new Error("Invalid token type");
}
```

#### 3. CORS Issues

**Error:** `Access to fetch blocked by CORS policy`

**Client-side:**

```javascript
// ❌ Wrong: Missing credentials
fetch("/api/v1/auth/oauth2/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: data,
});

// ✅ Correct: Including credentials
fetch("/api/v1/auth/oauth2/token", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: data,
});
```

**Server-side:**

```env
# Allow specific origins
SECURITY_ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
SECURITY_ALLOW_CREDENTIALS=true
```

#### 4. Token Refresh Loops

**Issue:** Infinite refresh attempts

**Solution:**

```javascript
class TokenManager {
  constructor() {
    this.refreshPromise = null;
  }

  async getValidToken() {
    const token = this.getStoredToken();

    if (!this.isTokenExpired(token)) {
      return token;
    }

    // Prevent multiple concurrent refresh attempts
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.refreshToken().finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  isTokenExpired(token) {
    if (!token) return true;

    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.exp * 1000 < Date.now() + 30000; // 30s buffer
  }
}
```

### Health Check Issues

**Check Service Status:**

```bash
# Basic health check
curl http://localhost:8080/api/v1/auth/health

# Detailed health with Redis status
curl http://localhost:8080/api/v1/auth/health/ready

# Liveness probe (minimal check)
curl http://localhost:8080/api/v1/auth/health/live
```

**Expected Responses:**

```json
// Healthy
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "healthy",
    "redis": "healthy"
  }
}

// Unhealthy
{
  "status": "unhealthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "healthy",
    "redis": "unhealthy"
  }
}
```

### PostgreSQL Connection Issues

**Check PostgreSQL Status:**

```bash
# Test PostgreSQL connection
psql -h localhost -p 5432 -U auth_user -d recipe_manager -c "SELECT 1"

# Check PostgreSQL logs
docker logs postgres-container

# Verify database configuration in service
curl http://localhost:8080/api/v1/auth/health
```

**Database-Dependent Operations:**
When PostgreSQL is unavailable, the following endpoints return HTTP 503:

- `POST /api/v1/auth/register` - User registration requires persistent storage
- `POST /api/v1/auth/login` - User authentication requires user data lookup
- `POST /api/v1/auth/reset-password` - Password reset requires user verification
- `POST /api/v1/auth/reset-password/confirm` - Password updates require persistent storage

**Graceful Degradation Behavior:**

- ✅ Service continues running (health endpoint returns 200 "degraded")
- ✅ OAuth2 flows remain fully functional (Redis-based)
- ✅ Token operations (refresh, revoke, introspect) work normally
- ⚠️ User management operations return 503 until database is restored
- ✅ Background reconnection attempts continue automatically

**Common Database Issues:**

```bash
# Connection refused
ERROR: connection to server at "localhost" (::1), port 5432 failed: Connection refused

# Solution: Ensure PostgreSQL is running and accessible
docker run -d --name postgres -p 5432:5432 \
  -e POSTGRES_DB=recipe_manager \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_password \
  postgres:15-alpine

# Authentication failed
ERROR: FATAL: password authentication failed for user "auth_user"

# Solution: Check credentials in environment variables
echo $POSTGRES_USER
echo $POSTGRES_PASSWORD

# Database does not exist
ERROR: FATAL: database "recipe_manager" does not exist

# Solution: Create database or check POSTGRES_DB setting
psql -h localhost -U postgres -c "CREATE DATABASE recipe_manager;"
```

### Redis Connection Issues

**Check Redis Status:**

```bash
# Test Redis connection
redis-cli -h localhost -p 6379 ping

# Check Redis logs
docker logs redis-container

# Verify Redis configuration in service
curl http://localhost:8080/api/v1/auth/health/ready
```

**Fallback Behavior:**
The service automatically falls back to in-memory storage if Redis is unavailable. This fallback:

- ✅ Allows service to continue running
- ⚠️ Data is not persisted between restarts
- ⚠️ No shared state in multi-instance deployments

### Debug Mode

**Enable Debug Logging:**

```env
LOGGING_LEVEL=debug
LOGGING_FORMAT=text  # More readable for debugging
```

**Debug Information Logged:**

- Detailed request/response data
- Token generation and validation steps
- PKCE validation process
- Client authentication details
- Redis operations
- CORS preflight handling

### Performance Troubleshooting

**Token Validation Performance:**

```javascript
// ❌ Avoid: Validating on every request without caching
app.use((req, res, next) => {
  const token = extractToken(req);
  jwt.verify(token, secret); // Expensive operation
  next();
});

// ✅ Better: Cache validation results
const tokenCache = new Map();
app.use((req, res, next) => {
  const token = extractToken(req);

  if (tokenCache.has(token)) {
    req.user = tokenCache.get(token);
    return next();
  }

  const decoded = jwt.verify(token, secret);
  tokenCache.set(token, decoded);

  // Expire cache entries
  setTimeout(() => tokenCache.delete(token), 60000);

  req.user = decoded;
  next();
});
```

**Redis Performance Tuning:**

```env
# Increase connection pool for high load
REDIS_POOL_SIZE=50
REDIS_MIN_IDLE_CONN=10

# Optimize timeouts
REDIS_DIAL_TIMEOUT=2s
REDIS_READ_TIMEOUT=1s
REDIS_WRITE_TIMEOUT=1s
```

### Getting Help

**Log Analysis:**

1. Check service logs for errors
2. Verify configuration values
3. Test with curl commands
4. Use debug logging temporarily

**Configuration Validation:**

```bash
# Test configuration loading
make run  # Check for config errors on startup

# Validate JWT secret length
echo $JWT_SECRET | wc -c  # Should be >= 32

# Test Redis connection
redis-cli -h $REDIS_HOST -p $REDIS_PORT ping
```

**Support Channels:**

- GitHub Issues: For bugs and feature requests
- Documentation: Refer to API documentation
- Health Endpoints: Monitor service status
- Metrics: Use Prometheus metrics for monitoring

---

This integration guide provides comprehensive information for successfully integrating with the OAuth2
authentication service. For additional support or specific use cases not covered here, please refer to the service
documentation or create an issue in the project repository.
