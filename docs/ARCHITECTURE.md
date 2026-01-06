# Architecture Overview

## System Architecture

The OAuth2 Authentication Service is designed as a high-performance, enterprise-grade microservice
that provides secure authentication and authorization capabilities for distributed systems.

### Core Components

```text
┌─────────────────────────────────────────────────────────────┐
│                    OAuth2 Auth Service                      │
├─────────────────────────────────────────────────────────────┤
│  HTTP Layer                                                 │
│  ├── Handlers (OAuth2, User Auth, Admin, Health, Metrics)   │
│  ├── Middleware (Rate Limiting, CORS, Logging, Recovery)    │
│  └── Router (Gorilla Mux)                                   │
├─────────────────────────────────────────────────────────────┤
│  Business Logic                                             │
│  ├── OAuth2 Service (Authorization & Token Flows)           │
│  ├── User Service (Registration, Login, Password Reset)     │
│  ├── Client Management (CRUD, Secret Rotation)              │
│  ├── Token Operations (Introspect, Revoke, UserInfo)        │
│  └── JWT Token Service                                      │
├─────────────────────────────────────────────────────────────┤
│  Data Layer                                                 │
│  ├── PostgreSQL (Persistent User Data)                      │
│  ├── MySQL (OAuth2 Client Credentials)                      │
│  ├── Redis (Sessions, Tokens, Rate Limiting, Caching)       │
│  └── Hybrid Repository Pattern (Database + Cache)           │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure                                             │
│  ├── Configuration Management (YAML + Environment)          │
│  ├── Health Monitoring (Graceful Degradation)               │
│  ├── Structured Logging                                     │
│  └── Prometheus Metrics                                     │
└─────────────────────────────────────────────────────────────┘
```

### Storage Architecture

The service uses a hybrid storage architecture with graceful degradation:

```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   PostgreSQL    │     │     MySQL       │     │     Redis       │
│                 │     │                 │     │                 │
│  • User data    │     │ • OAuth2 clients│     │ • Auth codes    │
│  • Profiles     │     │ • Client secrets│     │ • Access tokens │
│  • Passwords    │     │   (bcrypt hash) │     │ • Refresh tokens│
│                 │     │ • Audit trail   │     │ • Sessions      │
│  [Optional]     │     │  [Optional]     │     │ • Rate limits   │
└─────────────────┘     └─────────────────┘     │ • Client cache  │
                                                │                 │
                                                │ [Required -     │
                                                │  In-memory      │
                                                │  fallback]      │
                                                └─────────────────┘
```

**Graceful Degradation:**

- **Healthy**: All three storage systems operational
- **Degraded**: Redis available, PostgreSQL or MySQL unavailable (200 status)
- **Unhealthy**: Redis unavailable (503 status)

**Client Repository Pattern:**

- MySQL as primary source of truth for OAuth2 clients
- Redis cache layer for performance (cache-aside pattern)
- Automatic fallback to Redis-only mode if MySQL unavailable

### Data Flow

#### Authorization Code Flow with PKCE

```text
Client App → Authorization Endpoint → Redis (Store Code) →
Token Endpoint → JWT Generation → Redis (Store Session) →
Access/Refresh Tokens → Client App
```

#### Client Credentials Flow

```text
Service → Token Endpoint → Client Validation →
JWT Generation → Redis (Rate Limiting) →
Access Token → Service
```

## Security Architecture

### Defense in Depth

1. **Network Layer**
   - CORS protection
   - Rate limiting per IP/client
   - Request size limits

2. **Application Layer**
   - PKCE enforcement (Authorization Code Flow)
   - Secure token generation (crypto/rand)
   - JWT signature validation
   - Client authentication

3. **Data Layer**
   - PostgreSQL and MySQL encryption in transit (optional TLS)
   - Redis encryption in transit (optional TLS)
   - Client secrets hashed with bcrypt (cost factor 12)
   - Token blacklisting for revoked tokens
   - Secure session management

### Token Security

- **Access Tokens**: JWT with RS256 signatures
- **Refresh Tokens**: Opaque, cryptographically secure
- **Authorization Codes**: Short-lived, single-use
- **PKCE**: Protects against authorization code interception

## Scalability Considerations

### Horizontal Scaling

- **Stateless Design**: All session data stored in Redis
- **Load Balancer Ready**: Health checks and graceful shutdown
- **Container Native**: Docker support with multi-stage builds

### Performance Optimizations

- **Database Connection Pooling**: PostgreSQL (pgx) and MySQL connection pools
- **Redis Pipelining**: Batch operations where possible
- **Client Caching**: Cache-aside pattern for OAuth2 clients
- **JWT Claims Caching**: Minimize token validation overhead
- **Prometheus Metrics**: Real-time performance monitoring

## Reliability Features

### High Availability

- **Health Checks**: Deep health validation with dependencies
- **Graceful Shutdown**: Proper connection cleanup
- **Circuit Breaker Pattern**: Redis connection resilience
- **Retry Logic**: Automatic recovery from transient failures

### Data Consistency

- **Atomic Operations**: Redis transactions for multi-step operations
- **Token Lifecycle Management**: Proper cleanup and expiration
- **Race Condition Prevention**: Redis-based locking mechanisms

## Monitoring and Observability

### Metrics

- **Request Metrics**: Rate, duration, status codes
- **Business Metrics**: Token issuance, validation rates
- **System Metrics**: Redis connection health, memory usage
- **Security Metrics**: Failed authentication attempts, rate limiting

### Logging

- **Structured Logging**: JSON format with contextual information
- **Security Events**: Authentication failures, suspicious activity
- **Audit Trail**: Token lifecycle events
- **Performance Logs**: Slow queries, high-latency operations

## Integration Patterns

### Microservices Integration

- **Service-to-Service Auth**: Client Credentials Flow
- **API Gateway Integration**: Token validation endpoints
- **Event-Driven Architecture**: Redis pub/sub for token events

### Client Applications

- **Web Applications**: Authorization Code Flow with PKCE
- **Mobile Applications**: Secure token storage recommendations
- **Single Page Applications**: PKCE flow implementation
- **Backend Services**: Client Credentials Flow implementation
