# Quick Start: Client Registration for Backend Services

This guide shows you the fastest way to get OAuth2 client IDs for your 9 backend services.

## 🚀 Quick Setup (5 minutes)

### 1. Start Dependencies (Optional)

```bash
# PostgreSQL (optional - for persistent user storage)
docker run -d --name postgres -p 5432:5432 \
  -e POSTGRES_DB=recipe_manager \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_password \
  postgres:15-alpine

# Redis (will use in-memory fallback if not available)
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

### 2. Start the Auth Service

```bash
# Set up environment (if not done already)
make env-setup

# Start the service (works without database - will show "degraded" status)
make run
```

### 3. Register All Backend Services

Choose one of these methods:

#### Option A: Shell Script (Recommended - creates .env file)

```bash
make register-clients
```

#### Option B: CLI Tool

```bash
make register-clients-cli
```

#### Option C: Auto-registration on startup

```bash
# Enable in .env.local
echo "CLIENT_AUTO_REGISTER_ENABLED=true" >> .env.local

# Restart service
make run
```

### 4. Get Your Client Credentials

After registration, your credentials will be in `.env.clients`:

```bash
# View all registered clients
cat .env.clients

# Source for easy access
source .env.clients
echo $RECIPE_SERVICE_CLIENT_ID
echo $USER_SERVICE_CLIENT_ID
# ... etc for all 9 services
```

### 5. Test a Client

```bash
# Get an access token
make get-token CLIENT_ID=$API_GATEWAY_CLIENT_ID CLIENT_SECRET=$API_GATEWAY_CLIENT_SECRET

# The token is saved to .access_token for testing
cat .access_token
```

### 6. Check Service Status

```bash
# Check overall health (should show "degraded" without database)
curl http://localhost:8080/api/v1/auth/health

# Example response with PostgreSQL unavailable:
# {
#   "status": "degraded",
#   "components": {
#     "redis": {"status": "healthy"},
#     "database": {"status": "unhealthy"},
#     "configuration": {"status": "healthy"}
#   }
# }
```

## 📖 Next Steps

- **Integration Examples**: See `examples/` directory for Go and Node.js client code
- **Full Documentation**: Read `docs/CLIENT_MANAGEMENT.md` for detailed instructions
- **API Reference**: Check `docs/API_REFERENCE.md` for OAuth2 endpoint details

## 🔧 Available Make Commands

```bash
make register-clients          # Register all services (shell script)
make register-clients-cli      # Register all services (CLI tool)
make get-token CLIENT_ID=<id> CLIENT_SECRET=<secret>  # Get access token
make client-manager-help       # Show CLI tool help
make build-client-manager      # Build the CLI tool
```

## 💡 Pro Tips

1. **Use shell script method** - Creates `.env.clients` file with all credentials
2. **Source the .env.clients file** in your other services to use the credentials
3. **The API Gateway client** supports all OAuth2 flows (authorization code, client credentials, refresh token)
4. **Other backend services** use client credentials flow for service-to-service auth
5. **Check the logs** when starting the auth service to see which clients were registered
6. **Database is optional** - Service works in Redis-only mode if PostgreSQL is unavailable
7. **Health status shows "degraded"** when database is down but service remains functional
8. **User management features** (register, login, password reset) require PostgreSQL to be available

## 📝 Configuration Note

The service uses a **hybrid configuration approach**:

- **`.env.local`** - Connection data and secrets (database hosts, passwords, JWT secret)
- **`configs/*.yaml`** - Operational settings (timeouts, pool sizes, rate limits, OAuth2 scopes, logging)

The `.env.local` file contains only connection information and secrets, while operational settings are managed
in YAML files (`configs/defaults.yaml`, `configs/local.yaml`, etc.). The `ENVIRONMENT` variable in `.env.local`
determines which YAML config to load.

That's it! You now have OAuth2 client credentials for all your backend services. 🎉
