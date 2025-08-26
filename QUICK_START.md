# Quick Start: Client Registration for Backend Services

This guide shows you the fastest way to get OAuth2 client IDs for your 9 backend services.

## 🚀 Quick Setup (5 minutes)

### 1. Start the Auth Service

```bash
# Set up environment (if not done already)
make env-setup

# Start the service
make run
```

### 2. Register All Backend Services

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

### 3. Get Your Client Credentials

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

### 4. Test a Client

```bash
# Get an access token
make get-token CLIENT_ID=$API_GATEWAY_CLIENT_ID CLIENT_SECRET=$API_GATEWAY_CLIENT_SECRET

# The token is saved to .access_token for testing
cat .access_token
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

That's it! You now have OAuth2 client credentials for all your backend services. 🎉
