# OAuth2 Client Examples

This directory contains example implementations for integrating with the OAuth2 authentication service using different
programming languages and approaches.

## Examples Included

### 1. Go Client Example (`client-credentials-flow.go`)

A complete Go implementation demonstrating:

- Client credentials flow
- Token caching and automatic renewal
- Authenticated requests
- Token introspection
- Error handling

**Run the example:**

```bash
# Set your client credentials
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret" # pragma: allowlist secret
export AUTH_URL="http://localhost:8080"  # optional

# Run the example
go run examples/client-credentials-flow.go
```

### 2. Node.js Client Example (`client-credentials-flow.js`)

A comprehensive Node.js/JavaScript implementation with:

- Promise-based API using axios
- Token caching with expiry handling
- Comprehensive error handling
- Token introspection and revocation
- Reusable OAuthClient class

**Run the example:**

```bash
# Install dependencies
npm install axios

# Set your client credentials
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret" # pragma: allowlist secret
export AUTH_URL="http://localhost:8080"  # optional

# Run the example
node examples/client-credentials-flow.js
```

## Getting Client Credentials

Before running the examples, you need to register your client and get credentials:

### Option 1: Use the registration script

```bash
make register-clients
source .env.clients
export CLIENT_ID=$API_GATEWAY_CLIENT_ID
export CLIENT_SECRET=$API_GATEWAY_CLIENT_SECRET
```

### Option 2: Register a single client

```bash
./bin/client-manager -action register \
  -name "Example Client" \
  -redirects "http://localhost:8080/callback" \
  -scopes "read,write,profile" \
  -grants "client_credentials"
```

### Option 3: Use the shell script

```bash
./scripts/register-clients.sh
# Check the output for client credentials
```

## Common Integration Patterns

### 1. Service Initialization

**Go:**

```go
client := NewOAuthClient(
    os.Getenv("CLIENT_ID"),
    os.Getenv("CLIENT_SECRET"),
    "http://auth-service:8080"
)
```

**JavaScript:**

```javascript
const client = new OAuthClient(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  "http://auth-service:8080",
);
```

### 2. Making API Calls

**Go:**

```go
resp, err := client.MakeAuthenticatedRequest(
    "GET",
    "http://recipe-service:8080/api/recipes",
    nil
)
```

**JavaScript:**

```javascript
const recipes = await client.makeAuthenticatedRequest(
  "GET",
  "http://recipe-service:8080/api/recipes",
);
```

### 3. Token Management

Both examples handle token caching automatically:

- Tokens are cached until near expiry
- Automatic token renewal on expiry
- Thread-safe/async-safe token management

## Configuration Options

All examples support these environment variables:

- `CLIENT_ID` - Your OAuth2 client ID (required)
- `CLIENT_SECRET` - Your OAuth2 client secret (required)
- `AUTH_URL` - Auth service base URL (default: <http://localhost:8080>)

## Advanced Usage

### Custom Scopes

```go
// Go
token, err := client.GetAccessToken([]string{"read", "admin"})
```

```javascript
// JavaScript
const token = await client.getAccessToken(["read", "admin"]);
```

### Token Introspection

```go
// Go
introspection, err := client.IntrospectToken(accessToken)
```

```javascript
// JavaScript
const introspection = await client.introspectToken(accessToken);
```

### Error Handling

Both examples demonstrate proper error handling:

- Network errors
- Authentication failures
- Invalid responses
- Token expiry

## Testing Your Integration

1. Start the auth service:

   ```bash
   make run
   ```

2. Register your client:

   ```bash
   make register-clients
   ```

3. Set environment variables from `.env.clients`

4. Run the examples to test connectivity

## Production Considerations

1. **Environment Variables**: Store credentials securely
2. **HTTPS**: Always use HTTPS in production
3. **Token Storage**: Consider secure token storage for long-running services
4. **Error Handling**: Implement retry logic for network failures
5. **Monitoring**: Log authentication events for debugging
6. **Security**: Never log client secrets or access tokens

## Adding New Language Examples

To add examples for other languages:

1. Follow the same pattern as existing examples
2. Implement the `OAuthClient` class/interface
3. Include the same demonstration scenarios
4. Add documentation to this README
5. Update the main project documentation

The examples should demonstrate:

- Client credentials flow
- Token caching
- Authenticated requests
- Token introspection
- Error handling
- Usage instructions
