#!/usr/bin/env node

/**
 * OAuth2 Client Credentials Flow Example for Node.js
 * Demonstrates service-to-service authentication using OAuth2
 */

const axios = require('axios');
const qs = require('querystring');

class OAuthClient {
    constructor(clientId, clientSecret, authUrl) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authUrl = authUrl;
        this.httpClient = axios.create({
            timeout: 30000,
            headers: {
                'User-Agent': 'Recipe-Web-App-OAuth-Client/1.0'
            }
        });
        this.token = null;
        this.tokenExpiry = null;
    }

    /**
     * Get access token using client credentials flow
     * @param {string[]} scopes - Requested scopes
     * @returns {Promise<Object>} Token response
     */
    async getAccessToken(scopes = ['read', 'write']) {
        // Check if we have a valid cached token
        if (this.token && new Date() < this.tokenExpiry) {
            return this.token;
        }

        try {
            // Prepare form data
            const data = {
                grant_type: 'client_credentials',
                client_id: this.clientId,
                client_secret: this.clientSecret,
                scope: scopes.join(' ')
            };

            // Make token request
            const response = await this.httpClient.post(
                `${this.authUrl}/api/v1/auth/oauth/token`,
                qs.stringify(data),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            const tokenResponse = response.data;

            // Cache the token with a 60-second buffer before expiry
            this.token = tokenResponse;
            this.tokenExpiry = new Date(Date.now() + (tokenResponse.expires_in - 60) * 1000);

            return tokenResponse;
        } catch (error) {
            if (error.response) {
                throw new Error(`Token request failed: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            }
            throw new Error(`Token request failed: ${error.message}`);
        }
    }

    /**
     * Make an authenticated HTTP request
     * @param {string} method - HTTP method
     * @param {string} url - Request URL
     * @param {Object} data - Request body (optional)
     * @param {Object} options - Additional axios options
     * @returns {Promise<Object>} Response data
     */
    async makeAuthenticatedRequest(method, url, data = null, options = {}) {
        // Ensure we have a valid access token
        const token = await this.getAccessToken();

        try {
            const config = {
                method,
                url,
                headers: {
                    'Authorization': `${token.token_type} ${token.access_token}`,
                    ...options.headers
                },
                ...options
            };

            if (data) {
                config.data = data;
                config.headers['Content-Type'] = config.headers['Content-Type'] || 'application/json';
            }

            const response = await this.httpClient(config);
            return response.data;
        } catch (error) {
            if (error.response) {
                throw new Error(`Request failed: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            }
            throw new Error(`Request failed: ${error.message}`);
        }
    }

    /**
     * Introspect a token to validate it
     * @param {string} token - Token to introspect
     * @returns {Promise<Object>} Introspection response
     */
    async introspectToken(token) {
        try {
            const data = {
                token,
                client_id: this.clientId,
                client_secret: this.clientSecret
            };

            const response = await this.httpClient.post(
                `${this.authUrl}/api/v1/auth/oauth/introspect`,
                qs.stringify(data),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            return response.data;
        } catch (error) {
            if (error.response) {
                throw new Error(`Introspection failed: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            }
            throw new Error(`Introspection failed: ${error.message}`);
        }
    }

    /**
     * Revoke a token
     * @param {string} token - Token to revoke
     * @returns {Promise<void>}
     */
    async revokeToken(token) {
        try {
            const data = {
                token,
                client_id: this.clientId,
                client_secret: this.clientSecret
            };

            await this.httpClient.post(
                `${this.authUrl}/api/v1/auth/oauth/revoke`,
                qs.stringify(data),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );
        } catch (error) {
            if (error.response) {
                throw new Error(`Revocation failed: ${error.response.status} - ${JSON.stringify(error.response.data)}`);
            }
            throw new Error(`Revocation failed: ${error.message}`);
        }
    }
}

// Example usage
async function main() {
    // Get configuration from environment variables
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    const authUrl = process.env.AUTH_URL || 'http://localhost:8080';

    if (!clientId || !clientSecret) {
        console.error('❌ CLIENT_ID and CLIENT_SECRET environment variables must be set');
        process.exit(1);
    }

    console.log('OAuth2 Client Credentials Flow Example (Node.js)');
    console.log('==================================================\n');

    try {
        // Create OAuth client
        const client = new OAuthClient(clientId, clientSecret, authUrl);

        // Example 1: Get access token
        console.log('1. Getting access token...');
        const token = await client.getAccessToken(['read', 'write', 'profile']);

        console.log('✅ Access token obtained successfully!');
        console.log(`   Token Type: ${token.token_type}`);
        console.log(`   Expires In: ${token.expires_in} seconds`);
        console.log(`   Scope: ${token.scope || 'N/A'}`);
        console.log(`   Access Token: ${token.access_token.substring(0, 20)}...\n`);

        // Example 2: Introspect the token
        console.log('2. Introspecting token...');
        const introspection = await client.introspectToken(token.access_token);

        console.log('✅ Token introspection successful!');
        console.log(`   Active: ${introspection.active}`);
        console.log(`   Client ID: ${introspection.client_id}`);
        console.log(`   Scope: ${introspection.scope || 'N/A'}`);
        if (introspection.exp) {
            console.log(`   Expires At: ${new Date(introspection.exp * 1000).toISOString()}`);
        }
        console.log();

        // Example 3: Make authenticated request to health endpoint
        console.log('3. Making authenticated request...');
        const healthResponse = await client.makeAuthenticatedRequest(
            'GET',
            `${authUrl}/api/v1/auth/health`
        );

        console.log('✅ Authenticated request successful!');
        console.log(`   Health Status: ${healthResponse.status}`);
        console.log(`   Service: ${healthResponse.service}`);
        console.log(`   Version: ${healthResponse.version || 'N/A'}\n`);

        // Example 4: Demonstrate token caching
        console.log('4. Demonstrating token caching...');
        console.log('   Getting token again (should use cached token)...');

        const start = Date.now();
        const token2 = await client.getAccessToken(['read', 'write']);
        const duration = Date.now() - start;

        console.log('✅ Token retrieved from cache!');
        console.log(`   Duration: ${duration}ms (should be very fast)`);
        console.log(`   Same token: ${token.access_token === token2.access_token}\n`);

        // Example 5: Error handling
        console.log('5. Demonstrating error handling...');
        try {
            await client.makeAuthenticatedRequest('GET', `${authUrl}/api/v1/auth/nonexistent`);
        } catch (error) {
            console.log('✅ Error handling works correctly!');
            console.log(`   Error: ${error.message}\n`);
        }

        console.log('🎉 OAuth2 Client Credentials Flow Example Complete!\n');

        console.log('Usage in your Node.js service:');
        console.log('1. npm install axios');
        console.log('2. Set CLIENT_ID and CLIENT_SECRET environment variables');
        console.log('3. Create an OAuthClient instance');
        console.log('4. Use getAccessToken() to obtain tokens');
        console.log('5. Use makeAuthenticatedRequest() for API calls');
        console.log('6. The client handles token caching and renewal automatically');

    } catch (error) {
        console.error('❌ Example failed:', error.message);
        process.exit(1);
    }
}

// Export the class for use in other modules
module.exports = { OAuthClient };

// Run the example if this file is executed directly
if (require.main === module) {
    main().catch(console.error);
}
