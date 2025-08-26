// Package main demonstrates the OAuth2 client credentials flow
// for service-to-service authentication in Go.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// TokenResponse represents the OAuth2 token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// OAuthClient handles OAuth2 client credentials flow.
type OAuthClient struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	HTTPClient   *http.Client
	token        *TokenResponse
	tokenExpiry  time.Time
}

// NewOAuthClient creates a new OAuth2 client.
func NewOAuthClient(clientID, clientSecret, authURL string) *OAuthClient {
	return &OAuthClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      authURL,
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// GetAccessToken obtains an access token using client credentials flow.
func (c *OAuthClient) GetAccessToken(scopes []string) (*TokenResponse, error) {
	// Check if we have a valid cached token
	if c.token != nil && time.Now().Before(c.tokenExpiry) {
		return c.token, nil
	}

	// Prepare form data for token request
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.ClientSecret)

	if len(scopes) > 0 {
		scopeStr := ""
		for i, scope := range scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += scope
		}
		data.Set("scope", scopeStr)
	}

	// Make token request
	resp, err := c.HTTPClient.PostForm(c.AuthURL+"/api/v1/auth/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Cache the token with a buffer before expiry
	c.token = &tokenResp
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return &tokenResp, nil
}

// MakeAuthenticatedRequest makes an authenticated HTTP request using the access token.
func (c *OAuthClient) MakeAuthenticatedRequest(method, url string, body interface{}) (*http.Response, error) {
	// Ensure we have a valid access token
	token, err := c.GetAccessToken([]string{"read", "write"})
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	// Create the request
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Make the request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

// IntrospectToken validates a token using the introspection endpoint.
func (c *OAuthClient) IntrospectToken(token string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.ClientSecret)

	resp, err := c.HTTPClient.PostForm(c.AuthURL+"/api/v1/auth/oauth/introspect", data)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection failed with status %d: %s", resp.StatusCode, string(body))
	}

	var introspection map[string]interface{}
	if err := json.Unmarshal(body, &introspection); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return introspection, nil
}

func main() {
	// Get configuration from environment variables
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	authURL := os.Getenv("AUTH_URL")

	if clientID == "" || clientSecret == "" {
		log.Fatal("CLIENT_ID and CLIENT_SECRET environment variables must be set")
	}

	if authURL == "" {
		authURL = "http://localhost:8080"
	}

	fmt.Printf("OAuth2 Client Credentials Flow Example\n")
	fmt.Printf("======================================\n\n")

	// Create OAuth client
	client := NewOAuthClient(clientID, clientSecret, authURL)

	// Example 1: Get access token
	fmt.Println("1. Getting access token...")
	token, err := client.GetAccessToken([]string{"read", "write", "profile"})
	if err != nil {
		log.Fatalf("Failed to get access token: %v", err)
	}

	fmt.Printf("✅ Access token obtained successfully!\n")
	fmt.Printf("   Token Type: %s\n", token.TokenType)
	fmt.Printf("   Expires In: %d seconds\n", token.ExpiresIn)
	fmt.Printf("   Scope: %s\n", token.Scope)
	fmt.Printf("   Access Token: %s...\n\n", token.AccessToken[:20])

	// Example 2: Introspect the token
	fmt.Println("2. Introspecting token...")
	introspection, err := client.IntrospectToken(token.AccessToken)
	if err != nil {
		log.Fatalf("Failed to introspect token: %v", err)
	}

	fmt.Printf("✅ Token introspection successful!\n")
	fmt.Printf("   Active: %v\n", introspection["active"])
	fmt.Printf("   Client ID: %s\n", introspection["client_id"])
	fmt.Printf("   Scope: %s\n", introspection["scope"])
	if exp, ok := introspection["exp"].(float64); ok {
		fmt.Printf("   Expires At: %s\n", time.Unix(int64(exp), 0))
	}
	fmt.Println()

	// Example 3: Make authenticated request to health endpoint
	fmt.Println("3. Making authenticated request...")
	resp, err := client.MakeAuthenticatedRequest("GET", authURL+"/api/v1/auth/health", nil)
	if err != nil {
		log.Fatalf("Failed to make authenticated request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	fmt.Printf("✅ Authenticated request successful!\n")
	fmt.Printf("   Status: %s\n", resp.Status)
	fmt.Printf("   Response: %s\n\n", string(body))

	// Example 4: Demonstrate token caching
	fmt.Println("4. Demonstrating token caching...")
	fmt.Println("   Getting token again (should use cached token)...")

	start := time.Now()
	token2, err := client.GetAccessToken([]string{"read", "write"})
	duration := time.Since(start)

	if err != nil {
		log.Fatalf("Failed to get cached token: %v", err)
	}

	fmt.Printf("✅ Token retrieved from cache!\n")
	fmt.Printf("   Duration: %v (should be very fast)\n", duration)
	fmt.Printf("   Same token: %t\n\n", token.AccessToken == token2.AccessToken)

	fmt.Println("🎉 OAuth2 Client Credentials Flow Example Complete!")
	fmt.Println("\nUsage in your service:")
	fmt.Println("1. Store CLIENT_ID and CLIENT_SECRET as environment variables")
	fmt.Println("2. Create an OAuthClient instance")
	fmt.Println("3. Use GetAccessToken() to obtain tokens")
	fmt.Println("4. Use MakeAuthenticatedRequest() for API calls")
	fmt.Println("5. The client handles token caching and renewal automatically")
}
