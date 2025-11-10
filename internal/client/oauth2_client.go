package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// OAuth2Client extends BaseClient with OAuth2 authentication capabilities.
// It automatically injects bearer tokens for authenticated requests.
type OAuth2Client struct {
	*BaseClient // Embedded - inherits all BaseClient methods

	tokenManager TokenManager // Uses TokenManager for OAuth2 tokens
}

// NewOAuth2Client creates a new OAuth2-enabled HTTP client.
// It embeds the provided BaseClient and uses TokenManager for authentication.
//
// Parameters:
//   - baseClient: Base HTTP client for core operations
//   - tokenManager: Token manager for OAuth2 access tokens
func NewOAuth2Client(
	baseClient *BaseClient,
	tokenManager TokenManager,
) *OAuth2Client {
	return &OAuth2Client{
		BaseClient:   baseClient,
		tokenManager: tokenManager,
	}
}

// DoWithAuth executes an HTTP request with OAuth2 bearer token authentication.
// It automatically injects the access token from TokenManager.
// On 401 Unauthorized, it invalidates the token and retries once.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - method: HTTP method (GET, POST, PUT, DELETE, etc.)
//   - path: Path relative to baseURL
//   - body: Request body to be JSON-encoded (nil for GET requests)
//
// Returns the HTTP response. Caller is responsible for closing response body.
func (c *OAuth2Client) DoWithAuth(
	ctx context.Context,
	method string,
	path string,
	body interface{},
) (*http.Response, error) {
	// Get access token
	token, err := c.tokenManager.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Execute request with token
	resp, err := c.doWithToken(ctx, method, path, body, token)
	if err != nil {
		return nil, err
	}

	// If we get 401 Unauthorized, invalidate token and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close() // Explicitly ignore error on close before retry

		c.logger.Debug("Received 401 Unauthorized, invalidating token and retrying")
		c.tokenManager.InvalidateToken()

		// Get fresh token
		token, err = c.tokenManager.GetToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh access token: %w", err)
		}

		// Retry request
		resp, err = c.doWithToken(ctx, method, path, body, token)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// doWithToken executes an HTTP request with the provided bearer token.
func (c *OAuth2Client) doWithToken(
	ctx context.Context,
	method string,
	path string,
	body interface{},
	token string,
) (*http.Response, error) {
	url := c.baseURL + path

	// Marshal request body if provided
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	// Log request
	c.logger.WithFields(logrus.Fields{
		"method": method,
		"url":    url,
	}).Debug("Sending authenticated HTTP request")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"method": method,
			"url":    url,
			"error":  err,
		}).Error("Authenticated HTTP request failed")
		return nil, fmt.Errorf("authenticated HTTP request failed: %w", err)
	}

	// Log response
	c.logger.WithFields(logrus.Fields{
		"method": method,
		"url":    url,
		"status": resp.StatusCode,
	}).Debug("Received HTTP response for authenticated request")

	return resp, nil
}
