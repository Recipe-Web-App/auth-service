// Package client provides HTTP client utilities for calling downstream services.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TokenManager manages OAuth2 access tokens with automatic refresh.
// It provides thread-safe token caching to avoid redundant token requests.
type TokenManager interface {
	// GetToken returns a valid access token, refreshing if necessary.
	GetToken(ctx context.Context) (string, error)
	// InvalidateToken forces a token refresh on the next GetToken call.
	InvalidateToken()
}

// tokenManager is the concrete implementation of TokenManager.
type tokenManager struct {
	mu           sync.RWMutex
	clientID     string
	clientSecret string
	tokenURL     string
	httpClient   *http.Client
	logger       *logrus.Logger

	// Cached token
	accessToken string
	expiresAt   time.Time
}

// tokenResponse represents the OAuth2 token response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// NewTokenManager creates a new TokenManager for managing OAuth2 access tokens.
// The token manager uses client credentials flow to obtain tokens and caches them
// until 5 minutes before expiry.
//
// Parameters:
//   - clientID: OAuth2 client identifier
//   - clientSecret: OAuth2 client secret
//   - tokenURL: Token endpoint URL (e.g., "http://localhost:8080/api/v1/auth/token")
//   - logger: Structured logger for token operations
func NewTokenManager(
	clientID string,
	clientSecret string,
	tokenURL string,
	logger *logrus.Logger,
) TokenManager {
	const defaultTimeoutSeconds = 10
	return &tokenManager{
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     tokenURL,
		httpClient: &http.Client{
			Timeout: defaultTimeoutSeconds * time.Second,
		},
		logger: logger,
	}
}

// GetToken returns a valid access token, refreshing if necessary.
// It uses a read lock for cached tokens and upgrades to write lock for refresh.
func (t *tokenManager) GetToken(ctx context.Context) (string, error) {
	// Check if we have a valid cached token
	t.mu.RLock()
	if t.accessToken != "" && time.Now().Before(t.expiresAt) {
		token := t.accessToken
		t.mu.RUnlock()
		return token, nil
	}
	t.mu.RUnlock()

	// Need to refresh - acquire write lock
	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if t.accessToken != "" && time.Now().Before(t.expiresAt) {
		return t.accessToken, nil
	}

	// Refresh the token
	return t.refreshToken(ctx)
}

// InvalidateToken forces the cached token to be refreshed on the next GetToken call.
func (t *tokenManager) InvalidateToken() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.accessToken = ""
	t.expiresAt = time.Time{}

	t.logger.Debug("Token invalidated, will refresh on next request")
}

// refreshToken obtains a new access token using client credentials flow.
// Caller must hold write lock.
func (t *tokenManager) refreshToken(ctx context.Context) (string, error) {
	t.logger.WithFields(logrus.Fields{
		"client_id": t.clientID,
		"token_url": t.tokenURL,
	}).Debug("Refreshing access token")

	// Prepare client credentials request
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", t.clientID)
	data.Set("client_secret", t.clientSecret)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		t.tokenURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	// Parse response
	var tokenResp tokenResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&tokenResp); decodeErr != nil {
		return "", fmt.Errorf("failed to decode token response: %w", decodeErr)
	}

	// Cache the token with 5-minute buffer before expiry
	const expiryBufferMinutes = 5
	expiryBuffer := expiryBufferMinutes * time.Minute
	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	if expiresIn > expiryBuffer {
		expiresIn -= expiryBuffer
	}

	t.accessToken = tokenResp.AccessToken
	t.expiresAt = time.Now().Add(expiresIn)

	t.logger.WithFields(logrus.Fields{
		"expires_in": tokenResp.ExpiresIn,
		"expires_at": t.expiresAt,
	}).Debug("Access token refreshed successfully")

	return t.accessToken, nil
}
