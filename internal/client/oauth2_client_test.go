package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/client"
	"github.com/sirupsen/logrus"
)

func TestOAuth2Client_DoWithAuth(t *testing.T) {
	// Create token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"access_token": "test-oauth-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	// Create API server that checks for auth header
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-oauth-token" {
			t.Errorf("Expected 'Bearer test-oauth-token', got '%s'", authHeader)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := map[string]string{"status": "authenticated"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer apiServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create clients
	tokenManager := client.NewTokenManager("client-id", "client-secret", tokenServer.URL, logger)
	baseClient := client.NewBaseClient(apiServer.URL, 10*time.Second, logger)
	oauth2Client := client.NewOAuth2Client(baseClient, tokenManager)

	ctx := context.Background()

	resp, err := oauth2Client.DoWithAuth(ctx, http.MethodGet, "/protected", nil)
	if err != nil {
		t.Fatalf("DoWithAuth() failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestOAuth2Client_DoWithAuth_401Retry(t *testing.T) {
	requestCount := 0

	// Create token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"access_token": "refreshed-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	// Create API server that returns 401 first, then succeeds
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount == 1 {
			// First request - return 401
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Second request - succeed
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer refreshed-token" {
			t.Errorf("Expected refreshed token, got '%s'", authHeader)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer apiServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tokenManager := client.NewTokenManager("client-id", "client-secret", tokenServer.URL, logger)
	baseClient := client.NewBaseClient(apiServer.URL, 10*time.Second, logger)
	oauth2Client := client.NewOAuth2Client(baseClient, tokenManager)

	ctx := context.Background()

	resp, err := oauth2Client.DoWithAuth(ctx, http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("DoWithAuth() failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 after retry, got %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 API requests (initial + retry), got %d", requestCount)
	}
}

func TestOAuth2Client_InheritsBaseClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"access_token": "token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	baseURL := "http://example.com/api"
	tokenManager := client.NewTokenManager("id", "secret", tokenServer.URL, logger)
	baseClient := client.NewBaseClient(baseURL, 10*time.Second, logger)
	oauth2Client := client.NewOAuth2Client(baseClient, tokenManager)

	// Should inherit BaseURL() method
	if oauth2Client.BaseURL() != baseURL {
		t.Errorf("Expected baseURL '%s', got '%s'", baseURL, oauth2Client.BaseURL())
	}
}
