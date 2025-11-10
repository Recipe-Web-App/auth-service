package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/client"
	"github.com/sirupsen/logrus"
)

func TestTokenManager_GetToken(t *testing.T) {
	// Create mock token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("Expected grant_type=client_credentials, got %s", r.FormValue("grant_type"))
		}

		// Return token response
		resp := map[string]interface{}{
			"access_token": "test-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "notification:admin",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

	tm := client.NewTokenManager(
		"test-client-id",
		"test-client-secret",
		server.URL,
		logger,
	)

	ctx := context.Background()

	// First call should fetch token
	token, err := tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() failed: %v", err)
	}

	if token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got '%s'", token)
	}
}

func TestTokenManager_GetToken_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		resp := map[string]interface{}{
			"access_token": "cached-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tm := client.NewTokenManager(
		"test-client-id",
		"test-client-secret",
		server.URL,
		logger,
	)

	ctx := context.Background()

	// First call - should fetch token
	token1, err := tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("First GetToken() failed: %v", err)
	}

	// Second call - should use cached token
	token2, err := tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("Second GetToken() failed: %v", err)
	}

	if token1 != token2 {
		t.Errorf("Expected same token, got different tokens")
	}

	if callCount != 1 {
		t.Errorf("Expected 1 token request, got %d", callCount)
	}
}

func TestTokenManager_InvalidateToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		resp := map[string]interface{}{
			"access_token": "token-refresh",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tm := client.NewTokenManager(
		"test-client-id",
		"test-client-secret",
		server.URL,
		logger,
	)

	ctx := context.Background()

	// Get initial token
	_, err := tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() failed: %v", err)
	}

	// Invalidate
	tm.InvalidateToken()

	// Next call should fetch new token
	_, err = tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("GetToken() after invalidate failed: %v", err)
	}

	if callCount != 2 {
		t.Errorf("Expected 2 token requests after invalidate, got %d", callCount)
	}
}

func TestTokenManager_ConcurrentAccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()

		// Simulate slow token endpoint
		time.Sleep(50 * time.Millisecond)

		resp := map[string]interface{}{
			"access_token": "concurrent-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tm := client.NewTokenManager(
		"test-client-id",
		"test-client-secret",
		server.URL,
		logger,
	)

	ctx := context.Background()

	// Launch multiple concurrent GetToken calls
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for range numGoroutines {
		go func() {
			defer wg.Done()
			_, err := tm.GetToken(ctx)
			if err != nil {
				t.Errorf("GetToken() failed: %v", err)
			}
		}()
	}

	wg.Wait()

	// Should only call token endpoint once despite concurrent requests
	mu.Lock()
	count := callCount
	mu.Unlock()

	if count != 1 {
		t.Errorf("Expected 1 token request with concurrent access, got %d", count)
	}
}

func TestTokenManager_ErrorHandling(t *testing.T) {
	// Server returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tm := client.NewTokenManager(
		"test-client-id",
		"test-client-secret",
		server.URL,
		logger,
	)

	ctx := context.Background()

	_, err := tm.GetToken(ctx)
	if err == nil {
		t.Fatal("Expected error from GetToken(), got nil")
	}
}
