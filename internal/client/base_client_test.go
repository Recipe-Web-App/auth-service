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

func TestBaseClient_Do_GET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		resp := map[string]string{"status": "ok"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	bc := client.NewBaseClient(server.URL, 10*time.Second, logger)

	ctx := context.Background()
	resp, err := bc.Do(ctx, http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestBaseClient_Do_POST(t *testing.T) {
	type testRequest struct {
		Name string `json:"name"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		var req testRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		if req.Name != "test" {
			t.Errorf("Expected name 'test', got '%s'", req.Name)
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	bc := client.NewBaseClient(server.URL, 10*time.Second, logger)

	ctx := context.Background()
	reqBody := testRequest{Name: "test"}
	resp, err := bc.Do(ctx, http.MethodPost, "/create", reqBody)
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}
}

func TestBaseClient_BaseURL(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	expectedURL := "http://example.com/api/v1"
	const timeoutSeconds = 10
	bc := client.NewBaseClient(expectedURL, timeoutSeconds*time.Second, logger)

	if bc.BaseURL() != expectedURL {
		t.Errorf("Expected baseURL '%s', got '%s'", expectedURL, bc.BaseURL())
	}
}

func TestBaseClient_ParseErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		errResp := map[string]interface{}{
			"error":   "bad_request",
			"message": "Invalid request parameters",
			"detail":  "Field 'name' is required",
		}
		json.NewEncoder(w).Encode(errResp)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	bc := client.NewBaseClient(server.URL, 10*time.Second, logger)

	ctx := context.Background()
	resp, err := bc.Do(ctx, http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}

	err = bc.ParseErrorResponse(resp)
	if err == nil {
		t.Fatal("Expected error from ParseErrorResponse(), got nil")
	}

	expectedMsg := "HTTP 400"
	if len(err.Error()) < len(expectedMsg) || err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("Expected error to start with '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestBaseClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	bc := client.NewBaseClient(server.URL, 10*time.Second, logger)

	// Create context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := bc.Do(ctx, http.MethodGet, "/test", nil)
	if err == nil {
		t.Fatal("Expected error from cancelled context, got nil")
	}
}
