package notification_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/client"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/client/notification"
	"github.com/sirupsen/logrus"
)

func setupNotificationClient(t *testing.T, handler http.HandlerFunc) (*notification.Client, *httptest.Server) {
	// Create token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"access_token": "notif-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))

	// Create notification API server
	apiServer := httptest.NewServer(handler)

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tokenManager := client.NewTokenManager("client-id", "client-secret", tokenServer.URL, logger)
	baseClient := client.NewBaseClient(apiServer.URL, 10*time.Second, logger)
	oauth2Client := client.NewOAuth2Client(baseClient, tokenManager)
	notifClient := notification.NewClient(oauth2Client, logger)

	// Note: We're only returning the API server, not the token server
	// The token server will be cleaned up when the test ends
	t.Cleanup(func() {
		apiServer.Close()
		tokenServer.Close()
	})

	return notifClient, apiServer
}

func TestNotificationClient_SendPasswordReset(t *testing.T) {
	notifClient, _ := setupNotificationClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if r.URL.Path != "/notifications/password-reset" {
			t.Errorf("Expected path /notifications/password-reset, got %s", r.URL.Path)
		}

		// Verify request body
		var req notification.PasswordResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		if len(req.RecipientIDs) != 1 {
			t.Errorf("Expected 1 recipient, got %d", len(req.RecipientIDs))
		}

		if req.ResetToken != "reset-token-123" {
			t.Errorf("Expected reset token 'reset-token-123', got '%s'", req.ResetToken)
		}

		if req.ExpiryHours != 24 {
			t.Errorf("Expected expiry 24 hours, got %d", req.ExpiryHours)
		}

		// Return success response
		w.WriteHeader(http.StatusAccepted)
		resp := notification.BatchNotificationResponse{
			Notifications: []notification.Mapping{
				{
					NotificationID: "notif-id-1",
					RecipientID:    req.RecipientIDs[0],
				},
			},
			QueuedCount: 1,
			Message:     "Notifications queued successfully",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	})

	ctx := context.Background()
	req := &notification.PasswordResetRequest{
		RecipientIDs: []string{"user-id-1"},
		ResetToken:   "reset-token-123",
		ExpiryHours:  24,
	}

	resp, err := notifClient.SendPasswordReset(ctx, req)
	if err != nil {
		t.Fatalf("SendPasswordReset() failed: %v", err)
	}

	if resp.QueuedCount != 1 {
		t.Errorf("Expected queued count 1, got %d", resp.QueuedCount)
	}

	if len(resp.Notifications) != 1 {
		t.Errorf("Expected 1 notification mapping, got %d", len(resp.Notifications))
	}
}

func TestNotificationClient_SendWelcomeEmail(t *testing.T) {
	notifClient, _ := setupNotificationClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if r.URL.Path != "/notifications/welcome" {
			t.Errorf("Expected path /notifications/welcome, got %s", r.URL.Path)
		}

		// Verify request body
		var req notification.WelcomeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		if len(req.RecipientIDs) != 2 {
			t.Errorf("Expected 2 recipients, got %d", len(req.RecipientIDs))
		}

		// Return success response
		w.WriteHeader(http.StatusAccepted)
		resp := notification.BatchNotificationResponse{
			Notifications: []notification.Mapping{
				{NotificationID: "notif-1", RecipientID: req.RecipientIDs[0]},
				{NotificationID: "notif-2", RecipientID: req.RecipientIDs[1]},
			},
			QueuedCount: 2,
			Message:     "Notifications queued successfully",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	})

	ctx := context.Background()
	req := &notification.WelcomeRequest{
		RecipientIDs: []string{"user-1", "user-2"},
	}

	resp, err := notifClient.SendWelcomeEmail(ctx, req)
	if err != nil {
		t.Fatalf("SendWelcomeEmail() failed: %v", err)
	}

	if resp.QueuedCount != 2 {
		t.Errorf("Expected queued count 2, got %d", resp.QueuedCount)
	}

	if len(resp.Notifications) != 2 {
		t.Errorf("Expected 2 notification mappings, got %d", len(resp.Notifications))
	}
}

func TestNotificationClient_SendPasswordChanged(t *testing.T) {
	notifClient, _ := setupNotificationClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if r.URL.Path != "/notifications/password-changed" {
			t.Errorf("Expected path /notifications/password-changed, got %s", r.URL.Path)
		}

		// Verify request body
		var req notification.PasswordChangedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		if len(req.RecipientIDs) != 1 {
			t.Errorf("Expected 1 recipient, got %d", len(req.RecipientIDs))
		}

		// Return success response
		w.WriteHeader(http.StatusAccepted)
		resp := notification.BatchNotificationResponse{
			Notifications: []notification.Mapping{
				{
					NotificationID: "notif-id-1",
					RecipientID:    req.RecipientIDs[0],
				},
			},
			QueuedCount: 1,
			Message:     "Notifications queued successfully",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	})

	ctx := context.Background()
	req := &notification.PasswordChangedRequest{
		RecipientIDs: []string{"user-id-1"},
	}

	resp, err := notifClient.SendPasswordChanged(ctx, req)
	if err != nil {
		t.Fatalf("SendPasswordChanged() failed: %v", err)
	}

	if resp.QueuedCount != 1 {
		t.Errorf("Expected queued count 1, got %d", resp.QueuedCount)
	}

	if len(resp.Notifications) != 1 {
		t.Errorf("Expected 1 notification mapping, got %d", len(resp.Notifications))
	}
}

func TestNotificationClient_SendPasswordChanged_Error(t *testing.T) {
	notifClient, _ := setupNotificationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		errResp := notification.ErrorResponse{
			Error:   "forbidden",
			Message: "Requires service-to-service authentication",
			Detail:  "Password change notifications require service-to-service authentication",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			t.Fatalf("Failed to encode error response: %v", err)
		}
	})

	ctx := context.Background()
	req := &notification.PasswordChangedRequest{
		RecipientIDs: []string{"user-id-1"},
	}

	_, err := notifClient.SendPasswordChanged(ctx, req)
	if err == nil {
		t.Fatal("Expected error from SendPasswordChanged(), got nil")
	}

	expectedMsg := "Requires service-to-service authentication"
	if len(err.Error()) < len(expectedMsg) {
		t.Errorf("Error message too short, got: %s", err.Error())
	}
}

func TestNotificationClient_SendPasswordReset_Error(t *testing.T) {
	notifClient, _ := setupNotificationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		errResp := notification.ErrorResponse{
			Error:   "bad_request",
			Message: "Invalid reset token",
			Detail:  "Reset token must be at least 20 characters",
		}
		if err := json.NewEncoder(w).Encode(errResp); err != nil {
			t.Fatalf("Failed to encode error response: %v", err)
		}
	})

	ctx := context.Background()
	req := &notification.PasswordResetRequest{
		RecipientIDs: []string{"user-id-1"},
		ResetToken:   "short",
		ExpiryHours:  24,
	}

	_, err := notifClient.SendPasswordReset(ctx, req)
	if err == nil {
		t.Fatal("Expected error from SendPasswordReset(), got nil")
	}

	expectedMsg := "Invalid reset token"
	if len(err.Error()) < len(expectedMsg) {
		t.Errorf("Error message too short, got: %s", err.Error())
	}
}

func TestNotificationClient_InheritsOAuth2Client(t *testing.T) {
	notifClient, server := setupNotificationClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Should inherit BaseURL() method from embedded OAuth2Client -> BaseClient
	if notifClient.BaseURL() != server.URL {
		t.Errorf("Expected baseURL '%s', got '%s'", server.URL, notifClient.BaseURL())
	}
}
