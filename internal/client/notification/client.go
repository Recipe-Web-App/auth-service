package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/client"
	"github.com/sirupsen/logrus"
)

// Client provides methods for interacting with the notification service.
type Client struct {
	*client.OAuth2Client // Embedded - inherits all OAuth2Client methods

	logger *logrus.Logger
}

// NewClient creates a new notification service client.
// It embeds the provided OAuth2Client for authenticated requests.
//
// Parameters:
//   - oauth2Client: OAuth2-enabled HTTP client
//   - logger: Structured logger for notification operations
func NewClient(
	oauth2Client *client.OAuth2Client,
	logger *logrus.Logger,
) *Client {
	return &Client{
		OAuth2Client: oauth2Client,
		logger:       logger,
	}
}

// SendPasswordReset sends a password reset notification to a user.
// This is a fire-and-forget operation - errors are logged but not returned to maintain
// flow continuity. The notification service queues the email asynchronously.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - req: Password reset request with recipient ID, reset token, and expiry
//
// Returns the notification response with queued notification IDs, or error if request fails.
func (c *Client) SendPasswordReset(
	ctx context.Context,
	req *PasswordResetRequest,
) (*BatchNotificationResponse, error) {
	c.logger.WithFields(logrus.Fields{
		"recipient_count": len(req.RecipientIDs),
		"expiry_hours":    req.ExpiryHours,
	}).Debug("Sending password reset notification")

	resp, err := c.DoWithAuth(ctx, http.MethodPost, "/notifications/password-reset", req)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to send password reset notification")
		return nil, fmt.Errorf("failed to send password reset notification: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusAccepted {
		errResp, parseErr := c.parseErrorResponse(resp)
		if parseErr != nil {
			return nil, fmt.Errorf("password reset notification failed with status %d", resp.StatusCode)
		}
		c.logger.WithFields(logrus.Fields{
			"status":  resp.StatusCode,
			"error":   errResp.Error,
			"message": errResp.Message,
		}).Error("Password reset notification request failed")
		return nil, fmt.Errorf("password reset notification failed: %s", errResp.Message)
	}

	// Parse success response
	var notifResp BatchNotificationResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&notifResp); decodeErr != nil {
		return nil, fmt.Errorf("failed to decode password reset response: %w", decodeErr)
	}

	c.logger.WithFields(logrus.Fields{
		"queued_count": notifResp.QueuedCount,
	}).Info("Password reset notification queued successfully")

	return &notifResp, nil
}

// SendWelcomeEmail sends a welcome email notification to one or more users.
// This is a fire-and-forget operation - errors are logged but not returned to maintain
// flow continuity. The notification service queues the emails asynchronously.
// Supports batch operations for bulk user imports.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - req: Welcome request with recipient IDs
//
// Returns the notification response with queued notification IDs, or error if request fails.
func (c *Client) SendWelcomeEmail(
	ctx context.Context,
	req *WelcomeRequest,
) (*BatchNotificationResponse, error) {
	c.logger.WithFields(logrus.Fields{
		"recipient_count": len(req.RecipientIDs),
	}).Debug("Sending welcome email notification")

	resp, err := c.DoWithAuth(ctx, http.MethodPost, "/notifications/welcome", req)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to send welcome email notification")
		return nil, fmt.Errorf("failed to send welcome email notification: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusAccepted {
		errResp, parseErr := c.parseErrorResponse(resp)
		if parseErr != nil {
			return nil, fmt.Errorf("welcome email notification failed with status %d", resp.StatusCode)
		}
		c.logger.WithFields(logrus.Fields{
			"status":  resp.StatusCode,
			"error":   errResp.Error,
			"message": errResp.Message,
		}).Error("Welcome email notification request failed")
		return nil, fmt.Errorf("welcome email notification failed: %s", errResp.Message)
	}

	// Parse success response
	var notifResp BatchNotificationResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&notifResp); decodeErr != nil {
		return nil, fmt.Errorf("failed to decode welcome email response: %w", decodeErr)
	}

	c.logger.WithFields(logrus.Fields{
		"queued_count": notifResp.QueuedCount,
	}).Info("Welcome email notification queued successfully")

	return &notifResp, nil
}

// parseErrorResponse parses an error response from the notification service.
func (c *Client) parseErrorResponse(resp *http.Response) (*ErrorResponse, error) {
	var errResp ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return nil, fmt.Errorf("failed to decode error response: %w", err)
	}
	return &errResp, nil
}
