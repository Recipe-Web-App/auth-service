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
	return c.sendNotification(ctx, "/notifications/welcome", req, "welcome email", logrus.Fields{
		"recipient_count": len(req.RecipientIDs),
	})
}

// SendPasswordChanged sends a password changed security notification to one or more users.
// This is a fire-and-forget operation - errors are logged but not returned to maintain
// flow continuity. The notification service queues the emails asynchronously.
// Supports batch operations for bulk security events.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - req: Password changed request with recipient IDs
//
// Returns the notification response with queued notification IDs, or error if request fails.
func (c *Client) SendPasswordChanged(
	ctx context.Context,
	req *PasswordChangedRequest,
) (*BatchNotificationResponse, error) {
	return c.sendNotification(ctx, "/notifications/password-changed", req, "password changed", logrus.Fields{
		"recipient_count": len(req.RecipientIDs),
	})
}

// sendNotification is a helper method that handles the common notification sending logic.
// It sends a notification request to the specified endpoint and processes the response.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - endpoint: The notification endpoint path (e.g., "/notifications/welcome")
//   - reqBody: The request body to send
//   - notificationType: Human-readable notification type for logging (e.g., "welcome email")
//   - logFields: Additional fields to include in debug/error logs
//
// Returns the notification response with queued notification IDs, or error if request fails.
func (c *Client) sendNotification(
	ctx context.Context,
	endpoint string,
	reqBody interface{},
	notificationType string,
	logFields logrus.Fields,
) (*BatchNotificationResponse, error) {
	c.logger.WithFields(logFields).Debugf("Sending %s notification", notificationType)

	resp, err := c.DoWithAuth(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"error": err,
		}).Errorf("Failed to send %s notification", notificationType)
		return nil, fmt.Errorf("failed to send %s notification: %w", notificationType, err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusAccepted {
		errResp, parseErr := c.parseErrorResponse(resp)
		if parseErr != nil {
			return nil, fmt.Errorf("%s notification failed with status %d", notificationType, resp.StatusCode)
		}
		c.logger.WithFields(logrus.Fields{
			"status":  resp.StatusCode,
			"error":   errResp.Error,
			"message": errResp.Message,
		}).Errorf("%s notification request failed", notificationType)
		return nil, fmt.Errorf("%s notification failed: %s", notificationType, errResp.Message)
	}

	// Parse success response
	var notifResp BatchNotificationResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&notifResp); decodeErr != nil {
		return nil, fmt.Errorf("failed to decode %s response: %w", notificationType, decodeErr)
	}

	c.logger.WithFields(logrus.Fields{
		"queued_count": notifResp.QueuedCount,
	}).Infof("%s notification queued successfully", notificationType)

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
