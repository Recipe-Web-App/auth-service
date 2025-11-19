// Package notification provides client for the notification service API.
package notification

// PasswordResetRequest represents a password reset notification request.
type PasswordResetRequest struct {
	// RecipientIDs contains the user ID to send the password reset to (must be exactly 1).
	RecipientIDs []string `json:"recipient_ids"`
	// ResetToken is the secure password reset token (minimum 20 characters).
	ResetToken string `json:"reset_token"`
	// ExpiryHours is the number of hours until the token expires (1-72).
	ExpiryHours int `json:"expiry_hours"`
}

// WelcomeRequest represents a welcome email notification request.
type WelcomeRequest struct {
	// RecipientIDs contains one or more user IDs to send welcome emails to.
	// Supports batch operations for bulk user imports.
	RecipientIDs []string `json:"recipient_ids"`
}

// PasswordChangedRequest represents a password changed notification request.
type PasswordChangedRequest struct {
	// RecipientIDs contains one or more user IDs to send password changed notifications to.
	// Supports batch operations for security events.
	RecipientIDs []string `json:"recipient_ids"`
}

// BatchNotificationResponse represents the response from batch notification endpoints.
type BatchNotificationResponse struct {
	// Notifications contains the mapping of notification IDs to recipient IDs.
	Notifications []Mapping `json:"notifications"`
	// QueuedCount is the number of notifications successfully queued.
	QueuedCount int `json:"queued_count"`
	// Message is a human-readable status message.
	Message string `json:"message"`
}

// Mapping maps a notification ID to its recipient.
type Mapping struct {
	// NotificationID is the UUID of the created notification.
	NotificationID string `json:"notification_id"`
	// RecipientID is the UUID of the recipient user.
	RecipientID string `json:"recipient_id"`
}

// ErrorResponse represents an error response from the notification service.
type ErrorResponse struct {
	// Error is the error code/type.
	Error string `json:"error"`
	// Message is a human-readable error message.
	Message string `json:"message"`
	// Detail provides additional error details (optional).
	Detail string `json:"detail,omitempty"`
	// Errors contains field-specific validation errors (optional).
	Errors map[string]interface{} `json:"errors,omitempty"`
}
