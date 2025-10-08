package models_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	models "github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

func TestOAuth2ErrorError(t *testing.T) {
	tests := []struct {
		name        string
		error       *models.OAuth2Error
		expectedMsg string
	}{
		{
			name: "error_with_description",
			error: &models.OAuth2Error{
				Code:        "invalid_request",
				Description: "Missing required parameter",
			},
			expectedMsg: "invalid_request: Missing required parameter",
		},
		{
			name: "error_without_description",
			error: &models.OAuth2Error{
				Code: "invalid_client",
			},
			expectedMsg: "invalid_client",
		},
		{
			name: "error_with_empty_description",
			error: &models.OAuth2Error{
				Code:        "invalid_grant",
				Description: "",
			},
			expectedMsg: "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.error.Error()
			assert.Equal(t, tt.expectedMsg, msg)
		})
	}
}

func TestOAuth2ErrorWithState(t *testing.T) {
	err := &models.OAuth2Error{
		Code:        "invalid_request",
		Description: "Test error",
	}

	result := err.WithState("test-state")

	assert.Equal(t, "test-state", result.State)
	assert.Same(t, err, result) // Should return the same instance for chaining
}

func TestOAuth2ErrorWithDescription(t *testing.T) {
	err := &models.OAuth2Error{
		Code: "invalid_request",
	}

	result := err.WithDescription("New description")

	assert.Equal(t, "New description", result.Description)
	assert.Same(t, err, result) // Should return the same instance for chaining
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name           string
		error          *models.OAuth2Error
		expectedCode   string
		expectedStatus int
	}{
		{
			name:           "invalid_request",
			error:          models.ErrInvalidRequest,
			expectedCode:   "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid_client",
			error:          models.ErrInvalidClient,
			expectedCode:   "invalid_client",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid_grant",
			error:          models.ErrInvalidGrant,
			expectedCode:   "invalid_grant",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unauthorized_client",
			error:          models.ErrUnauthorizedClient,
			expectedCode:   "unauthorized_client",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "unsupported_grant_type",
			error:          models.ErrUnsupportedGrantType,
			expectedCode:   "unsupported_grant_type",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid_scope",
			error:          models.ErrInvalidScope,
			expectedCode:   "invalid_scope",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "access_denied",
			error:          models.ErrAccessDenied,
			expectedCode:   "access_denied",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "unsupported_response_type",
			error:          models.ErrUnsupportedResponseType,
			expectedCode:   "unsupported_response_type",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "server_error",
			error:          models.ErrServerError,
			expectedCode:   "server_error",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "temporarily_unavailable",
			error:          models.ErrTemporarilyUnavailable,
			expectedCode:   "temporarily_unavailable",
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedCode, tt.error.Code)
			assert.Equal(t, tt.expectedStatus, tt.error.StatusCode)
		})
	}
}

func TestNewErrorFunctions(t *testing.T) {
	tests := []struct {
		name           string
		createFunc     func(string) *models.OAuth2Error
		expectedCode   string
		expectedStatus int
		description    string
	}{
		{
			name:           "new_invalid_request",
			createFunc:     models.NewInvalidRequest,
			expectedCode:   "invalid_request",
			expectedStatus: http.StatusBadRequest,
			description:    "Test invalid request",
		},
		{
			name:           "new_invalid_client",
			createFunc:     models.NewInvalidClient,
			expectedCode:   "invalid_client",
			expectedStatus: http.StatusUnauthorized,
			description:    "Test invalid client",
		},
		{
			name:           "new_invalid_grant",
			createFunc:     models.NewInvalidGrant,
			expectedCode:   "invalid_grant",
			expectedStatus: http.StatusBadRequest,
			description:    "Test invalid grant",
		},
		{
			name:           "new_invalid_scope",
			createFunc:     models.NewInvalidScope,
			expectedCode:   "invalid_scope",
			expectedStatus: http.StatusBadRequest,
			description:    "Test invalid scope",
		},
		{
			name:           "new_server_error",
			createFunc:     models.NewServerError,
			expectedCode:   "server_error",
			expectedStatus: http.StatusInternalServerError,
			description:    "Test server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.createFunc(tt.description)

			assert.Equal(t, tt.expectedCode, err.Code)
			assert.Equal(t, tt.expectedStatus, err.StatusCode)
			assert.Equal(t, tt.description, err.Description)
		})
	}
}

func TestValidationErrorError(t *testing.T) {
	err := &models.ValidationError{
		Field:   "username",
		Message: "is required",
	}

	msg := err.Error()
	assert.Equal(t, "username: is required", msg)
}

func TestValidationErrorsError(t *testing.T) {
	tests := []struct {
		name        string
		errors      models.ValidationErrors
		expectedMsg string
	}{
		{
			name:        "empty_errors",
			errors:      models.ValidationErrors{},
			expectedMsg: "validation failed",
		},
		{
			name: "single_error",
			errors: models.ValidationErrors{
				{Field: "username", Message: "is required"},
			},
			expectedMsg: "username: is required",
		},
		{
			name: "multiple_errors",
			errors: models.ValidationErrors{
				{Field: "username", Message: "is required"},
				{Field: "password", Message: "is too short"},
			},
			expectedMsg: "validation failed with 2 errors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.errors.Error()
			assert.Equal(t, tt.expectedMsg, msg)
		})
	}
}

func TestValidationErrorsHasErrors(t *testing.T) {
	tests := []struct {
		name     string
		errors   models.ValidationErrors
		expected bool
	}{
		{
			name:     "no_errors",
			errors:   models.ValidationErrors{},
			expected: false,
		},
		{
			name: "has_errors",
			errors: models.ValidationErrors{
				{Field: "username", Message: "is required"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errors.HasErrors()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorChaining(t *testing.T) {
	// Test method chaining
	err := models.ErrInvalidRequest.WithDescription("Missing parameter").WithState("test-state")

	assert.Equal(t, "invalid_request", err.Code)
	assert.Equal(t, "Missing parameter", err.Description)
	assert.Equal(t, "test-state", err.State)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
}

func TestErrorImplementsErrorInterface(_ *testing.T) {
	var err error = &models.OAuth2Error{Code: "test"}

	// This should compile, proving that OAuth2Error implements error interface
	_ = err.Error()
}

func TestValidationErrorImplementsErrorInterface(_ *testing.T) {
	var err error = &models.ValidationError{Field: "test", Message: "message"}

	// This should compile, proving that ValidationError implements error interface
	_ = err.Error()
}

func TestValidationErrorsImplementsErrorInterface(_ *testing.T) {
	var err error = models.ValidationErrors{}

	// This should compile, proving that ValidationErrors implements error interface
	_ = err.Error()
}
