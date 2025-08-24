package models

import (
	"fmt"
	"net/http"
)

// OAuth2Error represents a standard OAuth2 error response as defined in RFC 6749.
// It implements the error interface and provides methods for building error responses
// with state and description information.
type OAuth2Error struct {
	// Code is the OAuth2 error code (e.g., "invalid_request", "invalid_client").
	Code string `json:"error"`
	// Description provides additional human-readable error information.
	Description string `json:"error_description,omitempty"`
	// URI is a reference to a web page with error information.
	URI string `json:"error_uri,omitempty"`
	// State is the client-provided state parameter for CSRF protection.
	State string `json:"state,omitempty"`
	// StatusCode is the HTTP status code to return (excluded from JSON).
	StatusCode int `json:"-"`
}

// NewInvalidRequest creates a new OAuth2Error with the "invalid_request" error code
// and the provided description. This error indicates that the request is missing
// a required parameter, includes an invalid parameter value, includes a parameter
// more than once, or is otherwise malformed. Returns HTTP 400 Bad Request.
func NewInvalidRequest(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "invalid_request",
		Description: description,
		StatusCode:  http.StatusBadRequest,
	}
}

// NewInvalidClient creates a new OAuth2Error with the "invalid_client" error code
// and the provided description. This error indicates that client authentication
// failed (e.g., unknown client, no client authentication included, or unsupported
// authentication method). Returns HTTP 401 Unauthorized.
func NewInvalidClient(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "invalid_client",
		Description: description,
		StatusCode:  http.StatusUnauthorized,
	}
}

// NewInvalidGrant creates a new OAuth2Error with the "invalid_grant" error code
// and the provided description. This error indicates that the provided authorization
// grant (e.g., authorization code, resource owner credentials) or refresh token is
// invalid, expired, revoked, does not match the redirection URI used in the
// authorization request, or was issued to another client. Returns HTTP 400 Bad Request.
func NewInvalidGrant(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "invalid_grant",
		Description: description,
		StatusCode:  http.StatusBadRequest,
	}
}

// NewInvalidScope creates a new OAuth2Error with the "invalid_scope" error code
// and the provided description. This error indicates that the requested scope is
// invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
// Returns HTTP 400 Bad Request.
func NewInvalidScope(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "invalid_scope",
		Description: description,
		StatusCode:  http.StatusBadRequest,
	}
}

// NewServerError creates a new OAuth2Error with the "server_error" error code
// and the provided description. This error indicates that the authorization server
// encountered an unexpected condition that prevented it from fulfilling the request.
// Returns HTTP 500 Internal Server Error.
func NewServerError(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "server_error",
		Description: description,
		StatusCode:  http.StatusInternalServerError,
	}
}

// Error returns a string representation of the OAuth2 error.
// It implements the error interface.
func (e *OAuth2Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// WithState sets the state parameter on the OAuth2Error and returns the error.
// The state parameter is used for CSRF protection in OAuth2 flows and should
// match the state parameter sent in the original authorization request.
// This method modifies the error in place and returns the same instance for chaining.
func (e *OAuth2Error) WithState(state string) *OAuth2Error {
	e.State = state
	return e
}

// WithDescription sets the error_description field on the OAuth2Error and returns the error.
// The description provides additional human-readable information about the error
// that can be displayed to the client or end-user.
// This method modifies the error in place and returns the same instance for chaining.
func (e *OAuth2Error) WithDescription(description string) *OAuth2Error {
	e.Description = description
	return e
}

var (
	// ErrInvalidRequest indicates that the request is missing a required parameter,
	// includes an invalid parameter value, includes a parameter more than once,
	// or is otherwise malformed. Returns HTTP 400 Bad Request.
	ErrInvalidRequest = &OAuth2Error{
		Code:       "invalid_request",
		StatusCode: http.StatusBadRequest,
	}

	// ErrInvalidClient indicates that client authentication failed (e.g., unknown client,
	// no client authentication included, or unsupported authentication method).
	// Returns HTTP 401 Unauthorized.
	ErrInvalidClient = &OAuth2Error{
		Code:       "invalid_client",
		StatusCode: http.StatusUnauthorized,
	}

	// ErrInvalidGrant indicates that the provided authorization grant (e.g., authorization
	// code, resource owner credentials) or refresh token is invalid, expired, revoked,
	// does not match the redirection URI used in the authorization request, or was
	// issued to another client. Returns HTTP 400 Bad Request.
	ErrInvalidGrant = &OAuth2Error{
		Code:       "invalid_grant",
		StatusCode: http.StatusBadRequest,
	}

	// ErrUnauthorizedClient indicates that the authenticated client is not authorized
	// to use this authorization grant type. Returns HTTP 401 Unauthorized.
	ErrUnauthorizedClient = &OAuth2Error{
		Code:       "unauthorized_client",
		StatusCode: http.StatusUnauthorized,
	}

	// ErrUnsupportedGrantType indicates that the authorization grant type is not
	// supported by the authorization server. Returns HTTP 400 Bad Request.
	ErrUnsupportedGrantType = &OAuth2Error{
		Code:       "unsupported_grant_type",
		StatusCode: http.StatusBadRequest,
	}

	// ErrInvalidScope indicates that the requested scope is invalid, unknown,
	// malformed, or exceeds the scope granted by the resource owner.
	// Returns HTTP 400 Bad Request.
	ErrInvalidScope = &OAuth2Error{
		Code:       "invalid_scope",
		StatusCode: http.StatusBadRequest,
	}

	// ErrAccessDenied indicates that the resource owner or authorization server
	// denied the request. Returns HTTP 403 Forbidden.
	ErrAccessDenied = &OAuth2Error{
		Code:       "access_denied",
		StatusCode: http.StatusForbidden,
	}

	// ErrUnsupportedResponseType indicates that the authorization server does not
	// support obtaining an authorization code using this method.
	// Returns HTTP 400 Bad Request.
	ErrUnsupportedResponseType = &OAuth2Error{
		Code:       "unsupported_response_type",
		StatusCode: http.StatusBadRequest,
	}

	// ErrServerError indicates that the authorization server encountered an
	// unexpected condition that prevented it from fulfilling the request.
	// Returns HTTP 500 Internal Server Error.
	ErrServerError = &OAuth2Error{
		Code:       "server_error",
		StatusCode: http.StatusInternalServerError,
	}

	// ErrTemporarilyUnavailable indicates that the authorization server is currently
	// unable to handle the request due to a temporary overloading or maintenance
	// of the server. Returns HTTP 503 Service Unavailable.
	ErrTemporarilyUnavailable = &OAuth2Error{
		Code:       "temporarily_unavailable",
		StatusCode: http.StatusServiceUnavailable,
	}
)

// ValidationError represents a single field validation error.
// It contains the field name that failed validation and a human-readable
// message describing the validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error returns a string representation of the validation error in the format
// "field: message". It implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a slice of ValidationError that represents multiple
// field validation errors. It implements the error interface and provides
// methods for handling collections of validation errors.
type ValidationErrors []ValidationError

// Error returns a string representation of the validation errors.
// If there are no errors, it returns "validation failed".
// If there is one error, it returns that error's message.
// If there are multiple errors, it returns a summary with the count.
// It implements the error interface.
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "validation failed"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("validation failed with %d errors", len(e))
}

// HasErrors returns true if there are one or more validation errors in the collection.
// This is a convenience method to check if validation failed without needing to
// check the length of the slice directly.
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}
