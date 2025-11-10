package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// BaseClient provides core HTTP client functionality for calling downstream services.
// It handles request/response marshaling, error parsing, and logging.
type BaseClient struct {
	httpClient *http.Client
	baseURL    string
	logger     *logrus.Logger
}

// NewBaseClient creates a new BaseClient for HTTP operations.
//
// Parameters:
//   - baseURL: Base URL for the service (e.g., "http://localhost:8000/api/v1/notification")
//   - timeout: HTTP request timeout duration
//   - logger: Structured logger for HTTP operations
func NewBaseClient(
	baseURL string,
	timeout time.Duration,
	logger *logrus.Logger,
) *BaseClient {
	return &BaseClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
		logger:  logger,
	}
}

// Do executes an HTTP request with JSON marshaling and error handling.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - method: HTTP method (GET, POST, PUT, DELETE, etc.)
//   - path: Path relative to baseURL (e.g., "/password-reset")
//   - body: Request body to be JSON-encoded (nil for GET requests)
//
// Returns the HTTP response. Caller is responsible for closing response body.
func (c *BaseClient) Do(
	ctx context.Context,
	method string,
	path string,
	body interface{},
) (*http.Response, error) {
	url := c.baseURL + path

	// Marshal request body if provided
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	// Log request
	c.logger.WithFields(logrus.Fields{
		"method": method,
		"url":    url,
	}).Debug("Sending HTTP request")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"method": method,
			"url":    url,
			"error":  err,
		}).Error("HTTP request failed")
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Log response
	c.logger.WithFields(logrus.Fields{
		"method": method,
		"url":    url,
		"status": resp.StatusCode,
	}).Debug("Received HTTP response")

	return resp, nil
}

// BaseURL returns the configured base URL for this client.
func (c *BaseClient) BaseURL() string {
	return c.baseURL
}

// ParseErrorResponse parses an error response body into a structured error.
// This is a helper method that can be used by clients that embed BaseClient.
func (c *BaseClient) ParseErrorResponse(resp *http.Response) error {
	defer resp.Body.Close()

	var errResp struct {
		Error   string                 `json:"error"`
		Message string                 `json:"message"`
		Detail  string                 `json:"detail,omitempty"`
		Errors  map[string]interface{} `json:"errors,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		// If we can't parse the error response, return a generic error
		return fmt.Errorf("HTTP %d: failed to parse error response", resp.StatusCode)
	}

	// Build error message
	errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, errResp.Message)
	if errResp.Detail != "" {
		errMsg += fmt.Sprintf(" - %s", errResp.Detail)
	}

	return fmt.Errorf("%s", errMsg)
}
