// Package middleware provides HTTP middleware components for the OAuth2 service
// including rate limiting, CORS, logging, security headers, and request validation.
package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/constants"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen/recipe-web-app/auth-service/pkg/logger"
)

const (
	// NanosecondsToMilliseconds conversion factor.
	NanosecondsToMilliseconds = 1000000
	// HTTPClientError minimum status code (4xx).
	HTTPClientError = 400
	// HTTPServerError minimum status code (5xx).
	HTTPServerError = 500
	// RequestIDLength is the length of generated request IDs.
	RequestIDLength = 8
)

// contextKey is an unexported type for keys stored in context to avoid collisions.
type contextKey string

// requestIDKey is the context key used to store the request ID.
const requestIDKey contextKey = "request_id"

// Stack holds all middleware dependencies and provides
// methods to create HTTP middleware handlers.
type Stack struct {
	config *config.Config
	store  redis.Store
	logger *logrus.Logger
}

// NewStack creates a new middleware stack with the provided dependencies.
func NewStack(cfg *config.Config, store redis.Store, logger *logrus.Logger) *Stack {
	return &Stack{
		config: cfg,
		store:  store,
		logger: logger,
	}
}

// Chain applies multiple middleware functions to an HTTP handler.
func (m *Stack) Chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := range middleware {
		h = middleware[len(middleware)-1-i](h)
	}
	return h
}

// RequestLogger logs HTTP requests with structured logging including
// request details, response status, and processing duration.
func (m *Stack) RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate request ID and store it in the typed context key
		requestID := generateRequestID()
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)

		// Also store the correlation ID using the logger's correlation ID system
		ctx = logger.SetCorrelationID(ctx, requestID)
		r = r.WithContext(ctx)

		// Wrap response writer to capture the status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Add request ID to response headers
		wrapped.Header().Set(constants.HeaderXRequestID, requestID)

		// Process request
		next.ServeHTTP(wrapped, r)

		// Skip logging for health check endpoints
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth/health") {
			return
		}

		// Log request details using correlation ID
		duration := time.Since(start)

		logEntry := logger.WithCorrelationID(r.Context(), m.logger)
		fields := logrus.Fields{
			"method":         r.Method,
			"path":           r.URL.Path,
			"query":          r.URL.RawQuery,
			"status":         wrapped.statusCode,
			"duration":       duration.String(),
			"duration_ms":    duration.Milliseconds(),
			"remote_addr":    getClientIP(r),
			"user_agent":     r.UserAgent(),
			"content_length": r.ContentLength,
		}

		if referer := r.Header.Get(constants.HeaderReferer); referer != "" {
			fields["referer"] = referer
		}

		level := logrus.InfoLevel
		if wrapped.statusCode >= HTTPClientError {
			level = logrus.WarnLevel
		}
		if wrapped.statusCode >= HTTPServerError {
			level = logrus.ErrorLevel
		}

		logEntry.WithFields(fields).Log(level, "HTTP request processed")
	})
}

// RateLimit implements Redis-based rate limiting per client IP address.
// It uses a sliding window algorithm with configurable requests per second and burst limits.
func (m *Stack) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		clientIP := getClientIP(r)

		// Allow requests from trusted proxies without rate limiting
		if m.isTrustedProxy(clientIP) {
			next.ServeHTTP(w, r)
			return
		}

		// Create rate limit key
		rateLimitKey := "client:" + clientIP

		// Check rate limit
		allowed, remaining, err := m.store.CheckRateLimit(
			ctx,
			rateLimitKey,
			m.config.Security.RateLimitRPS,
			m.config.Security.RateLimitWindow,
		)

		if err != nil {
			m.logger.WithError(err).Error("Failed to check rate limit")
			// Allow request on error to avoid blocking legitimate traffic
			next.ServeHTTP(w, r)
			return
		}

		// Set rate limit headers
		w.Header().Set("X-Ratelimit-Limit", string(rune(m.config.Security.RateLimitRPS)))
		w.Header().Set("X-Ratelimit-Remaining", string(rune(remaining)))
		w.Header().Set("X-Ratelimit-Window", m.config.Security.RateLimitWindow.String())

		if !allowed {
			m.logger.WithFields(logrus.Fields{
				"client_ip": clientIP,
				"path":      r.URL.Path,
				"method":    r.Method,
			}).Warn("Rate limit exceeded")

			w.Header().Set("Retry-After", m.config.Security.RateLimitWindow.String())
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CORS handles Cross-Origin Resource Sharing headers based on configuration.
func (m *Stack) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.setCORSHeaders(w, r)

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// setCORSHeaders sets the CORS headers based on the configured security settings.
// Assumes MaxAge is expressed as an integer number of seconds. If your
// configuration uses time.Duration, update this helper to convert appropriately
// (e.g. int(m.config.Security.MaxAge/time.Second)).
func (m *Stack) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// Check if origin is allowed
	if origin != "" && m.isOriginAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	} else if len(m.config.Security.AllowedOrigins) == 1 && m.config.Security.AllowedOrigins[0] == "*" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	// Set other CORS headers
	if len(m.config.Security.AllowedMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(m.config.Security.AllowedMethods, ", "))
	}

	if len(m.config.Security.AllowedHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(m.config.Security.AllowedHeaders, ", "))
	}

	if len(m.config.Security.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(m.config.Security.ExposedHeaders, ", "))
	}

	if m.config.Security.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if m.config.Security.MaxAge > 0 {
		// Format Max-Age as decimal seconds.
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(m.config.Security.MaxAge))
	}
}

// SecurityHeaders adds security-related HTTP headers to responses.
func (m *Stack) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy for OAuth2 endpoints
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"connect-src 'self'; " +
			"font-src 'self'; " +
			"object-src 'none'; " +
			"media-src 'self'; " +
			"frame-src 'none'; " +
			"base-uri 'self';"
		w.Header().Set("Content-Security-Policy", csp)

		// HSTS header for HTTPS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// Recovery recovers from panics and logs them while returning a proper error response.
func (m *Stack) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logEntry := logger.WithCorrelationID(r.Context(), m.logger)

				logEntry.WithFields(logrus.Fields{
					"method": r.Method,
					"path":   r.URL.Path,
					"panic":  err,
				}).Error("Panic recovered")

				// Return generic error to client
				w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(
					`{"error": "internal_server_error", ` +
						`"error_description": "An unexpected error occurred"}`,
				))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// ContentType validates Content-Type headers for POST requests.
func (m *Stack) ContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only validate Content-Type for POST requests with body
		if r.Method == http.MethodPost && r.ContentLength > 0 {
			contentType := r.Header.Get(constants.HeaderContentType)

			// Allow application/x-www-form-urlencoded and application/json
			isForm := strings.Contains(contentType, constants.ContentTypeFormURLEncoded)
			isJSON := strings.Contains(contentType, constants.ContentTypeJSON)
			if !isForm && !isJSON {
				w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
				w.WriteHeader(http.StatusUnsupportedMediaType)
				body := `{"error": "unsupported_media_type", "error_description": "Content-Type must be application/x-www-form-urlencoded or application/json"}`
				_, _ = w.Write([]byte(body))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter

	statusCode int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getClientIP extracts the real client IP address from various headers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (load balancers, proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header (nginx, some proxies)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// isTrustedProxy checks if the IP address is in the trusted proxies list.
func (m *Stack) isTrustedProxy(ip string) bool {
	for _, trustedIP := range m.config.Security.TrustedProxies {
		if ip == trustedIP {
			return true
		}
	}
	return false
}

// isOriginAllowed checks if an origin is allowed for CORS.
func (m *Stack) isOriginAllowed(origin string) bool {
	for _, allowedOrigin := range m.config.Security.AllowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
	}
	return false
}

// generateRequestID generates a unique request ID for tracing.
func generateRequestID() string {
	// Simple request ID generation (in production, consider using UUID or similar)
	return time.Now().Format("20060102150405") + "-" + randomString(RequestIDLength)
}

// randomString generates a random string of the specified length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}
