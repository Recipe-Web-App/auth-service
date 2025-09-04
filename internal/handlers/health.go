package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/constants"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/database"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/redis"
)

const (
	// HealthCheckTimeout is the default timeout for health check operations.
	HealthCheckTimeout = 5 * time.Second
	// MinJWTSecretLength is the minimum required length for JWT secret in health checks.
	MinJWTSecretLength = 32
)

// HealthHandler provides health check and monitoring endpoints.
type HealthHandler struct {
	config    *config.Config
	store     redis.Store
	dbMgr     *database.Manager
	logger    *logrus.Logger
	metrics   *Metrics
	startTime time.Time
}

// HealthStatus represents the health status of a component.
type HealthStatus string

const (
	// StatusHealthy indicates the component is healthy.
	StatusHealthy HealthStatus = "healthy"
	// StatusUnhealthy indicates the component is unhealthy.
	StatusUnhealthy HealthStatus = "unhealthy"
	// StatusDegraded indicates the component has degraded performance.
	StatusDegraded HealthStatus = "degraded"
)

// HealthResponse represents the overall health check response.
type HealthResponse struct {
	Status     HealthStatus               `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version,omitempty"`
	Uptime     string                     `json:"uptime,omitempty"`
	Components map[string]ComponentHealth `json:"components,omitempty"`
	Details    map[string]interface{}     `json:"details,omitempty"`
}

// ComponentHealth represents the health of an individual component.
type ComponentHealth struct {
	Status       HealthStatus `json:"status"`
	Message      string       `json:"message,omitempty"`
	LastChecked  time.Time    `json:"last_checked"`
	ResponseTime string       `json:"response_time,omitempty"`
}

// ReadinessResponse represents the readiness check response.
type ReadinessResponse struct {
	Ready      bool                       `json:"ready"`
	Timestamp  time.Time                  `json:"timestamp"`
	Components map[string]ComponentHealth `json:"components,omitempty"`
}

// Metrics holds Prometheus metrics for monitoring.
type Metrics struct {
	// HTTP metrics
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPResponseSize    *prometheus.HistogramVec

	// OAuth2 metrics
	OAuth2TokensIssued  *prometheus.CounterVec
	OAuth2TokensRevoked *prometheus.CounterVec
	OAuth2AuthRequests  *prometheus.CounterVec
	OAuth2Errors        *prometheus.CounterVec

	// System metrics
	RedisOperations  *prometheus.CounterVec
	RedisConnections prometheus.Gauge

	// Health metrics
	HealthChecksTotal     *prometheus.CounterVec
	ComponentHealthStatus *prometheus.GaugeVec
}

// NewHealthHandler creates a new health check handler.
func NewHealthHandler(
	cfg *config.Config,
	store redis.Store,
	dbMgr *database.Manager,
	logger *logrus.Logger,
) *HealthHandler {
	metrics := NewMetrics()
	prometheus.MustRegister(
		metrics.HTTPRequestsTotal,
		metrics.HTTPRequestDuration,
		metrics.HTTPResponseSize,
		metrics.OAuth2TokensIssued,
		metrics.OAuth2TokensRevoked,
		metrics.OAuth2AuthRequests,
		metrics.OAuth2Errors,
		metrics.RedisOperations,
		metrics.RedisConnections,
		metrics.HealthChecksTotal,
		metrics.ComponentHealthStatus,
	)

	return &HealthHandler{
		config:    cfg,
		store:     store,
		dbMgr:     dbMgr,
		logger:    logger,
		metrics:   metrics,
		startTime: time.Now(),
	}
}

// NewMetrics creates and returns Prometheus metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status_code"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		HTTPResponseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_http_response_size_bytes",
				Help:    "HTTP response size in bytes",
				Buckets: []float64{0, 100, 500, 1000, 5000, 10000, 50000},
			},
			[]string{"method", "path"},
		),
		OAuth2TokensIssued: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_oauth2_tokens_issued_total",
				Help: "Total number of OAuth2 tokens issued",
			},
			[]string{"grant_type", "client_id"},
		),
		OAuth2TokensRevoked: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_oauth2_tokens_revoked_total",
				Help: "Total number of OAuth2 tokens revoked",
			},
			[]string{"token_type", "client_id"},
		),
		OAuth2AuthRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_oauth2_authorization_requests_total",
				Help: "Total number of OAuth2 authorization requests",
			},
			[]string{"client_id", "status"},
		),
		OAuth2Errors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_oauth2_errors_total",
				Help: "Total number of OAuth2 errors",
			},
			[]string{"error_code", "endpoint"},
		),
		RedisOperations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_redis_operations_total",
				Help: "Total number of Redis operations",
			},
			[]string{"operation", "status"},
		),
		RedisConnections: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "auth_redis_connections",
				Help: "Number of active Redis connections",
			},
		),
		HealthChecksTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_health_checks_total",
				Help: "Total number of health checks",
			},
			[]string{"endpoint", "status"},
		),
		ComponentHealthStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "auth_component_health_status",
				Help: "Health status of service components (1=healthy, 0=unhealthy)",
			},
			[]string{"component"},
		),
	}
}

// RegisterRoutes registers health check and monitoring endpoints.
func (h *HealthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/health/live", h.Liveness)
	mux.HandleFunc("/health/ready", h.Readiness)
	mux.Handle("/metrics", promhttp.Handler())
}

// Health provides a comprehensive health check including all components.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	h.logger.Debug("Processing health check request")

	// Check all components
	components := make(map[string]ComponentHealth)
	overallStatus := StatusHealthy

	// Check Redis storage backend (critical for OAuth2)
	redisHealth := h.checkStorage(ctx)
	components["redis"] = redisHealth
	if redisHealth.Status != StatusHealthy {
		overallStatus = StatusUnhealthy
	}

	// Check database (optional, degrades service when unavailable)
	databaseHealth := h.checkDatabase(ctx)
	components["database"] = databaseHealth
	if databaseHealth.Status != StatusHealthy && overallStatus == StatusHealthy {
		overallStatus = StatusDegraded
	}

	// Check configuration
	configHealth := h.checkConfiguration()
	components["configuration"] = configHealth
	if configHealth.Status != StatusHealthy && overallStatus == StatusHealthy {
		overallStatus = StatusDegraded
	}

	// Update Prometheus metrics
	statusLabel := string(overallStatus)
	h.metrics.HealthChecksTotal.WithLabelValues("health", statusLabel).Inc()

	for component, health := range components {
		healthValue := float64(0)
		if health.Status == StatusHealthy {
			healthValue = 1
		}
		h.metrics.ComponentHealthStatus.WithLabelValues(component).Set(healthValue)
	}

	response := HealthResponse{
		Status:     overallStatus,
		Timestamp:  time.Now(),
		Version:    getVersion(),
		Uptime:     time.Since(h.startTime).String(),
		Components: components,
		Details: map[string]interface{}{
			"check_duration": time.Since(start).String(),
		},
	}

	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	switch overallStatus {
	case StatusHealthy:
		statusCode = http.StatusOK
	case StatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	case StatusDegraded:
		statusCode = http.StatusOK // Still return 200 for degraded
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode health response")
	}

	h.logger.WithFields(logrus.Fields{
		"status":   overallStatus,
		"duration": time.Since(start).String(),
	}).Debug("Health check completed")
}

// Liveness provides a simple liveness check that returns 200 if the service is alive.
// This is used by Kubernetes to determine if the pod should be restarted.
func (h *HealthHandler) Liveness(w http.ResponseWriter, _ *http.Request) {
	h.metrics.HealthChecksTotal.WithLabelValues("liveness", "healthy").Inc()

	response := map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now(),
		"uptime":    time.Since(h.startTime).String(),
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode liveness response")
	}
}

// Readiness checks if the service is ready to receive traffic.
// This is used by Kubernetes to determine if the pod should receive requests.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	h.logger.Debug("Processing readiness check")

	components := make(map[string]ComponentHealth)
	ready := true

	// Check Redis connectivity (required for readiness)
	redisHealth := h.checkStorage(ctx)
	components["redis"] = redisHealth
	if redisHealth.Status != StatusHealthy {
		ready = false
	}

	// Check database connectivity (optional - service can run without it)
	databaseHealth := h.checkDatabase(ctx)
	components["database"] = databaseHealth
	// Database being down doesn't affect readiness, only degrades functionality

	// Update metrics
	statusLabel := "ready"
	if !ready {
		statusLabel = "not_ready"
	}
	h.metrics.HealthChecksTotal.WithLabelValues("readiness", statusLabel).Inc()

	response := ReadinessResponse{
		Ready:      ready,
		Timestamp:  time.Now(),
		Components: components,
	}

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode readiness response")
	}

	h.logger.WithFields(logrus.Fields{
		"ready":    ready,
		"duration": time.Since(start).String(),
	}).Debug("Readiness check completed")
}

// checkStorage checks storage backend connectivity and performance.
func (h *HealthHandler) checkStorage(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Create a context with timeout for the health check
	checkCtx, cancel := context.WithTimeout(ctx, HealthCheckTimeout)
	defer cancel()

	err := h.store.Ping(checkCtx)
	duration := time.Since(start)

	// Determine storage type based on the store implementation
	storageType := h.getStorageType()

	if err != nil {
		h.logger.WithError(err).Warn("Storage health check failed")
		return ComponentHealth{
			Status:       StatusUnhealthy,
			Message:      storageType + " connection failed: " + err.Error(),
			LastChecked:  time.Now(),
			ResponseTime: duration.String(),
		}
	}

	// Check if response time is acceptable (warn if > 1s for Redis, always healthy for memory)
	status := StatusHealthy
	message := storageType + " is healthy"

	// Only check response time for Redis (memory store should always be fast)
	if storageType == "Redis" && duration > time.Second {
		status = StatusDegraded
		message = "Redis response time is slow"
	}

	return ComponentHealth{
		Status:       status,
		Message:      message,
		LastChecked:  time.Now(),
		ResponseTime: duration.String(),
	}
}

// checkDatabase checks PostgreSQL database connectivity.
func (h *HealthHandler) checkDatabase(ctx context.Context) ComponentHealth {
	start := time.Now()

	// If database manager is not configured, return healthy (not required)
	if h.dbMgr == nil {
		return ComponentHealth{
			Status:      StatusHealthy,
			Message:     "Database not configured (optional)",
			LastChecked: time.Now(),
		}
	}

	// Create a context with timeout for the health check
	checkCtx, cancel := context.WithTimeout(ctx, HealthCheckTimeout)
	defer cancel()

	err := h.dbMgr.Ping(checkCtx)
	duration := time.Since(start)

	if err != nil {
		h.logger.WithError(err).Debug("Database health check failed")
		return ComponentHealth{
			Status:       StatusUnhealthy,
			Message:      "PostgreSQL connection failed: " + err.Error(),
			LastChecked:  time.Now(),
			ResponseTime: duration.String(),
		}
	}

	// Check if database is marked as available by the manager
	if !h.dbMgr.IsAvailable() {
		return ComponentHealth{
			Status:       StatusUnhealthy,
			Message:      "Database marked as unavailable",
			LastChecked:  time.Now(),
			ResponseTime: duration.String(),
		}
	}

	// Check response time
	status := StatusHealthy
	message := "PostgreSQL is healthy"

	if duration > 2*time.Second {
		status = StatusDegraded
		message = "PostgreSQL response time is slow"
	}

	return ComponentHealth{
		Status:       status,
		Message:      message,
		LastChecked:  time.Now(),
		ResponseTime: duration.String(),
	}
}

// getStorageType determines the type of storage backend being used.
func (h *HealthHandler) getStorageType() string {
	// Use type assertion to determine the storage type
	switch h.store.(type) {
	case *redis.Client:
		return "Redis"
	case *redis.MemoryStore:
		return "In-Memory"
	default:
		return "Unknown"
	}
}

// checkConfiguration validates critical configuration values.
func (h *HealthHandler) checkConfiguration() ComponentHealth {
	var issues []string

	// Check JWT secret
	if len(h.config.JWT.Secret) < MinJWTSecretLength {
		issues = append(issues, "JWT secret is too short")
	}

	// Check token expiry settings
	if h.config.JWT.AccessTokenExpiry < time.Minute {
		issues = append(issues, "Access token expiry is too short")
	}

	if h.config.JWT.RefreshTokenExpiry < time.Hour {
		issues = append(issues, "Refresh token expiry is too short")
	}

	status := StatusHealthy
	message := "Configuration is valid"

	if len(issues) > 0 {
		status = StatusDegraded
		message = "Configuration issues: " + strings.Join(issues, ", ")
	}

	return ComponentHealth{
		Status:      status,
		Message:     message,
		LastChecked: time.Now(),
	}
}

// getVersion returns the service version (would typically come from build info).
func getVersion() string {
	// In a real deployment, this would be injected at build time
	return "1.0.0"
}
