// Package handlers provides HTTP handlers for the auth service endpoints.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/constants"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

// AdminHandler handles admin cache and session management endpoints.
type AdminHandler struct {
	adminSvc auth.AdminService
	config   *config.Config
	logger   *logrus.Logger
}

// NewAdminHandler creates a new admin handler instance with the provided dependencies.
func NewAdminHandler(adminSvc auth.AdminService, cfg *config.Config, logger *logrus.Logger) *AdminHandler {
	return &AdminHandler{
		adminSvc: adminSvc,
		config:   cfg,
		logger:   logger,
	}
}

// RegisterRoutes registers admin routes on the provided router.
// Note: The router should already have admin auth middleware applied.
func (h *AdminHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/cache/sessions/stats", h.GetSessionStats).Methods(http.MethodGet)
}

// GetSessionStats handles GET /admin/cache/sessions/stats
// Returns statistics about current sessions in the cache.
//
// Query Parameters:
//   - includeTtlPolicy: Include breakdown of sessions by TTL policy (default: false)
//   - includeTtlDistribution: Include histogram of remaining TTLs (default: false)
//   - includeTtlSummary: Include aggregate TTL statistics (default: false)
//
// Responses:
//   - 200: Session statistics retrieved successfully
//   - 401: Unauthorized (handled by middleware)
//   - 403: Forbidden (handled by middleware)
//   - 500: Internal server error
func (h *AdminHandler) GetSessionStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing session stats request")

	// Parse query parameters
	req := &models.SessionStatsRequest{
		IncludeTTLPolicy:       h.parseBoolParam(r, "includeTtlPolicy"),
		IncludeTTLDistribution: h.parseBoolParam(r, "includeTtlDistribution"),
		IncludeTTLSummary:      h.parseBoolParam(r, "includeTtlSummary"),
	}

	stats, err := h.adminSvc.GetSessionStats(ctx, req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get session stats")
		h.writeErrorResponse(w, "Failed to retrieve session statistics", http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, stats, http.StatusOK)
	h.logger.WithFields(logrus.Fields{
		"total_sessions":  stats.TotalSessions,
		"active_sessions": stats.ActiveSessions,
	}).Info("Session stats retrieved successfully")
}

// parseBoolParam parses a boolean query parameter with default false.
func (h *AdminHandler) parseBoolParam(r *http.Request, name string) bool {
	value := r.URL.Query().Get(name)
	if value == "" {
		return false
	}
	result, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return result
}

// writeJSONResponse writes a JSON response with the given status code.
func (h *AdminHandler) writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes a JSON error response with the given message and status code.
func (h *AdminHandler) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := map[string]interface{}{
		"error":             "authentication_error",
		"error_description": message,
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode error response")
	}
}
