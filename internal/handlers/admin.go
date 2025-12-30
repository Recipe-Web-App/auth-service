// Package handlers provides HTTP handlers for the auth service endpoints.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
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
	router.HandleFunc("/cache/sessions", h.ClearSessions).Methods(http.MethodDelete)
	router.HandleFunc("/cache/clear", h.ClearAllCaches).Methods(http.MethodPost)
	router.HandleFunc("/user-management/{userId}/force-logout", h.ForceLogout).Methods(http.MethodPost)
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

// ClearSessions handles DELETE /admin/cache/sessions
// Clears all cached sessions from the store.
//
// Responses:
//   - 200: Sessions cleared successfully
//   - 401: Unauthorized (handled by middleware)
//   - 403: Forbidden (handled by middleware)
//   - 500: Internal server error
func (h *AdminHandler) ClearSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing clear sessions request")

	response, err := h.adminSvc.ClearAllSessions(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to clear sessions")
		h.writeErrorResponse(w, "Failed to clear sessions", http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, response, http.StatusOK)
	h.logger.WithField("sessions_cleared", response.SessionsCleared).Info("Sessions cleared successfully")
}

// ClearAllCaches handles POST /admin/cache/clear
// Clears ALL cached data from the store including sessions, tokens, clients, and users.
// This is a nuclear option - use with extreme caution.
//
// Responses:
//   - 200: All caches cleared successfully
//   - 401: Unauthorized (handled by middleware)
//   - 403: Forbidden (handled by middleware)
//   - 500: Internal server error
func (h *AdminHandler) ClearAllCaches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Warn("Processing clear ALL caches request - this is a destructive operation")

	response, err := h.adminSvc.ClearAllCaches(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to clear all caches")
		h.writeErrorResponse(w, "Failed to clear all caches", http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, response, http.StatusOK)
	h.logger.WithFields(logrus.Fields{
		"caches_cleared":     response.CachesCleared,
		"total_keys_cleared": response.TotalKeysCleared,
	}).Warn("All caches cleared successfully")
}

// ForceLogout handles POST /admin/user-management/{userId}/force-logout
// Forces a user logout by clearing all their sessions.
//
// Path Parameters:
//   - userId: The UUID of the user to force logout
//
// Responses:
//   - 200: User logged out successfully
//   - 400: Invalid user ID format
//   - 401: Unauthorized (handled by middleware)
//   - 403: Forbidden (handled by middleware)
//   - 500: Internal server error
func (h *AdminHandler) ForceLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userId"]

	h.logger.WithField("user_id", userID).Info("Processing force logout request")

	// Validate UUID format
	if _, err := uuid.Parse(userID); err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Warn("Invalid user ID format")
		h.writeErrorResponse(w, "Invalid user ID format: must be a valid UUID", http.StatusBadRequest)
		return
	}

	response, err := h.adminSvc.ForceLogoutUser(ctx, userID)
	if err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Error("Failed to force logout user")
		h.writeErrorResponse(w, "Failed to force logout user", http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, response, http.StatusOK)
	h.logger.WithFields(logrus.Fields{
		"user_id":          userID,
		"sessions_cleared": response.SessionsCleared,
	}).Info("User force logout successful")
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
