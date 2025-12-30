// Package auth provides authentication and authorization services.
package auth

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/redis"
)

// AdminService defines the interface for administrative operations.
type AdminService interface {
	// GetSessionStats retrieves statistics about current sessions in the cache.
	GetSessionStats(ctx context.Context, req *models.SessionStatsRequest) (*models.SessionStats, error)

	// ClearAllSessions clears all sessions from the cache.
	ClearAllSessions(ctx context.Context) (*models.ClearSessionsResponse, error)

	// ForceLogoutUser clears all sessions for a specific user.
	ForceLogoutUser(ctx context.Context, userID string) (*models.ForceLogoutResponse, error)

	// ClearAllCaches clears all cached data including sessions, tokens, clients, and users.
	ClearAllCaches(ctx context.Context) (*models.ClearAllCachesResponse, error)
}

// adminService implements the AdminService interface.
type adminService struct {
	config *config.Config
	store  redis.Store
	logger *logrus.Logger
}

// NewAdminService creates a new admin service instance with the provided dependencies.
func NewAdminService(
	cfg *config.Config,
	store redis.Store,
	logger *logrus.Logger,
) AdminService {
	return &adminService{
		config: cfg,
		store:  store,
		logger: logger,
	}
}

// GetSessionStats retrieves statistics about current sessions in the cache.
// It delegates to the Redis store to collect session counts, memory usage,
// and optional TTL information based on the request parameters.
func (s *adminService) GetSessionStats(
	ctx context.Context,
	req *models.SessionStatsRequest,
) (*models.SessionStats, error) {
	s.logger.WithFields(logrus.Fields{
		"include_ttl_policy":       req.IncludeTTLPolicy,
		"include_ttl_distribution": req.IncludeTTLDistribution,
		"include_ttl_summary":      req.IncludeTTLSummary,
	}).Info("Retrieving session statistics")

	stats, err := s.store.GetSessionStats(ctx, req)
	if err != nil {
		s.logger.WithError(err).Error("Failed to retrieve session statistics")
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"total_sessions":  stats.TotalSessions,
		"active_sessions": stats.ActiveSessions,
		"memory_usage":    stats.MemoryUsage,
	}).Info("Session statistics retrieved successfully")

	return stats, nil
}

// ClearAllSessions clears all sessions from the cache.
// It delegates to the Redis store to perform the actual deletion.
func (s *adminService) ClearAllSessions(ctx context.Context) (*models.ClearSessionsResponse, error) {
	s.logger.Info("Clearing all sessions from cache")

	count, err := s.store.ClearAllSessions(ctx)
	if err != nil {
		s.logger.WithError(err).Error("Failed to clear sessions")
		return nil, err
	}

	s.logger.WithField("sessions_cleared", count).Info("Sessions cleared successfully")

	return &models.ClearSessionsResponse{
		Success:         true,
		Message:         fmt.Sprintf("Successfully cleared %d sessions from cache", count),
		SessionsCleared: count,
	}, nil
}

// ForceLogoutUser clears all sessions for a specific user.
// It delegates to the Redis store to perform the actual deletion.
func (s *adminService) ForceLogoutUser(ctx context.Context, userID string) (*models.ForceLogoutResponse, error) {
	s.logger.WithField("user_id", userID).Info("Force logging out user")

	count, err := s.store.ClearUserSessions(ctx, userID)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to clear user sessions")
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"sessions_cleared": count,
		"user_id":          userID,
	}).Info("User sessions cleared successfully")

	return &models.ForceLogoutResponse{
		Success:         true,
		Message:         fmt.Sprintf("Successfully logged out user and cleared %d sessions", count),
		UserID:          userID,
		SessionsCleared: count,
	}, nil
}

// ClearAllCaches clears all cached data from the store.
// This is a nuclear option that clears sessions, tokens, clients, users, and all other cached data.
// It delegates to the Redis store to perform the actual deletion.
func (s *adminService) ClearAllCaches(ctx context.Context) (*models.ClearAllCachesResponse, error) {
	s.logger.Warn("Clearing all caches - this is a destructive operation")

	response, err := s.store.ClearAllCaches(ctx)
	if err != nil {
		s.logger.WithError(err).Error("Failed to clear all caches")
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"caches_cleared":     response.CachesCleared,
		"total_keys_cleared": response.TotalKeysCleared,
	}).Warn("All caches cleared successfully")

	return response, nil
}
