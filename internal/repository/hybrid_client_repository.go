package repository

import (
	"context"
	"errors"
	"sync"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/sirupsen/logrus"
)

// ErrClientNotFound is returned when a client does not exist in the repository.
var ErrClientNotFound = errors.New("client not found")

// HybridClientRepository implements ClientRepository with MySQL primary storage and Redis caching.
// This repository follows the cache-aside pattern:
//   - Reads: Check cache first, on miss read from MySQL and populate cache
//   - Writes: Write to MySQL first (source of truth), then update cache
//   - Graceful degradation: Falls back to Redis-only if MySQL is unavailable
//
// Thread-safe for concurrent operations.
type HybridClientRepository struct {
	mysql  ClientRepository // MySQL repository (primary storage)
	redis  ClientRepository // Redis repository (cache layer)
	logger *logrus.Logger   // Structured logger

	// State tracking for graceful degradation
	mysqlAvailable bool         // Tracks MySQL availability
	mu             sync.RWMutex // Protects mysqlAvailable flag
}

// NewHybridClientRepository creates a new hybrid client repository.
// Both mysql and redis repositories are required, but mysql can be nil if not configured.
func NewHybridClientRepository(mysql, redis ClientRepository, logger *logrus.Logger) *HybridClientRepository {
	return &HybridClientRepository{
		mysql:          mysql,
		redis:          redis,
		logger:         logger,
		mysqlAvailable: mysql != nil,
	}
}

// CreateClient stores a new client in MySQL (primary) and Redis (cache).
func (r *HybridClientRepository) CreateClient(ctx context.Context, client *models.Client) error {
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	// Try MySQL first if available
	if mysqlAvailable && r.mysql != nil {
		success, err := r.tryMySQLCreate(ctx, client)
		if err != nil {
			return err // Business logic error
		}
		if success {
			return nil // MySQL succeeded
		}
		// MySQL failed with connection error, fall through to Redis
	}

	// MySQL unavailable or failed - use Redis only
	r.logger.Info("Using Redis-only mode for CreateClient (MySQL unavailable)")
	return r.redis.CreateClient(ctx, client)
}

// tryMySQLCreate attempts to create a client in MySQL and update cache.
// Returns (true, nil) if successful, (false, nil) if connection error (caller should fall back),
// or (false, err) for business logic errors that should be propagated.
func (r *HybridClientRepository) tryMySQLCreate(ctx context.Context, client *models.Client) (bool, error) {
	err := r.mysql.CreateClient(ctx, client)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during CreateClient, falling back to Redis")
			r.setMySQLUnavailable()
			return false, nil
		}
		// Business logic error (e.g., duplicate client)
		return false, err
	}

	// MySQL succeeded, update cache
	if cacheErr := r.redis.CreateClient(ctx, client); cacheErr != nil {
		r.logger.WithError(cacheErr).Warn("Failed to cache client in Redis after MySQL create")
		// Don't fail the operation - MySQL is source of truth
	}
	return true, nil
}

// GetClientByID retrieves a client from cache (Redis) first, then MySQL on cache miss.
func (r *HybridClientRepository) GetClientByID(ctx context.Context, clientID string) (*models.Client, error) {
	// Try cache first
	client, err := r.redis.GetClientByID(ctx, clientID)
	if err == nil && client != nil {
		return client, nil // Cache hit
	}

	if err != nil {
		r.logger.WithError(err).Debug("Redis cache miss or error during GetClientByID")
	}

	// Cache miss - try MySQL
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	if !mysqlAvailable || r.mysql == nil {
		// MySQL not available, return Redis result
		if client == nil && err == nil {
			return nil, ErrClientNotFound
		}
		return client, err
	}

	// Fetch from MySQL
	client, err = r.mysql.GetClientByID(ctx, clientID)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during GetClientByID")
			r.setMySQLUnavailable()
		}
		return nil, err
	}

	if client == nil {
		return nil, ErrClientNotFound
	}

	// Populate cache (best effort - don't fail if cache update fails)
	if cacheErr := r.redis.CreateClient(ctx, client); cacheErr != nil {
		r.logger.WithError(cacheErr).Debug("Failed to populate cache after MySQL read")
	}

	return client, nil
}

// UpdateClient updates the client in MySQL (primary) and invalidates/updates cache.
func (r *HybridClientRepository) UpdateClient(ctx context.Context, client *models.Client) error {
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	// Try MySQL first if available
	if mysqlAvailable && r.mysql != nil {
		success, err := r.tryMySQLUpdate(ctx, client)
		if err != nil {
			return err // Business logic error
		}
		if success {
			return nil // MySQL succeeded
		}
		// MySQL failed with connection error, fall through to Redis
	}

	// MySQL unavailable - use Redis only
	r.logger.Info("Using Redis-only mode for UpdateClient (MySQL unavailable)")
	return r.redis.UpdateClient(ctx, client)
}

// tryMySQLUpdate attempts to update a client in MySQL and update cache.
// Returns (true, nil) if successful, (false, nil) if connection error (caller should fall back),
// or (false, err) for business logic errors that should be propagated.
func (r *HybridClientRepository) tryMySQLUpdate(ctx context.Context, client *models.Client) (bool, error) {
	err := r.mysql.UpdateClient(ctx, client)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during UpdateClient, falling back to Redis")
			r.setMySQLUnavailable()
			return false, nil
		}
		// Business logic error
		return false, err
	}

	// MySQL succeeded, update cache
	if cacheErr := r.redis.UpdateClient(ctx, client); cacheErr != nil {
		r.logger.WithError(cacheErr).Warn("Failed to update cache in Redis after MySQL update")
	}
	return true, nil
}

// UpdateClientSecret rotates the secret in MySQL (primary) and cache.
func (r *HybridClientRepository) UpdateClientSecret(ctx context.Context, clientID, newSecretHash string) error {
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	// Try MySQL first if available
	if mysqlAvailable && r.mysql != nil {
		success, err := r.tryMySQLUpdateSecret(ctx, clientID, newSecretHash)
		if err != nil {
			return err // Business logic error
		}
		if success {
			return nil // MySQL succeeded
		}
		// MySQL failed with connection error, fall through to Redis
	}

	// MySQL unavailable - use Redis only
	r.logger.Info("Using Redis-only mode for UpdateClientSecret (MySQL unavailable)")
	return r.redis.UpdateClientSecret(ctx, clientID, newSecretHash)
}

// tryMySQLUpdateSecret attempts to update a client secret in MySQL and cache.
// Returns (true, nil) if successful, (false, nil) if connection error (caller should fall back),
// or (false, err) for business logic errors that should be propagated.
func (r *HybridClientRepository) tryMySQLUpdateSecret(
	ctx context.Context,
	clientID, newSecretHash string,
) (bool, error) {
	err := r.mysql.UpdateClientSecret(ctx, clientID, newSecretHash)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during UpdateClientSecret, falling back to Redis")
			r.setMySQLUnavailable()
			return false, nil
		}
		// Business logic error
		return false, err
	}

	// MySQL succeeded, update cache
	if cacheErr := r.redis.UpdateClientSecret(ctx, clientID, newSecretHash); cacheErr != nil {
		r.logger.WithError(cacheErr).Warn("Failed to update secret in Redis cache after MySQL update")
	}
	return true, nil
}

// DeleteClient removes the client from MySQL (primary) and cache.
func (r *HybridClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	// Try MySQL first if available
	if mysqlAvailable && r.mysql != nil {
		success, err := r.tryMySQLDelete(ctx, clientID)
		if err != nil {
			return err // Business logic error
		}
		if success {
			return nil // MySQL succeeded
		}
		// MySQL failed with connection error, fall through to Redis
	}

	// MySQL unavailable - use Redis only
	r.logger.Info("Using Redis-only mode for DeleteClient (MySQL unavailable)")
	return r.redis.DeleteClient(ctx, clientID)
}

// tryMySQLDelete attempts to delete a client from MySQL and cache.
// Returns (true, nil) if successful, (false, nil) if connection error (caller should fall back),
// or (false, err) for business logic errors that should be propagated.
func (r *HybridClientRepository) tryMySQLDelete(ctx context.Context, clientID string) (bool, error) {
	err := r.mysql.DeleteClient(ctx, clientID)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during DeleteClient, falling back to Redis")
			r.setMySQLUnavailable()
			return false, nil
		}
		// Business logic error
		return false, err
	}

	// MySQL succeeded, delete from cache
	if cacheErr := r.redis.DeleteClient(ctx, clientID); cacheErr != nil {
		r.logger.WithError(cacheErr).Warn("Failed to delete from Redis cache after MySQL delete")
	}
	return true, nil
}

// ListActiveClients retrieves all active clients from MySQL (primary source).
func (r *HybridClientRepository) ListActiveClients(ctx context.Context) ([]*models.Client, error) {
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	if !mysqlAvailable || r.mysql == nil {
		return nil, errors.New("ListActiveClients requires MySQL which is currently unavailable")
	}

	clients, err := r.mysql.ListActiveClients(ctx)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during ListActiveClients")
			r.setMySQLUnavailable()
		}
		return nil, err
	}

	return clients, nil
}

// IsClientExists checks both cache and MySQL for client existence.
func (r *HybridClientRepository) IsClientExists(ctx context.Context, clientID string) (bool, error) {
	// Check cache first
	exists, err := r.redis.IsClientExists(ctx, clientID)
	if err == nil && exists {
		return true, nil // Cache hit
	}

	// Check MySQL
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	if !mysqlAvailable || r.mysql == nil {
		return exists, err // Return Redis result
	}

	exists, err = r.mysql.IsClientExists(ctx, clientID)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during IsClientExists")
			r.setMySQLUnavailable()
		}
		return false, err
	}

	return exists, nil
}

// GetClientByName retrieves a client by name from MySQL (primary source).
// This operation is not efficient in Redis, so we only check MySQL.
func (r *HybridClientRepository) GetClientByName(ctx context.Context, name string) (*models.Client, error) {
	r.mu.RLock()
	mysqlAvailable := r.mysqlAvailable
	r.mu.RUnlock()

	// Only MySQL supports efficient name-based lookups
	if !mysqlAvailable || r.mysql == nil {
		return nil, errors.New("GetClientByName requires MySQL which is currently unavailable")
	}

	client, err := r.mysql.GetClientByName(ctx, name)
	if err != nil {
		if isConnectionError(err) {
			r.logger.WithError(err).Warn("MySQL unavailable during GetClientByName")
			r.setMySQLUnavailable()
		}
		return nil, err
	}

	return client, nil
}

// setMySQLUnavailable marks MySQL as unavailable (thread-safe).
// This is called when connection errors are detected.
func (r *HybridClientRepository) setMySQLUnavailable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mysqlAvailable = false
}

// SetMySQLAvailable updates the MySQL availability flag (thread-safe).
// This is exposed for external health monitoring systems to restore MySQL availability.
func (r *HybridClientRepository) SetMySQLAvailable(available bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mysqlAvailable = available
}

// IsMySQLAvailable returns the current MySQL availability status.
func (r *HybridClientRepository) IsMySQLAvailable() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mysqlAvailable
}

// isConnectionError determines if an error is a connection/availability error vs business logic error.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common connection error messages
	msg := err.Error()
	return contains(msg, "database connection not available") ||
		contains(msg, "connection refused") ||
		contains(msg, "connection reset") ||
		contains(msg, "no such host") ||
		contains(msg, "timeout") ||
		contains(msg, "context deadline exceeded")
}

// contains checks if a string contains a substring (case-sensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
