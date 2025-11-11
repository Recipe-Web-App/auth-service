package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/redis"
)

// RedisClientRepository implements ClientRepository for Redis storage.
// This implementation wraps the existing Redis Store interface to provide
// backward compatibility with the existing Redis-based client storage.
type RedisClientRepository struct {
	store redis.Store
}

// NewRedisClientRepository creates a new Redis client repository.
func NewRedisClientRepository(store redis.Store) *RedisClientRepository {
	return &RedisClientRepository{
		store: store,
	}
}

// CreateClient stores a new OAuth2 client in Redis.
func (r *RedisClientRepository) CreateClient(ctx context.Context, client *models.Client) error {
	// Check if client already exists
	existing, err := r.store.GetClient(ctx, client.ID)
	if err == nil && existing != nil {
		return fmt.Errorf("client already exists: %s", client.ID)
	}

	return r.store.StoreClient(ctx, client)
}

// GetClientByID retrieves an OAuth2 client from Redis by ID.
func (r *RedisClientRepository) GetClientByID(ctx context.Context, clientID string) (*models.Client, error) {
	return r.store.GetClient(ctx, clientID)
}

// UpdateClient updates an existing OAuth2 client in Redis.
// Redis doesn't distinguish between create and update, so this just stores the client.
func (r *RedisClientRepository) UpdateClient(ctx context.Context, client *models.Client) error {
	// Verify client exists
	existing, err := r.store.GetClient(ctx, client.ID)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("client not found: %s", client.ID)
	}

	return r.store.StoreClient(ctx, client)
}

// UpdateClientSecret rotates the client secret to a new hashed value.
func (r *RedisClientRepository) UpdateClientSecret(ctx context.Context, clientID, newSecretHash string) error {
	// Get existing client
	client, err := r.store.GetClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	if client == nil {
		return fmt.Errorf("client not found: %s", clientID)
	}

	// Update secret and store
	client.Secret = newSecretHash // pragma: allowlist secret
	return r.store.StoreClient(ctx, client)
}

// DeleteClient removes an OAuth2 client from Redis.
func (r *RedisClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	// Verify client exists before deletion
	existing, err := r.store.GetClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("client not found: %s", clientID)
	}

	return r.store.DeleteClient(ctx, clientID)
}

// ListActiveClients retrieves all active OAuth2 clients from Redis.
// Note: This is not an efficient operation in Redis as it requires scanning all client keys.
func (r *RedisClientRepository) ListActiveClients(_ context.Context) ([]*models.Client, error) {
	// Redis doesn't have a native "list all" operation that's efficient.
	// This would require SCAN with pattern matching on auth:client:* keys.
	// For now, return an error indicating this operation is not supported.
	return nil, errors.New("ListActiveClients is not efficiently supported in Redis repository")
}

// IsClientExists checks if a client with the given ID exists in Redis.
func (r *RedisClientRepository) IsClientExists(ctx context.Context, clientID string) (bool, error) {
	client, err := r.store.GetClient(ctx, clientID)
	if err != nil {
		return false, fmt.Errorf("failed to check client existence: %w", err)
	}
	return client != nil, nil
}

// GetClientByName retrieves an OAuth2 client by its name from Redis.
// Note: This is not efficient in Redis as it requires scanning all client keys.
// Consider using MySQL repository for name-based lookups.
func (r *RedisClientRepository) GetClientByName(_ context.Context, _ string) (*models.Client, error) {
	// Redis stores clients by ID, not by name.
	// Scanning all keys to find by name would be inefficient.
	// This operation should use the MySQL repository when available.
	return nil, errors.New("GetClientByName is not efficiently supported in Redis repository")
}
