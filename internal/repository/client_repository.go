// Package repository defines interfaces and implementations for data access layers.
// This file contains the ClientRepository interface for OAuth2 client management.
package repository

import (
	"context"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

// ClientRepository defines the interface for OAuth2 client data persistence.
// Implementations may use different storage backends (MySQL, Redis, etc.)
// All methods accept a context for cancellation and timeout support.
type ClientRepository interface {
	// CreateClient stores a new OAuth2 client in the repository.
	// The client secret should be hashed before calling this method.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - client: The client to create (must have valid ID, name, and hashed secret)
	//
	// Returns:
	//   - error: nil on success, error if client already exists or storage fails
	CreateClient(ctx context.Context, client *models.Client) error

	// GetClientByID retrieves an OAuth2 client by its unique identifier.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - clientID: The unique client identifier
	//
	// Returns:
	//   - *models.Client: The client if found, nil if not found
	//   - error: nil on success, error if retrieval fails
	GetClientByID(ctx context.Context, clientID string) (*models.Client, error)

	// UpdateClient updates an existing OAuth2 client's information.
	// Note: Use UpdateClientSecret for secret rotation.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - client: The client with updated information
	//
	// Returns:
	//   - error: nil on success, error if client not found or update fails
	UpdateClient(ctx context.Context, client *models.Client) error

	// UpdateClientSecret rotates the client secret to a new hashed value.
	// This is a dedicated method for security-sensitive secret updates.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - clientID: The unique client identifier
	//   - newSecretHash: The new bcrypt hash of the client secret
	//
	// Returns:
	//   - error: nil on success, error if client not found or update fails
	UpdateClientSecret(ctx context.Context, clientID, newSecretHash string) error

	// DeleteClient removes an OAuth2 client from the repository.
	// This operation should also invalidate all associated tokens.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - clientID: The unique client identifier
	//
	// Returns:
	//   - error: nil on success, error if client not found or deletion fails
	DeleteClient(ctx context.Context, clientID string) error

	// ListActiveClients retrieves all active OAuth2 clients.
	// Useful for administrative operations and monitoring.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//
	// Returns:
	//   - []*models.Client: Slice of active clients
	//   - error: nil on success, error if retrieval fails
	ListActiveClients(ctx context.Context) ([]*models.Client, error)

	// IsClientExists checks if a client with the given ID exists.
	// More efficient than GetClientByID when only existence check is needed.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - clientID: The unique client identifier
	//
	// Returns:
	//   - bool: true if client exists, false otherwise
	//   - error: nil on success, error if check fails
	IsClientExists(ctx context.Context, clientID string) (bool, error)

	// GetClientByName retrieves an OAuth2 client by its name.
	// Used to prevent duplicate client registrations with the same name.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - name: The client name
	//
	// Returns:
	//   - *models.Client: The client if found, nil if not found
	//   - error: nil on success, error if retrieval fails
	GetClientByName(ctx context.Context, name string) (*models.Client, error)
}
