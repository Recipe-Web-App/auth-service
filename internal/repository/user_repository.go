package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

// UserRepository defines the interface for user data persistence operations.
type UserRepository interface {
	// CreateUser creates a new user in the database.
	CreateUser(ctx context.Context, user *models.UserWithPassword) error

	// GetUserByUsername retrieves a user by username.
	GetUserByUsername(ctx context.Context, username string) (*models.UserWithPassword, error)

	// GetUserByEmail retrieves a user by email address.
	GetUserByEmail(ctx context.Context, email string) (*models.UserWithPassword, error)

	// GetUserByID retrieves a user by their UUID.
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.UserWithPassword, error)

	// UpdateUser updates an existing user's information.
	UpdateUser(ctx context.Context, user *models.UserWithPassword) error

	// DeleteUser soft-deletes a user by setting is_active to false.
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	// IsUsernameExists checks if a username already exists.
	IsUsernameExists(ctx context.Context, username string) (bool, error)

	// IsEmailExists checks if an email already exists.
	IsEmailExists(ctx context.Context, email string) (bool, error)
}
