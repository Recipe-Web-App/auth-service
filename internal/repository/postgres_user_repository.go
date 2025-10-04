package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
)

// PoolGetter is a function that returns the current database connection pool.
type PoolGetter func() *pgxpool.Pool

// PostgresUserRepository implements UserRepository for PostgreSQL database.
type PostgresUserRepository struct {
	getPool PoolGetter
}

// NewPostgresUserRepository creates a new PostgreSQL user repository.
// The poolGetter function allows the repository to always use the current
// active connection pool, supporting automatic reconnection.
func NewPostgresUserRepository(poolGetter PoolGetter) *PostgresUserRepository {
	return &PostgresUserRepository{
		getPool: poolGetter,
	}
}

// CreateUser creates a new user in the database.
func (r *PostgresUserRepository) CreateUser(ctx context.Context, user *models.UserWithPassword) error {
	pool := r.getPool()
	if pool == nil {
		return errors.New("database connection not available")
	}

	query := `
		INSERT INTO recipe_manager.users
		(user_id, role, username, email, password_hash, full_name, bio, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := pool.Exec(ctx, query,
		user.UserID,
		"USER", // Default role
		user.Username,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.Bio,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByUsername retrieves a user by username.
func (r *PostgresUserRepository) GetUserByUsername(
	ctx context.Context,
	username string,
) (*models.UserWithPassword, error) {
	query := `
		SELECT user_id, role, username, email, password_hash, full_name, bio, is_active, created_at, updated_at
		FROM recipe_manager.users
		WHERE username = $1`

	return r.scanUser(ctx, query, username)
}

// GetUserByEmail retrieves a user by email address.
func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.UserWithPassword, error) {
	query := `
		SELECT user_id, role, username, email, password_hash, full_name, bio, is_active, created_at, updated_at
		FROM recipe_manager.users
		WHERE email = $1`

	return r.scanUser(ctx, query, email)
}

// GetUserByID retrieves a user by their UUID.
func (r *PostgresUserRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.UserWithPassword, error) {
	query := `
		SELECT user_id, role, username, email, password_hash, full_name, bio, is_active, created_at, updated_at
		FROM recipe_manager.users
		WHERE user_id = $1`

	return r.scanUser(ctx, query, userID)
}

// UpdateUser updates an existing user's information.
func (r *PostgresUserRepository) UpdateUser(ctx context.Context, user *models.UserWithPassword) error {
	pool := r.getPool()
	if pool == nil {
		return errors.New("database connection not available")
	}

	query := `
		UPDATE recipe_manager.users
		SET email = $2, password_hash = $3, full_name = $4, bio = $5, is_active = $6, updated_at = $7
		WHERE user_id = $1`

	result, err := pool.Exec(ctx, query,
		user.UserID,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.Bio,
		user.IsActive,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New("user not found")
	}

	return nil
}

// DeleteUser soft-deletes a user by setting is_active to false.
func (r *PostgresUserRepository) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	pool := r.getPool()
	if pool == nil {
		return errors.New("database connection not available")
	}

	query := `
		UPDATE recipe_manager.users
		SET is_active = false, updated_at = $2
		WHERE user_id = $1`

	result, err := pool.Exec(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New("user not found")
	}

	return nil
}

// IsUsernameExists checks if a username already exists.
func (r *PostgresUserRepository) IsUsernameExists(ctx context.Context, username string) (bool, error) {
	pool := r.getPool()
	if pool == nil {
		return false, errors.New("database connection not available")
	}

	query := `SELECT EXISTS(SELECT 1 FROM recipe_manager.users WHERE username = $1)`

	var exists bool
	err := pool.QueryRow(ctx, query, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check username existence: %w", err)
	}

	return exists, nil
}

// IsEmailExists checks if an email already exists.
func (r *PostgresUserRepository) IsEmailExists(ctx context.Context, email string) (bool, error) {
	pool := r.getPool()
	if pool == nil {
		return false, errors.New("database connection not available")
	}

	query := `SELECT EXISTS(SELECT 1 FROM recipe_manager.users WHERE email = $1)`

	var exists bool
	err := pool.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}

	return exists, nil
}

// scanUser is a helper method to scan user data from database rows.
func (r *PostgresUserRepository) scanUser(
	ctx context.Context,
	query string,
	args ...interface{},
) (*models.UserWithPassword, error) {
	pool := r.getPool()
	if pool == nil {
		return nil, errors.New("database connection not available")
	}

	var user models.UserWithPassword
	var role string
	var fullName, bio *string

	err := pool.QueryRow(ctx, query, args...).Scan(
		&user.UserID,
		&role,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&fullName,
		&bio,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	// Handle nullable fields
	if fullName != nil {
		user.FullName = fullName
	}
	if bio != nil {
		user.Bio = bio
	}

	return &user, nil
}
