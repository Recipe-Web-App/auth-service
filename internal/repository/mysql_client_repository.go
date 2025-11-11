package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

// DBGetter is a function that returns the current database connection.
// This pattern allows the repository to use the current active connection,
// supporting automatic reconnection and graceful degradation.
type DBGetter func() *sql.DB

// MySQLClientRepository implements ClientRepository for MySQL database.
type MySQLClientRepository struct {
	getDB DBGetter
}

// NewMySQLClientRepository creates a new MySQL client repository.
// The dbGetter function allows the repository to always use the current
// active database connection, supporting automatic reconnection.
func NewMySQLClientRepository(dbGetter DBGetter) *MySQLClientRepository {
	return &MySQLClientRepository{
		getDB: dbGetter,
	}
}

// CreateClient stores a new OAuth2 client in MySQL.
func (r *MySQLClientRepository) CreateClient(ctx context.Context, client *models.Client) error {
	db := r.getDB()
	if db == nil {
		return errors.New("database connection not available")
	}

	// Marshal JSON fields
	grantTypesJSON, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal grant_types: %w", err)
	}

	scopesJSON, err := json.Marshal(client.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	var redirectURIsJSON []byte
	if len(client.RedirectURIs) > 0 {
		redirectURIsJSON, err = json.Marshal(client.RedirectURIs)
		if err != nil {
			return fmt.Errorf("failed to marshal redirect_uris: %w", err)
		}
	}

	var metadataJSON []byte
	if len(client.Metadata) > 0 {
		metadataJSON, err = json.Marshal(client.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	query := `
		INSERT INTO oauth2_clients
		(client_id, client_secret_hash, client_name, grant_types, scopes, redirect_uris,
		 is_active, created_at, updated_at, created_by, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = db.ExecContext(ctx, query,
		client.ID,
		client.Secret, // Expected to be hashed before calling this method
		client.Name,
		grantTypesJSON,
		scopesJSON,
		nullableJSON(redirectURIsJSON),
		client.IsActive,
		client.CreatedAt,
		client.UpdatedAt,
		nullableString(client.CreatedBy),
		nullableJSON(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	return nil
}

// GetClientByID retrieves an OAuth2 client from MySQL by ID.
func (r *MySQLClientRepository) GetClientByID(ctx context.Context, clientID string) (*models.Client, error) {
	db := r.getDB()
	if db == nil {
		return nil, errors.New("database connection not available")
	}

	query := `
		SELECT client_id, client_secret_hash, client_name, grant_types, scopes, redirect_uris,
		       is_active, created_at, updated_at, created_by, metadata
		FROM oauth2_clients
		WHERE client_id = ?`

	return r.scanClient(ctx, db, query, clientID)
}

// UpdateClient updates an existing OAuth2 client's information.
func (r *MySQLClientRepository) UpdateClient(ctx context.Context, client *models.Client) error {
	db := r.getDB()
	if db == nil {
		return errors.New("database connection not available")
	}

	// Marshal JSON fields
	grantTypesJSON, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal grant_types: %w", err)
	}

	scopesJSON, err := json.Marshal(client.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	var redirectURIsJSON []byte
	if len(client.RedirectURIs) > 0 {
		redirectURIsJSON, err = json.Marshal(client.RedirectURIs)
		if err != nil {
			return fmt.Errorf("failed to marshal redirect_uris: %w", err)
		}
	}

	var metadataJSON []byte
	if len(client.Metadata) > 0 {
		metadataJSON, err = json.Marshal(client.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	query := `
		UPDATE oauth2_clients
		SET client_name = ?,
		    grant_types = ?,
		    scopes = ?,
		    redirect_uris = ?,
		    is_active = ?,
		    updated_at = ?,
		    metadata = ?
		WHERE client_id = ?`

	result, err := db.ExecContext(ctx, query,
		client.Name,
		grantTypesJSON,
		scopesJSON,
		nullableJSON(redirectURIsJSON),
		client.IsActive,
		time.Now(),
		nullableJSON(metadataJSON),
		client.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client not found: %s", client.ID)
	}

	return nil
}

// UpdateClientSecret rotates the client secret to a new hashed value.
func (r *MySQLClientRepository) UpdateClientSecret(ctx context.Context, clientID, newSecretHash string) error {
	db := r.getDB()
	if db == nil {
		return errors.New("database connection not available")
	}

	query := `
		UPDATE oauth2_clients
		SET client_secret_hash = ?,
		    updated_at = ?
		WHERE client_id = ?`

	result, err := db.ExecContext(ctx, query, newSecretHash, time.Now(), clientID)
	if err != nil {
		return fmt.Errorf("failed to update client secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client not found: %s", clientID)
	}

	return nil
}

// DeleteClient removes an OAuth2 client from MySQL.
func (r *MySQLClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	db := r.getDB()
	if db == nil {
		return errors.New("database connection not available")
	}

	query := `DELETE FROM oauth2_clients WHERE client_id = ?`

	result, err := db.ExecContext(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client not found: %s", clientID)
	}

	return nil
}

// ListActiveClients retrieves all active OAuth2 clients.
func (r *MySQLClientRepository) ListActiveClients(ctx context.Context) ([]*models.Client, error) {
	db := r.getDB()
	if db == nil {
		return nil, errors.New("database connection not available")
	}

	query := `
		SELECT client_id, client_secret_hash, client_name, grant_types, scopes, redirect_uris,
		       is_active, created_at, updated_at, created_by, metadata
		FROM oauth2_clients
		WHERE is_active = true
		ORDER BY created_at DESC`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active clients: %w", err)
	}
	defer rows.Close()

	var clients []*models.Client
	for rows.Next() {
		client, scanErr := r.scanClientRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating client rows: %w", err)
	}

	return clients, nil
}

// IsClientExists checks if a client with the given ID exists.
func (r *MySQLClientRepository) IsClientExists(ctx context.Context, clientID string) (bool, error) {
	db := r.getDB()
	if db == nil {
		return false, errors.New("database connection not available")
	}

	query := `SELECT EXISTS(SELECT 1 FROM oauth2_clients WHERE client_id = ?)`

	var exists bool
	err := db.QueryRowContext(ctx, query, clientID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check client existence: %w", err)
	}

	return exists, nil
}

// GetClientByName retrieves an OAuth2 client by its name.
func (r *MySQLClientRepository) GetClientByName(ctx context.Context, name string) (*models.Client, error) {
	db := r.getDB()
	if db == nil {
		return nil, errors.New("database connection not available")
	}

	query := `
		SELECT client_id, client_secret_hash, client_name, grant_types, scopes, redirect_uris,
		       is_active, created_at, updated_at, created_by, metadata
		FROM oauth2_clients
		WHERE client_name = ?
		LIMIT 1`

	return r.scanClient(ctx, db, query, name)
}

// scanClient is a helper method to scan a single client from a query.
func (r *MySQLClientRepository) scanClient(
	ctx context.Context,
	db *sql.DB,
	query string,
	args ...interface{},
) (*models.Client, error) {
	row := db.QueryRowContext(ctx, query, args...)
	client, err := r.scanClientRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return client, nil
}

// scanClientRow scans a client from a database row.
func (r *MySQLClientRepository) scanClientRow(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.Client, error) {
	var client models.Client
	var grantTypesJSON, scopesJSON []byte
	var redirectURIsJSON, metadataJSON sql.NullString
	var createdBy sql.NullString

	err := scanner.Scan(
		&client.ID,
		&client.Secret, // This is the hashed secret from client_secret_hash
		&client.Name,
		&grantTypesJSON,
		&scopesJSON,
		&redirectURIsJSON,
		&client.IsActive,
		&client.CreatedAt,
		&client.UpdatedAt,
		&createdBy,
		&metadataJSON,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan client: %w", err)
	}

	// Unmarshal JSON fields
	if unmarshalErr := json.Unmarshal(grantTypesJSON, &client.GrantTypes); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal grant_types: %w", unmarshalErr)
	}

	if unmarshalErr := json.Unmarshal(scopesJSON, &client.Scopes); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal scopes: %w", unmarshalErr)
	}

	// Handle nullable redirect_uris
	if redirectURIsJSON.Valid && redirectURIsJSON.String != "" {
		if unmarshalErr := json.Unmarshal([]byte(redirectURIsJSON.String), &client.RedirectURIs); unmarshalErr != nil {
			return nil, fmt.Errorf("failed to unmarshal redirect_uris: %w", unmarshalErr)
		}
	} else {
		client.RedirectURIs = []string{}
	}

	// Handle nullable created_by
	if createdBy.Valid {
		client.CreatedBy = &createdBy.String
	}

	// Handle nullable metadata
	if metadataJSON.Valid && metadataJSON.String != "" {
		if unmarshalErr := json.Unmarshal([]byte(metadataJSON.String), &client.Metadata); unmarshalErr != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", unmarshalErr)
		}
	} else {
		client.Metadata = make(map[string]interface{})
	}

	return &client, nil
}

// nullableString converts a *string to sql.NullString for database operations.
func nullableString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

// nullableJSON converts a []byte to sql.NullString for JSON database operations.
func nullableJSON(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: string(b), Valid: true}
}
