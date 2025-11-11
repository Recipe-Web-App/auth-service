package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

// RegisterClient creates a new OAuth2 client with the specified configuration.
// It generates a unique client ID and secret, validates the parameters,
// hashes the client secret using bcrypt, and stores the client in the repository.
func (s *OAuth2Service) RegisterClient(
	ctx context.Context,
	name string,
	redirectURIs []string,
	scopes []string,
	grantTypes []string,
) (*models.Client, error) {
	return s.RegisterClientWithCreator(ctx, name, redirectURIs, scopes, grantTypes, nil)
}

// RegisterClientWithCreator creates a new OAuth2 client with the specified configuration and creator.
// This extended version allows setting who created the client for audit trails.
func (s *OAuth2Service) RegisterClientWithCreator(
	ctx context.Context,
	name string,
	redirectURIs []string,
	scopes []string,
	grantTypes []string,
	createdBy *string,
) (*models.Client, error) {
	s.logger.WithFields(map[string]interface{}{
		"name":          name,
		"redirect_uris": redirectURIs,
		"scopes":        scopes,
		"grant_types":   grantTypes,
		"created_by":    createdBy,
	}).Info("Registering new OAuth2 client")

	// Validate input parameters
	if name == "" {
		return nil, errors.New("client name is required")
	}

	if len(redirectURIs) == 0 {
		return nil, errors.New("at least one redirect URI is required")
	}

	if len(scopes) == 0 {
		scopes = s.config.OAuth2.DefaultScopes
	}

	if len(grantTypes) == 0 {
		grantTypes = []string{string(models.GrantTypeAuthorizationCode)}
	}

	// Validate scopes against supported scopes
	for _, scope := range scopes {
		if !s.containsScope(s.config.OAuth2.SupportedScopes, scope) {
			return nil, fmt.Errorf("unsupported scope: %s", scope)
		}
	}

	// Validate grant types against supported grant types
	for _, grantType := range grantTypes {
		if !s.containsScope(s.config.OAuth2.SupportedGrantTypes, grantType) {
			return nil, fmt.Errorf("unsupported grant type: %s", grantType)
		}
	}

	// Create new client with plaintext secret
	client := models.NewClient(name, redirectURIs, scopes, grantTypes)
	client.CreatedBy = createdBy
	client.Metadata = make(map[string]interface{})

	// Store the plaintext secret temporarily to return to caller
	plaintextSecret := client.Secret // pragma: allowlist secret

	// Hash the client secret before storage
	hashedSecret, err := HashClientSecret(client.Secret)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash client secret")
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}
	client.Secret = hashedSecret // pragma: allowlist secret

	// Store client in repository
	if storeErr := s.clientRepo.CreateClient(ctx, client); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store client")
		return nil, fmt.Errorf("failed to store client: %w", storeErr)
	}

	s.logger.WithFields(map[string]interface{}{
		"client_id":   client.ID,
		"client_name": client.Name,
	}).Info("OAuth2 client registered successfully")

	// Return client with plaintext secret (only shown once)
	client.Secret = plaintextSecret // pragma: allowlist secret
	return client, nil
}

// GetClient retrieves an OAuth2 client by client ID.
func (s *OAuth2Service) GetClient(ctx context.Context, clientID string) (*models.Client, error) {
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}

	client, err := s.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	if client == nil {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	return client, nil
}

// ValidateClient validates client credentials (client ID and secret).
// It returns the client if validation succeeds, otherwise returns an error.
// The client secret is verified using bcrypt hash comparison.
func (s *OAuth2Service) ValidateClient(ctx context.Context, clientID, clientSecret string) (*models.Client, error) {
	if clientID == "" {
		return nil, models.NewInvalidClient("client_id is required")
	}

	client, err := s.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to get client during validation")
		return nil, models.NewInvalidClient("Client not found")
	}

	if client == nil {
		return nil, models.NewInvalidClient("Client not found")
	}

	if !client.IsActive {
		return nil, models.NewInvalidClient("Client is inactive")
	}

	// Verify client secret if provided using bcrypt
	if clientSecret != "" {
		if verifyErr := VerifyClientSecret(client.Secret, clientSecret); verifyErr != nil {
			s.logger.WithFields(map[string]interface{}{
				"client_id": clientID,
			}).Warn("Invalid client secret provided")
			return nil, models.NewInvalidClient("Invalid client credentials")
		}
	}

	return client, nil
}

// UpdateClientSecret rotates the client secret to a new server-generated value.
// The old secret must be provided for verification before rotation.
// Returns the new plaintext secret (shown only once).
func (s *OAuth2Service) UpdateClientSecret(
	ctx context.Context,
	clientID string,
	currentSecret string,
) (string, error) {
	s.logger.WithFields(map[string]interface{}{
		"client_id": clientID,
	}).Info("Rotating client secret")

	// Validate current credentials
	client, err := s.ValidateClient(ctx, clientID, currentSecret)
	if err != nil {
		return "", fmt.Errorf("invalid current credentials: %w", err)
	}

	// Generate new cryptographically secure secret using UUID
	newSecret := uuid.New().String()

	// Hash the new secret
	newHashedSecret, err := HashClientSecret(newSecret)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new client secret")
		return "", fmt.Errorf("failed to hash new secret: %w", err)
	}

	// Update the secret in repository
	if updateErr := s.clientRepo.UpdateClientSecret(ctx, client.ID, newHashedSecret); updateErr != nil {
		s.logger.WithError(updateErr).Error("Failed to update client secret")
		return "", fmt.Errorf("failed to update secret: %w", updateErr)
	}

	s.logger.WithFields(map[string]interface{}{
		"client_id": clientID,
	}).Info("Client secret rotated successfully")

	// Return the plaintext new secret (only time it's shown)
	return newSecret, nil
}
