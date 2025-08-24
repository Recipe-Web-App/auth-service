package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
)

// RegisterClient creates a new OAuth2 client with the specified configuration.
// It generates a unique client ID and secret, validates the parameters,
// and stores the client in Redis.
func (s *OAuth2Service) RegisterClient(
	ctx context.Context,
	name string,
	redirectURIs []string,
	scopes []string,
	grantTypes []string,
) (*models.Client, error) {
	s.logger.WithFields(map[string]interface{}{
		"name":          name,
		"redirect_uris": redirectURIs,
		"scopes":        scopes,
		"grant_types":   grantTypes,
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

	// Create new client
	client := models.NewClient(name, redirectURIs, scopes, grantTypes)

	// Store client in Redis
	if err := s.store.StoreClient(ctx, client); err != nil {
		s.logger.WithError(err).Error("Failed to store client")
		return nil, fmt.Errorf("failed to store client: %w", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"client_id":   client.ID,
		"client_name": client.Name,
	}).Info("OAuth2 client registered successfully")

	return client, nil
}

// GetClient retrieves an OAuth2 client by client ID.
func (s *OAuth2Service) GetClient(ctx context.Context, clientID string) (*models.Client, error) {
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}

	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	return client, nil
}

// ValidateClient validates client credentials (client ID and secret).
// It returns the client if validation succeeds, otherwise returns an error.
func (s *OAuth2Service) ValidateClient(ctx context.Context, clientID, clientSecret string) (*models.Client, error) {
	if clientID == "" {
		return nil, models.NewInvalidClient("client_id is required")
	}

	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return nil, models.NewInvalidClient("Client not found")
	}

	if !client.IsActive {
		return nil, models.NewInvalidClient("Client is inactive")
	}

	// Verify client secret if provided
	if clientSecret != "" && client.Secret != clientSecret { // pragma: allowlist secret
		s.logger.WithFields(map[string]interface{}{
			"client_id": clientID,
		}).Warn("Invalid client secret provided")
		return nil, models.NewInvalidClient("Invalid client credentials")
	}

	return client, nil
}
