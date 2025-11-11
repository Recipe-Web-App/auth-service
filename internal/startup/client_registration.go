// Package startup provides utilities for service initialization including
// client auto-registration from configuration files.
package startup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
)

// ClientConfig represents the structure of client definitions in configuration files.
type ClientConfig struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
}

// ClientRegistrationService handles automatic client registration during service startup.
type ClientRegistrationService struct {
	config  *config.Config
	authSvc auth.Service
	logger  *logrus.Logger
}

// NewClientRegistrationService creates a new client registration service.
func NewClientRegistrationService(
	cfg *config.Config,
	authSvc auth.Service,
	logger *logrus.Logger,
) *ClientRegistrationService {
	return &ClientRegistrationService{
		config:  cfg,
		authSvc: authSvc,
		logger:  logger,
	}
}

// RegisterClients handles client registration based on configuration.
// It can register clients from a configuration file and/or create a sample client.
func (crs *ClientRegistrationService) RegisterClients(ctx context.Context) error {
	// Create sample client if enabled
	if crs.config.ClientAutoRegister.CreateSampleClient {
		if err := crs.createSampleClient(ctx); err != nil {
			crs.logger.WithError(err).Warn("Failed to create sample client")
		}
	}

	// Auto-register clients from config if enabled
	if crs.config.ClientAutoRegister.Enabled {
		if err := crs.registerFromConfig(ctx); err != nil {
			crs.logger.WithError(err).Error("Failed to register clients from config")
			return err
		}
	}

	return nil
}

// createSampleClient creates the default sample client for testing.
func (crs *ClientRegistrationService) createSampleClient(ctx context.Context) error {
	createdBy := "auto-registration-sample"
	sampleClient, err := crs.authSvc.RegisterClientWithCreator(
		ctx,
		"Sample Client",
		[]string{"http://localhost:3000/callback", "http://localhost:8080/callback"},
		[]string{"openid", "profile", "email", "read", "write"},
		[]string{"authorization_code", "client_credentials", "refresh_token"},
		&createdBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create sample client: %w", err)
	}

	crs.logger.WithFields(logrus.Fields{
		"client_id":     sampleClient.ID,
		"client_secret": sampleClient.Secret,
		"created_by":    createdBy,
	}).Info("Sample client created for testing")

	return nil
}

// validateConfigPath validates the config path to prevent directory traversal attacks.
func validateConfigPath(configPath string) error {
	// Clean the path to resolve any . or .. elements
	cleanPath := filepath.Clean(configPath)

	// Ensure the path doesn't contain directory traversal sequences
	if strings.Contains(cleanPath, "..") {
		return errors.New("directory traversal not allowed in config path")
	}

	// Ensure the path is not absolute to prevent accessing system files
	if filepath.IsAbs(cleanPath) {
		if err := validateAbsolutePath(cleanPath); err != nil {
			return err
		}
	}

	// Ensure it's a JSON file
	if !strings.HasSuffix(strings.ToLower(cleanPath), ".json") {
		return errors.New("config file must be a JSON file")
	}

	return nil
}

// validateAbsolutePath checks if absolute path is in allowed directories.
func validateAbsolutePath(cleanPath string) error {
	// Allow absolute paths only if they're in allowed directories
	allowedPrefixes := []string{
		"/app/configs/",
		"/opt/app/configs/",
		"/usr/local/app/configs/",
	}

	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cleanPath, prefix) {
			return nil
		}
	}

	// For development, also allow configs/ directory in current working directory
	cwd, err := os.Getwd()
	if err == nil {
		configsDir := filepath.Join(cwd, "configs")
		if strings.HasPrefix(cleanPath, configsDir) {
			return nil
		}
	}

	return errors.New("absolute paths not allowed outside of permitted directories")
}

// registerFromConfig reads and registers clients from the configuration file.
func (crs *ClientRegistrationService) registerFromConfig(ctx context.Context) error {
	configPath := crs.config.ClientAutoRegister.ConfigPath

	// Validate and sanitize the config path for security
	if err := validateConfigPath(configPath); err != nil {
		crs.logger.WithError(err).Error("Invalid config path")
		return fmt.Errorf("invalid config path: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		crs.logger.WithField("config_path", configPath).Warn("Client config file not found, skipping auto-registration")
		return nil
	}

	// Read the configuration file
	// #nosec G304 - configPath is validated above to prevent directory traversal
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open client config file: %w", err)
	}
	defer file.Close()

	var clients []ClientConfig
	if decodeErr := json.NewDecoder(file).Decode(&clients); decodeErr != nil {
		return fmt.Errorf("failed to parse client config file: %w", decodeErr)
	}

	crs.logger.WithFields(logrus.Fields{
		"config_path":  configPath,
		"client_count": len(clients),
	}).Info("Auto-registering clients from config file")

	// Register each client
	createdBy := "auto-registration-config"
	for i, clientConfig := range clients {
		client, regErr := crs.authSvc.RegisterClientWithCreator(
			ctx,
			clientConfig.Name,
			clientConfig.RedirectURIs,
			clientConfig.Scopes,
			clientConfig.GrantTypes,
			&createdBy,
		)
		if regErr != nil {
			crs.logger.WithFields(logrus.Fields{
				"client_name": clientConfig.Name,
				"error":       regErr,
			}).Error("Failed to register client from config")
			continue
		}

		crs.logger.WithFields(logrus.Fields{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"client_name":   client.Name,
			"created_by":    createdBy,
			"index":         i + 1,
			"total":         len(clients),
		}).Info("Client registered from config")
	}

	return nil
}

// RegisterSingleClient registers a single client with the given configuration.
// This is a utility method for programmatic client registration.
func (crs *ClientRegistrationService) RegisterSingleClient(
	ctx context.Context,
	name string,
	redirectURIs []string,
	scopes []string,
	grantTypes []string,
) error {
	client, err := crs.authSvc.RegisterClient(ctx, name, redirectURIs, scopes, grantTypes)
	if err != nil {
		return fmt.Errorf("failed to register client %s: %w", name, err)
	}

	crs.logger.WithFields(logrus.Fields{
		"client_id":     client.ID,
		"client_secret": client.Secret,
		"client_name":   client.Name,
	}).Info("Client registered successfully")

	return nil
}
