// Package config provides configuration management for the OAuth2 authentication service.
package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

// loadYAMLConfig loads operational configuration from YAML files based on the environment.
// It first loads defaults.yaml, then overlays environment-specific configuration
// (local.yaml, nonprod.yaml, or prod.yaml).
// Returns a map of configuration values to be merged into the main Config struct.
func loadYAMLConfig(env Environment) (map[string]interface{}, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigName("defaults")
	v.AddConfigPath("./configs")
	v.AddConfigPath("../configs")
	v.AddConfigPath("../../configs")

	// Load defaults
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read defaults config: %w", err)
	}

	// Determine environment-specific config file
	var envConfigFile string
	switch env {
	case Local:
		envConfigFile = "local"
	case NonProd:
		envConfigFile = "nonprod"
	case Prod:
		envConfigFile = "prod"
	default:
		envConfigFile = "local"
	}

	// Load environment-specific overrides
	envViper := viper.New()
	envViper.SetConfigType("yaml")
	envViper.SetConfigName(envConfigFile)
	envViper.AddConfigPath("./configs")
	envViper.AddConfigPath("../configs")
	envViper.AddConfigPath("../../configs")

	if err := envViper.ReadInConfig(); err != nil {
		// Environment-specific config is optional, only return error if it's not a "file not found" error
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("failed to read %s config: %w", envConfigFile, err)
		}
	}

	// Merge environment-specific config into defaults
	if err := v.MergeConfigMap(envViper.AllSettings()); err != nil {
		return nil, fmt.Errorf("failed to merge environment config: %w", err)
	}

	return v.AllSettings(), nil
}
