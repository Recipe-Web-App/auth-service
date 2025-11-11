package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
)

const jwtSecret = "this-is-a-very-long-secret-key-for-testing-purposes-123456789" // pragma: allowlist secret

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		wantErr  bool
		validate func(*testing.T, *config.Config)
	}{
		{
			name: "valid_configuration",
			envVars: map[string]string{
				"JWT_SECRET":  jwtSecret,
				"SERVER_PORT": "9090",
				"REDIS_URL":   "redis://localhost:6380",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, 9090, cfg.Server.Port)
				assert.Equal(t, "redis://localhost:6380", cfg.Redis.URL)
				assert.Equal(t, jwtSecret, cfg.JWT.Secret)
			},
		},
		{
			name: "missing_jwt_secret",
			envVars: map[string]string{
				"SERVER_PORT": "8080",
			},
			wantErr: true,
		},
		{
			name: "short_jwt_secret",
			envVars: map[string]string{
				"JWT_SECRET":  "short",
				"SERVER_PORT": "8080",
			},
			wantErr: true,
		},
		{
			name: "invalid_port",
			envVars: map[string]string{
				"JWT_SECRET":  jwtSecret,
				"SERVER_PORT": "99999",
			},
			wantErr: true,
		},
		// Note: JWT_ALGORITHM and JWT_ACCESS_TOKEN_EXPIRY now come from YAML config files,
		// not environment variables. Their validation is tested in TestConfigValidate.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			clearEnv(t)

			// Set test environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			cfg, err := config.Load()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)

			if tt.validate != nil {
				tt.validate(t, cfg)
			}

			// Verify default values are set
			assert.Equal(t, "0.0.0.0", cfg.Server.Host)
			assert.Equal(t, 15*time.Second, cfg.Server.ReadTimeout)
			assert.Equal(t, "info", cfg.Logging.Level)
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{
			name: "valid_config",
			config: &config.Config{
				Server: config.ServerConfig{Port: 8080},
				JWT: config.JWTConfig{
					Secret:             jwtSecret,
					AccessTokenExpiry:  15 * time.Minute,
					RefreshTokenExpiry: 24 * time.Hour,
					Algorithm:          "HS256",
				},
			},
			wantErr: false,
		},
		{
			name: "empty_jwt_secret",
			config: &config.Config{
				Server: config.ServerConfig{Port: 8080},
				JWT:    config.JWTConfig{Secret: ""},
			},
			wantErr: true,
		},
		{
			name: "short_jwt_secret",
			config: &config.Config{
				Server: config.ServerConfig{Port: 8080},
				JWT:    config.JWTConfig{Secret: "short"},
			},
			wantErr: true,
		},
		{
			name: "invalid_port_low",
			config: &config.Config{
				Server: config.ServerConfig{Port: 0},
				JWT: config.JWTConfig{
					Secret: jwtSecret,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid_port_high",
			config: &config.Config{
				Server: config.ServerConfig{Port: 99999},
				JWT: config.JWTConfig{
					Secret: jwtSecret,
				},
			},
			wantErr: true,
		},
		{
			name: "short_access_token_expiry",
			config: &config.Config{
				Server: config.ServerConfig{Port: 8080},
				JWT: config.JWTConfig{
					Secret:            jwtSecret,
					AccessTokenExpiry: 30 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "short_refresh_token_expiry",
			config: &config.Config{
				Server: config.ServerConfig{Port: 8080},
				JWT: config.JWTConfig{
					Secret:             jwtSecret,
					AccessTokenExpiry:  15 * time.Minute,
					RefreshTokenExpiry: 30 * time.Minute,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid_algorithm",
			config: &config.Config{
				Server: config.ServerConfig{Port: 8080},
				JWT: config.JWTConfig{
					Secret:             jwtSecret,
					AccessTokenExpiry:  15 * time.Minute,
					RefreshTokenExpiry: 24 * time.Hour,
					Algorithm:          "INVALID",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigServerAddr(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 9090,
		},
	}

	addr := cfg.ServerAddr()
	assert.Equal(t, "localhost:9090", addr)
}

func TestConfigIsTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.Config
		expected bool
	}{
		{
			name: "tls_enabled",
			config: &config.Config{
				Server: config.ServerConfig{
					TLSCert: "/path/to/cert.pem",
					TLSKey:  "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "tls_disabled_no_cert",
			config: &config.Config{
				Server: config.ServerConfig{
					TLSKey: "/path/to/key.pem",
				},
			},
			expected: false,
		},
		{
			name: "tls_disabled_no_key",
			config: &config.Config{
				Server: config.ServerConfig{
					TLSCert: "/path/to/cert.pem",
				},
			},
			expected: false,
		},
		{
			name: "tls_disabled_empty",
			config: &config.Config{
				Server: config.ServerConfig{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsTLSEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func clearEnv(_ *testing.T) {
	envVars := []string{
		"SERVER_PORT", "SERVER_HOST", "SERVER_READ_TIMEOUT", "SERVER_WRITE_TIMEOUT",
		"REDIS_URL", "REDIS_PASSWORD", "REDIS_DB",
		"JWT_SECRET", "JWT_ACCESS_TOKEN_EXPIRY", "JWT_REFRESH_TOKEN_EXPIRY",
		"JWT_ISSUER", "JWT_ALGORITHM",
		"OAUTH2_AUTHORIZATION_CODE_EXPIRY", "OAUTH2_PKCE_REQUIRED",
		"SECURITY_RATE_LIMIT_RPS", "SECURITY_ALLOWED_ORIGINS",
		"LOGGING_LEVEL", "LOGGING_FORMAT",
	}

	for _, env := range envVars {
		// Use t.Setenv in callers to ensure test framework restores env after test.
		// For compatibility with existing callers that pass a nil/test placeholder,
		// fall back to os.Unsetenv when t is nil.
		// (Most tests call clearEnv(t) so this branch will not execute normally.)
		// However this function signature was originally clearEnv(t *testing.T) in tests
		// so keep behavior compatible: use os.Unsetenv here.
		os.Unsetenv(env)
	}
}
