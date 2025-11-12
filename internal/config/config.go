// Package config provides configuration management for the OAuth2 authentication service.
// It supports environment variable-based configuration with validation and default values
// for all service components including server, Redis, JWT, OAuth2, security, and logging settings.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	// MinJWTSecretLength is the minimum required length for JWT secret.
	MinJWTSecretLength = 32
	// MinPortNumber is the minimum valid port number.
	MinPortNumber = 1
	// MaxPortNumber is the maximum valid port number.
	MaxPortNumber = 65535
	// maskPrefixLength is the number of characters to show before masking in logs.
	maskPrefixLength = 3
)

// Config represents the complete configuration for the OAuth2 service.
// Connection data and secrets come from environment variables, while operational
// settings (timeouts, pool sizes, etc.) come from YAML files.
type Config struct {
	// Environment holds environment-specific settings.
	Environment EnvironmentConfig `envconfig:"ENVIRONMENT"         mapstructure:"-"`
	// Server contains HTTP server configuration.
	Server ServerConfig `envconfig:"SERVER"              mapstructure:"server"`
	// Redis contains Redis connection configuration.
	Redis RedisConfig `envconfig:"REDIS"               mapstructure:"redis"`
	// PostgresDatabase contains PostgreSQL database configuration.
	PostgresDatabase DatabaseConfig `envconfig:"POSTGRES"            mapstructure:"postgres"`
	// MySQLDatabase contains MySQL database configuration.
	MySQLDatabase MySQLConfig `envconfig:"MYSQL"               mapstructure:"mysql"`
	// AuthServiceClient contains OAuth2 client credentials for the auth service itself.
	AuthServiceClient ClientConfig `envconfig:"AUTH_SERVICE_CLIENT" mapstructure:"-"`
	// JWT contains JWT token configuration.
	JWT JWTConfig `envconfig:"JWT"                 mapstructure:"jwt"`
	// OAuth2 contains OAuth2 flow-specific configuration.
	OAuth2 OAuth2Config `                                mapstructure:"oauth2"`
	// Security contains security-related settings.
	Security SecurityConfig `                                mapstructure:"security"`
	// Logging contains logging configuration.
	Logging LoggingConfig `                                mapstructure:"logging"`
	// ClientAutoRegister contains client auto-registration configuration.
	ClientAutoRegister ClientAutoRegisterConfig `                                mapstructure:"client_auto_register"`
}

type Environment string

const (
	Local   Environment = "LOCAL"
	NonProd Environment = "NONPROD"
	Prod    Environment = "PROD"
)

// EnvironmentConfig holds environment-specific settings.
type EnvironmentConfig struct {
	// Environment indicates the current running environment (LOCAL, NONPROD, PROD).
	Environment Environment `envconfig:"ENVIRONMENT" default:"LOCAL"`
}

// ServerConfig holds HTTP server configuration including network settings and timeouts.
type ServerConfig struct {
	// Port is the HTTP server listening port.
	Port int `envconfig:"PORT" default:"8080"    mapstructure:"-"`
	// Host is the network interface to bind to.
	Host string `envconfig:"HOST" default:"0.0.0.0" mapstructure:"-"`
	// ReadTimeout is the maximum duration for reading the entire request (from YAML).
	ReadTimeout time.Duration `                                   mapstructure:"read_timeout"`
	// WriteTimeout is the maximum duration before timing out writes (from YAML).
	WriteTimeout time.Duration `                                   mapstructure:"write_timeout"`
	// IdleTimeout is the maximum amount of time to wait for keep-alive connections (from YAML).
	IdleTimeout time.Duration `                                   mapstructure:"idle_timeout"`
	// ShutdownTimeout is the maximum time to wait for graceful server shutdown (from YAML).
	ShutdownTimeout time.Duration `                                   mapstructure:"shutdown_timeout"`
	// TLSCert is the path to the TLS certificate file for HTTPS (from YAML).
	TLSCert string `                                   mapstructure:"tls_cert"`
	// TLSKey is the path to the TLS private key file for HTTPS (from YAML).
	TLSKey string `                                   mapstructure:"tls_key"`
}

// RedisConfig contains Redis connection configuration and pool settings.
type RedisConfig struct {
	// URL is the Redis connection URL.
	URL string `envconfig:"URL"      default:"redis://localhost:6379" mapstructure:"-"`
	// Password is the Redis authentication password.
	Password string `envconfig:"PASSWORD"                                  mapstructure:"-"`
	// DB is the Redis database number to use.
	DB int `envconfig:"DB"       default:"0"                      mapstructure:"-"`
	// MaxRetries is the maximum number of retry attempts for failed operations (from YAML).
	MaxRetries int `                                                      mapstructure:"max_retries"`
	// PoolSize is the maximum number of socket connections (from YAML).
	PoolSize int `                                                      mapstructure:"pool_size"`
	// MinIdleConn is the minimum number of idle connections (from YAML).
	MinIdleConn int `                                                      mapstructure:"min_idle_conn"`
	// DialTimeout is the timeout for establishing new connections (from YAML).
	DialTimeout time.Duration `                                                      mapstructure:"dial_timeout"`
	// ReadTimeout is the timeout for socket reads (from YAML).
	ReadTimeout time.Duration `                                                      mapstructure:"read_timeout"`
	// WriteTimeout is the timeout for socket writes (from YAML).
	WriteTimeout time.Duration `                                                      mapstructure:"write_timeout"`
	// PoolTimeout is the amount of time client waits for connection (from YAML).
	PoolTimeout time.Duration `                                                      mapstructure:"pool_timeout"`
	// IdleTimeout is the amount of time after which client closes idle connections (from YAML).
	IdleTimeout time.Duration `                                                      mapstructure:"idle_timeout"`
}

// DatabaseConfig contains PostgreSQL database connection configuration and pool settings.
type DatabaseConfig struct {
	// Host is the PostgreSQL server hostname.
	Host string `envconfig:"HOST"     default:"localhost"      mapstructure:"-"`
	// Port is the PostgreSQL server port.
	Port int `envconfig:"PORT"     default:"5432"           mapstructure:"-"`
	// Database is the PostgreSQL database name.
	Database string `envconfig:"DB"       default:"recipe_manager" mapstructure:"-"`
	// Schema is the PostgreSQL schema name.
	Schema string `envconfig:"SCHEMA"   default:"recipe_manager" mapstructure:"-"`
	// User is the database username.
	User string `envconfig:"USER"                              mapstructure:"-"`
	// Password is the database password.
	Password string `envconfig:"PASSWORD"                          mapstructure:"-"`
	// SSLMode is the SSL connection mode (from YAML).
	SSLMode string `                                              mapstructure:"ssl_mode"`
	// MaxConn is the maximum number of connections in the pool (from YAML).
	MaxConn int32 `                                              mapstructure:"max_conn"`
	// MinConn is the minimum number of connections in the pool (from YAML).
	MinConn int32 `                                              mapstructure:"min_conn"`
	// MaxConnLifetime is the maximum lifetime of a connection (from YAML).
	MaxConnLifetime time.Duration `                                              mapstructure:"max_conn_lifetime"`
	// MaxConnIdleTime is the maximum idle time for a connection (from YAML).
	MaxConnIdleTime time.Duration `                                              mapstructure:"max_conn_idle_time"`
	// HealthCheckPeriod is how often to check database connectivity (from YAML).
	HealthCheckPeriod time.Duration `                                              mapstructure:"health_check_period"`
	// ConnectTimeout is the timeout for establishing connections (from YAML).
	ConnectTimeout time.Duration `                                              mapstructure:"connect_timeout"`
}

// MySQLConfig contains MySQL database connection configuration and pool settings.
type MySQLConfig struct {
	// Host is the MySQL server hostname.
	Host string `envconfig:"HOST"               default:"localhost"      mapstructure:"-"`
	// Port is the MySQL server port.
	Port int `envconfig:"PORT"               default:"3306"           mapstructure:"-"`
	// Database is the MySQL database name.
	Database string `envconfig:"DB"                 default:"client_manager" mapstructure:"-"`
	// User is the database username.
	User string `envconfig:"CLIENT_DB_USER"                              mapstructure:"-"`
	// Password is the database password.
	Password string `envconfig:"CLIENT_DB_PASSWORD"                          mapstructure:"-"`
	// MaxConn is the maximum number of open connections (from YAML).
	MaxConn int `                                                        mapstructure:"max_conn"`
	// MinConn is the minimum number of idle connections (from YAML).
	MinConn int `                                                        mapstructure:"min_conn"`
	// MaxConnLifetime is the maximum lifetime of a connection (from YAML).
	MaxConnLifetime time.Duration `                                                        mapstructure:"max_conn_lifetime"`
	// MaxConnIdleTime is the maximum idle time for a connection (from YAML).
	MaxConnIdleTime time.Duration `                                                        mapstructure:"max_conn_idle_time"`
	// HealthCheckPeriod is how often to check database connectivity (from YAML).
	HealthCheckPeriod time.Duration `                                                        mapstructure:"health_check_period"`
	// ConnectTimeout is the timeout for establishing connections (from YAML).
	ConnectTimeout time.Duration `                                                        mapstructure:"connect_timeout"`
}

// ClientConfig contains OAuth2 client credentials configuration.
type ClientConfig struct {
	// ClientID is the OAuth2 client identifier.
	ClientID string `envconfig:"CLIENT_ID"     default:"auth-service-client-id"`
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string `envconfig:"CLIENT_SECRET" default:"auth-service-client-secret"`
}

// JWTConfig contains JWT token configuration including signing secret and expiry times.
type JWTConfig struct {
	// Secret is the signing secret for JWT tokens (required, minimum 32 characters).
	Secret string `envconfig:"SECRET" required:"true" mapstructure:"-"`
	// AccessTokenExpiry is the lifetime of access tokens (from YAML).
	AccessTokenExpiry time.Duration `                                   mapstructure:"access_token_expiry"`
	// RefreshTokenExpiry is the lifetime of refresh tokens (from YAML).
	RefreshTokenExpiry time.Duration `                                   mapstructure:"refresh_token_expiry"`
	// Issuer is the JWT issuer claim (from YAML).
	Issuer string `                                   mapstructure:"issuer"`
	// Algorithm is the JWT signing algorithm (from YAML).
	Algorithm string `                                   mapstructure:"algorithm"`
}

// OAuth2Config contains OAuth2 flow-specific settings (all from YAML).
type OAuth2Config struct {
	// AuthorizationCodeExpiry is the lifetime of authorization codes.
	AuthorizationCodeExpiry time.Duration `mapstructure:"authorization_code_expiry"`
	// ClientCredentialsExpiry is the lifetime of client credentials tokens.
	ClientCredentialsExpiry time.Duration `mapstructure:"client_credentials_expiry"`
	// PKCERequired determines if PKCE is mandatory for authorization code flow.
	PKCERequired bool `mapstructure:"pkce_required"`
	// DefaultScopes are the scopes granted when none are specified.
	DefaultScopes []string `mapstructure:"default_scopes"`
	// SupportedScopes are all scopes this server supports.
	SupportedScopes []string `mapstructure:"supported_scopes"`
	// SupportedGrantTypes are the OAuth2 grant types this server supports.
	SupportedGrantTypes []string `mapstructure:"supported_grant_types"`
	// SupportedResponseTypes are the OAuth2 response types this server supports.
	SupportedResponseTypes []string `mapstructure:"supported_response_types"`
}

// SecurityConfig contains security-related settings (all from YAML).
type SecurityConfig struct {
	// RateLimitRPS is the maximum requests per second per client.
	RateLimitRPS int `mapstructure:"rate_limit_rps"`
	// RateLimitBurst is the maximum burst size for rate limiting.
	RateLimitBurst int `mapstructure:"rate_limit_burst"`
	// RateLimitWindow is the time window for rate limiting.
	RateLimitWindow time.Duration `mapstructure:"rate_limit_window"`
	// AllowedOrigins are the CORS allowed origins.
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	// AllowedMethods are the CORS allowed HTTP methods.
	AllowedMethods []string `mapstructure:"allowed_methods"`
	// AllowedHeaders are the CORS allowed headers.
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	// ExposedHeaders are the CORS exposed headers.
	ExposedHeaders []string `mapstructure:"exposed_headers"`
	// AllowCredentials determines if CORS allows credentials.
	AllowCredentials bool `mapstructure:"allow_credentials"`
	// MaxAge is the CORS preflight cache duration in seconds.
	MaxAge int `mapstructure:"max_age"`
	// TrustedProxies are the trusted proxy IP addresses or networks.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	// SecureCookies determines if cookies should be marked as secure.
	SecureCookies bool `mapstructure:"secure_cookies"`
	// SameSiteCookies sets the SameSite attribute for cookies.
	SameSiteCookies string `mapstructure:"same_site_cookies"`
}

// LoggingConfig contains logging configuration (all from YAML).
type LoggingConfig struct {
	// Level is the logging level (debug, info, warn, error).
	Level string `mapstructure:"level"`
	// Format is the log output format (json, text).
	Format string `mapstructure:"format"`
	// Output is the log output destination (stdout, stderr, file path).
	Output string `mapstructure:"output"`
	// ConsoleFormat is the format for console output (text, json).
	ConsoleFormat string `mapstructure:"console_format"`
	// FileFormat is the format for file output (text, json).
	FileFormat string `mapstructure:"file_format"`
	// FilePath is the path to the log file for dual output.
	FilePath string `mapstructure:"file_path"`
	// EnableDualOutput enables both console and file logging simultaneously.
	EnableDualOutput bool `mapstructure:"enable_dual_output"`
}

// ClientAutoRegisterConfig contains client auto-registration configuration (all from YAML).
type ClientAutoRegisterConfig struct {
	// Enabled determines if client auto-registration is enabled.
	Enabled bool `mapstructure:"enabled"`
	// ConfigPath is the path to the client configuration file.
	ConfigPath string `mapstructure:"config_path"`
	// CreateSampleClient determines if the sample client should be created.
	CreateSampleClient bool `mapstructure:"create_sample_client"`
}

// Load reads configuration from environment variables and YAML files,
// returning a validated Config instance. It returns an error if configuration
// is invalid or required values are missing.
func Load() (*Config, error) {
	// Step 1: Load environment-specific connection data and secrets from env vars
	var cfg Config
	if configErr := envconfig.Process("", &cfg); configErr != nil {
		return nil, fmt.Errorf("failed to load environment configuration: %w", configErr)
	}

	// Debug logging for PostgreSQL configuration
	logrus.WithFields(logrus.Fields{
		"postgres_host":     cfg.PostgresDatabase.Host,
		"postgres_port":     cfg.PostgresDatabase.Port,
		"postgres_db":       cfg.PostgresDatabase.Database,
		"postgres_schema":   cfg.PostgresDatabase.Schema,
		"postgres_user":     cfg.PostgresDatabase.User,
		"postgres_password": maskString(cfg.PostgresDatabase.Password),
		"user_empty":        cfg.PostgresDatabase.User == "",
		"password_empty":    cfg.PostgresDatabase.Password == "",
	}).Debug("PostgreSQL configuration loaded from environment variables")

	// Step 2: Load operational settings from YAML files based on environment
	yamlSettings, yamlSettingsErr := loadYAMLConfig(cfg.Environment.Environment)
	if yamlSettingsErr != nil {
		return nil, fmt.Errorf("failed to load YAML configuration: %w", yamlSettingsErr)
	}

	// Step 3: Unmarshal YAML settings into a temporary struct
	v := viper.New()
	for key, value := range yamlSettings {
		v.Set(key, value)
	}

	var yamlCfg Config
	if yamlConfigErr := v.Unmarshal(&yamlCfg); yamlConfigErr != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML configuration: %w", yamlConfigErr)
	}

	// Step 4: Merge YAML operational settings into env-loaded config
	// (only copy non-zero values from YAML to preserve env-loaded values)
	mergeYAMLIntoConfig(&cfg, &yamlCfg)

	if configErr := cfg.Validate(); configErr != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", configErr)
	}

	return &cfg, nil
}

// mergeYAMLIntoConfig copies operational settings from YAML config into the main config.
// It only copies the fields that come from YAML, preserving env-loaded values.
func mergeYAMLIntoConfig(dst, src *Config) {
	// Server operational settings
	dst.Server.ReadTimeout = src.Server.ReadTimeout
	dst.Server.WriteTimeout = src.Server.WriteTimeout
	dst.Server.IdleTimeout = src.Server.IdleTimeout
	dst.Server.ShutdownTimeout = src.Server.ShutdownTimeout
	dst.Server.TLSCert = src.Server.TLSCert
	dst.Server.TLSKey = src.Server.TLSKey

	// Redis pool settings
	dst.Redis.MaxRetries = src.Redis.MaxRetries
	dst.Redis.PoolSize = src.Redis.PoolSize
	dst.Redis.MinIdleConn = src.Redis.MinIdleConn
	dst.Redis.DialTimeout = src.Redis.DialTimeout
	dst.Redis.ReadTimeout = src.Redis.ReadTimeout
	dst.Redis.WriteTimeout = src.Redis.WriteTimeout
	dst.Redis.PoolTimeout = src.Redis.PoolTimeout
	dst.Redis.IdleTimeout = src.Redis.IdleTimeout

	// PostgreSQL pool settings
	dst.PostgresDatabase.SSLMode = src.PostgresDatabase.SSLMode
	dst.PostgresDatabase.MaxConn = src.PostgresDatabase.MaxConn
	dst.PostgresDatabase.MinConn = src.PostgresDatabase.MinConn
	dst.PostgresDatabase.MaxConnLifetime = src.PostgresDatabase.MaxConnLifetime
	dst.PostgresDatabase.MaxConnIdleTime = src.PostgresDatabase.MaxConnIdleTime
	dst.PostgresDatabase.HealthCheckPeriod = src.PostgresDatabase.HealthCheckPeriod
	dst.PostgresDatabase.ConnectTimeout = src.PostgresDatabase.ConnectTimeout

	// MySQL pool settings
	dst.MySQLDatabase.MaxConn = src.MySQLDatabase.MaxConn
	dst.MySQLDatabase.MinConn = src.MySQLDatabase.MinConn
	dst.MySQLDatabase.MaxConnLifetime = src.MySQLDatabase.MaxConnLifetime
	dst.MySQLDatabase.MaxConnIdleTime = src.MySQLDatabase.MaxConnIdleTime
	dst.MySQLDatabase.HealthCheckPeriod = src.MySQLDatabase.HealthCheckPeriod
	dst.MySQLDatabase.ConnectTimeout = src.MySQLDatabase.ConnectTimeout

	// JWT operational settings
	dst.JWT.AccessTokenExpiry = src.JWT.AccessTokenExpiry
	dst.JWT.RefreshTokenExpiry = src.JWT.RefreshTokenExpiry
	dst.JWT.Issuer = src.JWT.Issuer
	dst.JWT.Algorithm = src.JWT.Algorithm

	// OAuth2 settings (all from YAML)
	dst.OAuth2 = src.OAuth2

	// Security settings (all from YAML)
	dst.Security = src.Security

	// Logging settings (all from YAML)
	dst.Logging = src.Logging

	// Client auto-registration settings (all from YAML)
	dst.ClientAutoRegister = src.ClientAutoRegister
}

// Validate performs comprehensive validation of all configuration values,
// ensuring they meet security and operational requirements.
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return errors.New("JWT secret is required")
	}

	if len(c.JWT.Secret) < MinJWTSecretLength {
		return fmt.Errorf("JWT secret must be at least %d characters long", MinJWTSecretLength)
	}

	if c.Server.Port < MinPortNumber || c.Server.Port > MaxPortNumber {
		return errors.New("server port must be between 1 and 65535")
	}

	if c.JWT.AccessTokenExpiry < time.Minute {
		return errors.New("access token expiry must be at least 1 minute")
	}

	if c.JWT.RefreshTokenExpiry < time.Hour {
		return errors.New("refresh token expiry must be at least 1 hour")
	}

	validAlgorithms := map[string]bool{
		"HS256": true, "HS384": true, "HS512": true,
		"RS256": true, "RS384": true, "RS512": true,
		"ES256": true, "ES384": true, "ES512": true,
	}
	if !validAlgorithms[c.JWT.Algorithm] {
		return fmt.Errorf("unsupported JWT algorithm: %s", c.JWT.Algorithm)
	}

	return nil
}

// ServerAddr returns the formatted server address string in host:port format.
func (c *Config) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// IsTLSEnabled returns true if both TLS certificate and key paths are configured.
func (c *Config) IsTLSEnabled() bool {
	return c.Server.TLSCert != "" && c.Server.TLSKey != ""
}

// DatabaseDSN returns the PostgreSQL connection string (Data Source Name).
//
// Deprecated: Use PostgresDatabaseDSN instead.
func (c *Config) DatabaseDSN() string {
	return c.PostgresDatabaseDSN()
}

// PostgresDatabaseDSN returns the PostgreSQL connection string (Data Source Name).
func (c *Config) PostgresDatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s search_path=%s",
		c.PostgresDatabase.Host,
		c.PostgresDatabase.Port,
		c.PostgresDatabase.Database,
		c.PostgresDatabase.User,
		c.PostgresDatabase.Password,
		c.PostgresDatabase.SSLMode,
		c.PostgresDatabase.Schema,
	)
}

// MySQLDSN returns the MySQL connection string (Data Source Name).
func (c *Config) MySQLDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		c.MySQLDatabase.User,
		c.MySQLDatabase.Password,
		c.MySQLDatabase.Host,
		c.MySQLDatabase.Port,
		c.MySQLDatabase.Database,
	)
}

// IsDatabaseConfigured returns true if PostgreSQL database user and password are configured.
//
// Deprecated: Use IsPostgresDatabaseConfigured instead.
func (c *Config) IsDatabaseConfigured() bool {
	return c.IsPostgresDatabaseConfigured()
}

// IsPostgresDatabaseConfigured returns true if PostgreSQL database user and password are configured.
//
// This checks if both POSTGRES_USER and POSTGRES_PASSWORD environment variables are set and non-empty.
// If this returns false, PostgreSQL will not be used and the service will fall back to Redis-only storage.
//
// Troubleshooting:
// - Ensure POSTGRES_USER and POSTGRES_PASSWORD are set in your .env.local file
// - Check that values are not empty strings or just whitespace
// - Verify the .env.local file is being loaded (check GO_ENV or ENVIRONMENT variables)
// - Enable debug logging (set LOG_LEVEL=debug) to see loaded configuration values.
func (c *Config) IsPostgresDatabaseConfigured() bool {
	return c.PostgresDatabase.User != "" && c.PostgresDatabase.Password != ""
}

// IsMySQLDatabaseConfigured returns true if MySQL database user and password are configured.
func (c *Config) IsMySQLDatabaseConfigured() bool {
	return c.MySQLDatabase.User != "" && c.MySQLDatabase.Password != ""
}

// maskString masks a sensitive string for safe logging.
// Shows first 3 characters followed by "***" to indicate value is present without exposing it.
// If string is empty, returns "<empty>". If shorter than 3 chars, returns "***".
func maskString(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= maskPrefixLength {
		return "***"
	}
	return s[:maskPrefixLength] + "***"
}
