// Package config provides configuration management for the OAuth2 authentication service.
// It supports environment variable-based configuration with validation and default values
// for all service components including server, Redis, JWT, OAuth2, security, and logging settings.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

const (
	// MinJWTSecretLength is the minimum required length for JWT secret.
	MinJWTSecretLength = 32
	// MinPortNumber is the minimum valid port number.
	MinPortNumber = 1
	// MaxPortNumber is the maximum valid port number.
	MaxPortNumber = 65535
)

// Config represents the complete configuration for the OAuth2 service,
// aggregating all component-specific configurations.
type Config struct {
	// Environment holds environment-specific settings.
	Environment EnvironmentConfig `envconfig:"ENVIRONMENT"`
	// Server contains HTTP server configuration including ports, timeouts, and TLS settings.
	Server ServerConfig `envconfig:"SERVER"`
	// Redis contains Redis connection and pool configuration.
	Redis RedisConfig `envconfig:"REDIS"`
	// PostgresDatabase contains PostgreSQL database configuration.
	PostgresDatabase DatabaseConfig `envconfig:"POSTGRES"`
	// MySQLDatabase contains MySQL database configuration.
	MySQLDatabase MySQLConfig `envconfig:"MYSQL"`
	// AuthServiceClient contains OAuth2 client credentials for the auth service itself.
	AuthServiceClient ClientConfig `envconfig:"AUTH_SERVICE_CLIENT"`
	// JWT contains JWT token generation and validation settings.
	JWT JWTConfig `envconfig:"JWT"`
	// OAuth2 contains OAuth2 flow-specific configuration.
	OAuth2 OAuth2Config `envconfig:"OAUTH2"`
	// Security contains security-related settings like CORS and rate limiting.
	Security SecurityConfig `envconfig:"SECURITY"`
	// Logging contains logging configuration.
	Logging LoggingConfig `envconfig:"LOGGING"`
	// ClientAutoRegister contains client auto-registration configuration.
	ClientAutoRegister ClientAutoRegisterConfig `envconfig:"CLIENT_AUTO_REGISTER"`
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
	Environment Environment `envconfig:"ENV" default:"LOCAL"`
}

// ServerConfig holds HTTP server configuration including network settings,
// timeouts, and TLS certificate paths.
type ServerConfig struct {
	// Port is the HTTP server listening port.
	Port int `envconfig:"PORT"             default:"8080"`
	// Host is the network interface to bind to.
	Host string `envconfig:"HOST"             default:"0.0.0.0"`
	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration `envconfig:"READ_TIMEOUT"     default:"15s"`
	// WriteTimeout is the maximum duration before timing out writes.
	WriteTimeout time.Duration `envconfig:"WRITE_TIMEOUT"    default:"15s"`
	// IdleTimeout is the maximum amount of time to wait for keep-alive connections.
	IdleTimeout time.Duration `envconfig:"IDLE_TIMEOUT"     default:"60s"`
	// ShutdownTimeout is the maximum time to wait for graceful server shutdown.
	ShutdownTimeout time.Duration `envconfig:"SHUTDOWN_TIMEOUT" default:"30s"`
	// TLSCert is the path to the TLS certificate file for HTTPS.
	TLSCert string `envconfig:"TLS_CERT"`
	// TLSKey is the path to the TLS private key file for HTTPS.
	TLSKey string `envconfig:"TLS_KEY"`
}

// RedisConfig contains Redis connection configuration including
// connection pool settings and timeouts.
type RedisConfig struct {
	// URL is the Redis connection URL.
	URL string `envconfig:"URL"           default:"redis://localhost:6379"`
	// Password is the Redis authentication password.
	Password string `envconfig:"PASSWORD"`
	// DB is the Redis database number to use.
	DB int `envconfig:"DB"            default:"0"`
	// MaxRetries is the maximum number of retry attempts for failed operations.
	MaxRetries int `envconfig:"MAX_RETRIES"   default:"3"`
	// PoolSize is the maximum number of socket connections.
	PoolSize int `envconfig:"POOL_SIZE"     default:"10"`
	// MinIdleConn is the minimum number of idle connections.
	MinIdleConn int `envconfig:"MIN_IDLE_CONN" default:"5"`
	// DialTimeout is the timeout for establishing new connections.
	DialTimeout time.Duration `envconfig:"DIAL_TIMEOUT"  default:"5s"`
	// ReadTimeout is the timeout for socket reads.
	ReadTimeout time.Duration `envconfig:"READ_TIMEOUT"  default:"3s"`
	// WriteTimeout is the timeout for socket writes.
	WriteTimeout time.Duration `envconfig:"WRITE_TIMEOUT" default:"3s"`
	// PoolTimeout is the amount of time client waits for connection.
	PoolTimeout time.Duration `envconfig:"POOL_TIMEOUT"  default:"4s"`
	// IdleTimeout is the amount of time after which client closes idle connections.
	IdleTimeout time.Duration `envconfig:"IDLE_TIMEOUT"  default:"300s"`
}

// DatabaseConfig contains PostgreSQL database connection configuration
// including connection pool settings and health check parameters.
type DatabaseConfig struct {
	// Host is the PostgreSQL server hostname.
	Host string `envconfig:"HOST"                default:"localhost"`
	// Port is the PostgreSQL server port.
	Port int `envconfig:"PORT"                default:"5432"`
	// Database is the PostgreSQL database name.
	Database string `envconfig:"DB"                  default:"recipe_manager"`
	// Schema is the PostgreSQL schema name.
	Schema string `envconfig:"SCHEMA"              default:"recipe_manager"`
	// User is the database username (AUTH_DB_USER from env vars).
	User string `envconfig:"AUTH_DB_USER"`
	// Password is the database password (AUTH_DB_PASSWORD from env vars).
	Password string `envconfig:"AUTH_DB_PASSWORD"`
	// SSLMode is the SSL connection mode (disable, require, verify-ca, verify-full).
	SSLMode string `envconfig:"SSL_MODE"            default:"require"`
	// MaxConn is the maximum number of connections in the pool.
	MaxConn int32 `envconfig:"MAX_CONN"            default:"25"`
	// MinConn is the minimum number of connections in the pool.
	MinConn int32 `envconfig:"MIN_CONN"            default:"5"`
	// MaxConnLifetime is the maximum lifetime of a connection.
	MaxConnLifetime time.Duration `envconfig:"MAX_CONN_LIFETIME"   default:"1h"`
	// MaxConnIdleTime is the maximum idle time for a connection.
	MaxConnIdleTime time.Duration `envconfig:"MAX_CONN_IDLE_TIME"  default:"30m"`
	// HealthCheckPeriod is how often to check database connectivity.
	HealthCheckPeriod time.Duration `envconfig:"HEALTH_CHECK_PERIOD" default:"30s"`
	// ConnectTimeout is the timeout for establishing connections.
	ConnectTimeout time.Duration `envconfig:"CONNECT_TIMEOUT"     default:"10s"`
}

// MySQLConfig contains MySQL database connection configuration
// including connection pool settings and health check parameters.
type MySQLConfig struct {
	// Host is the MySQL server hostname.
	Host string `envconfig:"HOST"                default:"localhost"`
	// Port is the MySQL server port.
	Port int `envconfig:"PORT"                default:"3306"`
	// Database is the MySQL database name.
	Database string `envconfig:"DB"                  default:"client_manager"`
	// User is the database username (CLIENT_DB_USER from env vars).
	User string `envconfig:"CLIENT_DB_USER"`
	// Password is the database password (CLIENT_DB_PASSWORD from env vars).
	Password string `envconfig:"CLIENT_DB_PASSWORD"`
	// MaxConn is the maximum number of open connections.
	MaxConn int `envconfig:"MAX_CONN"            default:"25"`
	// MinConn is the minimum number of idle connections.
	MinConn int `envconfig:"MIN_CONN"            default:"5"`
	// MaxConnLifetime is the maximum lifetime of a connection.
	MaxConnLifetime time.Duration `envconfig:"MAX_CONN_LIFETIME"   default:"1h"`
	// MaxConnIdleTime is the maximum idle time for a connection.
	MaxConnIdleTime time.Duration `envconfig:"MAX_CONN_IDLE_TIME"  default:"30m"`
	// HealthCheckPeriod is how often to check database connectivity.
	HealthCheckPeriod time.Duration `envconfig:"HEALTH_CHECK_PERIOD" default:"30s"`
	// ConnectTimeout is the timeout for establishing connections.
	ConnectTimeout time.Duration `envconfig:"CONNECT_TIMEOUT"     default:"10s"`
}

// ClientConfig contains OAuth2 client credentials configuration.
type ClientConfig struct {
	// ID is the OAuth2 client identifier.
	ClientID string `envconfig:"CLIENT_ID"     default:"auth-service-client-id"`
	// Secret is the OAuth2 client secret.
	ClientSecret string `envconfig:"CLIENT_SECRET" default:"auth-service-client-secret"`
}

// JWTConfig contains JWT token configuration including signing secrets,
// token expiry times, and supported algorithms.
type JWTConfig struct {
	// Secret is the signing secret for JWT tokens (required, minimum 32 characters).
	Secret string `envconfig:"SECRET"               required:"true"`
	// AccessTokenExpiry is the lifetime of access tokens.
	AccessTokenExpiry time.Duration `envconfig:"ACCESS_TOKEN_EXPIRY"                  default:"15m"`
	// RefreshTokenExpiry is the lifetime of refresh tokens.
	RefreshTokenExpiry time.Duration `envconfig:"REFRESH_TOKEN_EXPIRY"                 default:"168h"`
	// Issuer is the JWT issuer claim.
	Issuer string `envconfig:"ISSUER"                               default:"auth-service"`
	// Algorithm is the JWT signing algorithm (HS256, HS384, HS512, RS256, etc.).
	Algorithm string `envconfig:"ALGORITHM"                            default:"HS256"`
}

// OAuth2Config contains OAuth2 flow-specific settings including
// token expiry times, PKCE requirements, and supported scopes.
type OAuth2Config struct {
	// AuthorizationCodeExpiry is the lifetime of authorization codes.
	AuthorizationCodeExpiry time.Duration `envconfig:"AUTHORIZATION_CODE_EXPIRY" default:"10m"`
	// ClientCredentialsExpiry is the lifetime of client credentials tokens.
	ClientCredentialsExpiry time.Duration `envconfig:"CLIENT_CREDENTIALS_EXPIRY" default:"1h"`
	// PKCERequired determines if PKCE is mandatory for authorization code flow.
	PKCERequired bool `envconfig:"PKCE_REQUIRED"             default:"true"`
	// DefaultScopes are the scopes granted when none are specified.
	DefaultScopes []string
	// SupportedScopes are all scopes this server supports.
	SupportedScopes []string
	// SupportedGrantTypes are the OAuth2 grant types this server supports.
	SupportedGrantTypes []string `envconfig:"SUPPORTED_GRANT_TYPES"     default:"authorization_code,client_credentials,refresh_token"`
	// SupportedResponseTypes are the OAuth2 response types this server supports.
	SupportedResponseTypes []string `envconfig:"SUPPORTED_RESPONSE_TYPES"  default:"code"`
}

// SecurityConfig contains security-related settings including
// rate limiting, CORS configuration, and cookie security.
type SecurityConfig struct {
	// RateLimitRPS is the maximum requests per second per client.
	RateLimitRPS int `envconfig:"RATE_LIMIT_RPS"    default:"100"`
	// RateLimitBurst is the maximum burst size for rate limiting.
	RateLimitBurst int `envconfig:"RATE_LIMIT_BURST"  default:"200"`
	// RateLimitWindow is the time window for rate limiting.
	RateLimitWindow time.Duration `envconfig:"RATE_LIMIT_WINDOW" default:"1m"`
	// AllowedOrigins are the CORS allowed origins.
	AllowedOrigins []string `envconfig:"ALLOWED_ORIGINS"   default:"*"`
	// AllowedMethods are the CORS allowed HTTP methods.
	AllowedMethods []string `envconfig:"ALLOWED_METHODS"   default:"GET,POST,PUT,DELETE,OPTIONS"`
	// AllowedHeaders are the CORS allowed headers.
	AllowedHeaders []string `envconfig:"ALLOWED_HEADERS"   default:"*"`
	// ExposedHeaders are the CORS exposed headers.
	ExposedHeaders []string `envconfig:"EXPOSED_HEADERS"`
	// AllowCredentials determines if CORS allows credentials.
	AllowCredentials bool `envconfig:"ALLOW_CREDENTIALS" default:"true"`
	// MaxAge is the CORS preflight cache duration in seconds.
	MaxAge int `envconfig:"MAX_AGE"           default:"86400"`
	// TrustedProxies are the trusted proxy IP addresses or networks.
	TrustedProxies []string `envconfig:"TRUSTED_PROXIES"`
	// SecureCookies determines if cookies should be marked as secure.
	SecureCookies bool `envconfig:"SECURE_COOKIES"    default:"true"`
	// SameSiteCookies sets the SameSite attribute for cookies.
	SameSiteCookies string `envconfig:"SAME_SITE_COOKIES" default:"strict"`
}

// LoggingConfig contains logging configuration including
// log level, format, and output destination.
type LoggingConfig struct {
	// Level is the logging level (debug, info, warn, error).
	Level string `envconfig:"LEVEL"              default:"info"`
	// Format is the log output format (json, text).
	Format string `envconfig:"FORMAT"             default:"json"`
	// Output is the log output destination (stdout, stderr, file path).
	Output string `envconfig:"OUTPUT"             default:"stdout"`
	// ConsoleFormat is the format for console output (text, json).
	ConsoleFormat string `envconfig:"CONSOLE_FORMAT"     default:"text"`
	// FileFormat is the format for file output (text, json).
	FileFormat string `envconfig:"FILE_FORMAT"        default:"json"`
	// FilePath is the path to the log file for dual output.
	FilePath string `envconfig:"FILE_PATH"`
	// EnableDualOutput enables both console and file logging simultaneously.
	EnableDualOutput bool `envconfig:"ENABLE_DUAL_OUTPUT" default:"false"`
}

// ClientAutoRegisterConfig contains client auto-registration configuration
// for automatically creating OAuth2 clients from configuration files.
type ClientAutoRegisterConfig struct {
	// Enabled determines if client auto-registration is enabled.
	Enabled bool `envconfig:"ENABLED"              default:"false"`
	// ConfigPath is the path to the client configuration file.
	ConfigPath string `envconfig:"CONFIG_PATH"          default:"configs/clients.json"`
	// CreateSampleClient determines if the sample client should be created.
	CreateSampleClient bool `envconfig:"CREATE_SAMPLE_CLIENT" default:"true"`
}

// Load reads configuration from environment variables and returns
// a validated Config instance. It returns an error if configuration
// is invalid or required values are missing.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize OAuth2 scope constants
	cfg.OAuth2.DefaultScopes = []string{"openid", "profile"}
	cfg.OAuth2.SupportedScopes = []string{
		"openid", "profile", "email", "read", "write",
		"media:read", "media:write", "user:read", "user:write", "admin",
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
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
func (c *Config) IsPostgresDatabaseConfigured() bool {
	return c.PostgresDatabase.User != "" && c.PostgresDatabase.Password != ""
}

// IsMySQLDatabaseConfigured returns true if MySQL database user and password are configured.
func (c *Config) IsMySQLDatabaseConfigured() bool {
	return c.MySQLDatabase.User != "" && c.MySQLDatabase.Password != ""
}
