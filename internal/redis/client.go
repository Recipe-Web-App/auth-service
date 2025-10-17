// Package redis provides a Redis client implementation for OAuth2 authentication data storage.
// This package implements a comprehensive Redis store for managing OAuth2 entities including
// clients, authorization codes, access tokens, refresh tokens, user sessions, token blacklists,
// and rate limiting. It offers thread-safe operations with connection pooling, automatic TTL
// handling, and structured logging for debugging and monitoring.
//
// The Redis keys are organized with prefixes to avoid collisions:
//   - auth:client:{id} - OAuth2 client registrations
//   - auth:code:{code} - Authorization codes with TTL
//   - auth:access_token:{token} - Access tokens with TTL
//   - auth:refresh_token:{token} - Refresh tokens with TTL
//   - auth:session:{id} - User sessions with TTL
//   - auth:blacklist:{token} - Revoked/blacklisted tokens
//   - auth:rate_limit:{key} - Rate limiting counters with TTL
//
// All operations are context-aware and provide detailed error reporting.
// Token values are masked in logs for security purposes.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

const (
	// MinTokenLengthForMasking is the minimum token length before masking is applied.
	MinTokenLengthForMasking = 8
)

// Client is a Redis client wrapper that implements the Store interface for OAuth2 data storage.
// It provides thread-safe access to Redis operations with connection pooling, structured logging,
// and automatic error handling. The client maintains a persistent connection pool and handles
// reconnection automatically.
//
// Thread Safety: All methods are safe for concurrent use by multiple goroutines.
// Connection Management: Uses Redis connection pooling with configurable pool size and timeouts.
// Error Handling: All Redis errors are wrapped with contextual information.
type Client struct {
	rdb    *redis.Client  // Redis client instance with connection pooling
	logger *logrus.Logger // Structured logger for debugging and monitoring
}

// Store defines the interface for OAuth2 data storage operations in Redis.
// All methods are context-aware and provide comprehensive error handling.
// The interface supports the complete OAuth2 flow including client registration,
// authorization codes, token management, session handling, token revocation,
// and rate limiting.
//
// Error Handling: All methods return descriptive errors. Non-existent entities
// return specific "not found" errors rather than generic Redis errors.
//
// Thread Safety: Implementations must be safe for concurrent use.
type Store interface {
	// Close gracefully closes the Redis connection pool.
	// Returns an error if the connection cannot be closed properly.
	Close() error

	// Ping verifies connectivity to the Redis server.
	// Returns an error if the server is unreachable or unresponsive.
	Ping(ctx context.Context) error

	// StoreClient persists an OAuth2 client registration in Redis.
	// The client is stored without TTL and remains until explicitly deleted.
	// Returns an error if marshaling or Redis operation fails.
	StoreClient(ctx context.Context, client *models.Client) error

	// GetClient retrieves an OAuth2 client by ID.
	// Returns nil and "client not found" error if the client doesn't exist.
	// Returns an error if unmarshaling or Redis operation fails.
	GetClient(ctx context.Context, clientID string) (*models.Client, error)

	// DeleteClient removes an OAuth2 client registration from Redis.
	// Returns an error if the Redis delete operation fails.
	// Does not return an error if the client doesn't exist.
	DeleteClient(ctx context.Context, clientID string) error

	// StoreAuthorizationCode persists an authorization code with TTL.
	// The code automatically expires after the specified duration.
	// Returns an error if marshaling or Redis operation fails.
	StoreAuthorizationCode(ctx context.Context, code *models.AuthorizationCode, ttl time.Duration) error

	// GetAuthorizationCode retrieves an authorization code.
	// Returns nil and "authorization code not found" error if expired or non-existent.
	// Returns an error if unmarshaling or Redis operation fails.
	GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error)

	// DeleteAuthorizationCode removes an authorization code from Redis.
	// Typically called after code exchange to prevent replay attacks.
	// Returns an error if the Redis delete operation fails.
	DeleteAuthorizationCode(ctx context.Context, code string) error

	// StoreAccessToken persists an access token with TTL.
	// The token automatically expires after the specified duration.
	// Returns an error if marshaling or Redis operation fails.
	StoreAccessToken(ctx context.Context, token *models.AccessToken, ttl time.Duration) error

	// GetAccessToken retrieves an access token and its metadata.
	// Returns nil and "access token not found" error if expired or non-existent.
	// Returns an error if unmarshaling or Redis operation fails.
	GetAccessToken(ctx context.Context, token string) (*models.AccessToken, error)

	// DeleteAccessToken removes an access token from Redis.
	// Used for cleanup operations or immediate token invalidation.
	// Returns an error if the Redis delete operation fails.
	DeleteAccessToken(ctx context.Context, token string) error

	// RevokeAccessToken marks an access token as revoked while preserving it in Redis.
	// The token remains in storage until its original expiration time.
	// Returns an error if the token doesn't exist or Redis operation fails.
	RevokeAccessToken(ctx context.Context, token string) error

	// StoreRefreshToken persists a refresh token with TTL.
	// The token automatically expires after the specified duration.
	// Returns an error if marshaling or Redis operation fails.
	StoreRefreshToken(ctx context.Context, token *models.RefreshToken, ttl time.Duration) error

	// GetRefreshToken retrieves a refresh token and its metadata.
	// Returns nil and "refresh token not found" error if expired or non-existent.
	// Returns an error if unmarshaling or Redis operation fails.
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)

	// DeleteRefreshToken removes a refresh token from Redis.
	// Typically called during token refresh to invalidate the old token.
	// Returns an error if the Redis delete operation fails.
	DeleteRefreshToken(ctx context.Context, token string) error

	// RevokeRefreshToken marks a refresh token as revoked while preserving it in Redis.
	// The token remains in storage until its original expiration time.
	// Returns an error if the token doesn't exist or Redis operation fails.
	RevokeRefreshToken(ctx context.Context, token string) error

	// StoreSession persists a user session with TTL.
	// The session automatically expires after the specified duration.
	// Returns an error if marshaling or Redis operation fails.
	StoreSession(ctx context.Context, session *models.Session, ttl time.Duration) error

	// GetSession retrieves a user session by ID.
	// Returns nil and "session not found" error if expired or non-existent.
	// Returns an error if unmarshaling or Redis operation fails.
	GetSession(ctx context.Context, sessionID string) (*models.Session, error)

	// DeleteSession removes a user session from Redis.
	// Used for logout operations or session cleanup.
	// Returns an error if the Redis delete operation fails.
	DeleteSession(ctx context.Context, sessionID string) error

	// IsTokenBlacklisted checks if a token is in the blacklist.
	// Returns true if the token is blacklisted, false otherwise.
	// Returns an error if the Redis operation fails.
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)

	// BlacklistToken adds a token to the blacklist with TTL.
	// The blacklist entry expires after the specified duration.
	// Used for token revocation and security purposes.
	// Returns an error if the Redis operation fails.
	BlacklistToken(ctx context.Context, token string, ttl time.Duration) error

	// StoreUser persists a user with password in Redis.
	// The user is stored without TTL and remains until explicitly deleted.
	// Returns an error if marshaling or Redis operation fails.
	StoreUser(ctx context.Context, user *models.UserWithPassword) error

	// GetUser retrieves a user by username.
	// Returns nil and "user not found" error if the user doesn't exist.
	// Returns an error if unmarshaling or Redis operation fails.
	GetUser(ctx context.Context, username string) (*models.UserWithPassword, error)

	// GetUserByEmail retrieves a user by email address.
	// Returns nil and "user not found" error if the user doesn't exist.
	// Returns an error if unmarshaling or Redis operation fails.
	GetUserByEmail(ctx context.Context, email string) (*models.UserWithPassword, error)

	// UpdateUser updates an existing user's information.
	// Returns an error if the user doesn't exist or Redis operation fails.
	UpdateUser(ctx context.Context, user *models.UserWithPassword) error

	// DeleteUser removes a user from Redis.
	// Returns an error if the Redis delete operation fails.
	// Does not return an error if the user doesn't exist.
	DeleteUser(ctx context.Context, username string) error

	// StorePasswordResetToken persists a password reset token with TTL.
	// The token automatically expires after the specified duration.
	// Returns an error if marshaling or Redis operation fails.
	StorePasswordResetToken(ctx context.Context, token *models.PasswordResetToken, ttl time.Duration) error

	// GetPasswordResetToken retrieves a password reset token.
	// Returns nil and "password reset token not found" error if expired or non-existent.
	// Returns an error if unmarshaling or Redis operation fails.
	GetPasswordResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error)

	// DeletePasswordResetToken removes a password reset token from Redis.
	// Typically called after password reset to prevent replay attacks.
	// Returns an error if the Redis delete operation fails.
	DeletePasswordResetToken(ctx context.Context, token string) error
}

// NewClient creates a new Redis client instance with the provided configuration.
// It establishes a connection pool, validates connectivity, and returns a ready-to-use client.
//
// Configuration:
//   - URL: Redis connection string (redis://host:port/db)
//   - Password: Optional authentication password
//   - DB: Database number to select
//   - Connection pooling settings (MaxRetries, PoolSize, MinIdleConn)
//   - Timeout settings (DialTimeout, ReadTimeout, WriteTimeout, PoolTimeout, IdleTimeout)
//
// The function performs an initial connectivity test using Ping() and returns an error
// if the Redis server is unreachable.
//
// Returns:
//   - *Client: Configured Redis client ready for use
//   - error: Connection or configuration error
func NewClient(cfg *config.RedisConfig, logger *logrus.Logger) (*Client, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	if cfg.Password != "" {
		opts.Password = cfg.Password // pragma: allowlist secret
	}
	if cfg.DB != 0 {
		opts.DB = cfg.DB
	}

	opts.MaxRetries = cfg.MaxRetries
	opts.PoolSize = cfg.PoolSize
	opts.MinIdleConns = cfg.MinIdleConn
	opts.DialTimeout = cfg.DialTimeout
	opts.ReadTimeout = cfg.ReadTimeout
	opts.WriteTimeout = cfg.WriteTimeout
	opts.PoolTimeout = cfg.PoolTimeout
	opts.ConnMaxIdleTime = cfg.IdleTimeout

	rdb := redis.NewClient(opts)

	client := &Client{
		rdb:    rdb,
		logger: logger,
	}

	if pingErr := client.Ping(context.Background()); pingErr != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", pingErr)
	}

	logger.Info("Connected to Redis successfully")

	return client, nil
}

// Close gracefully shuts down the Redis client and closes all connections in the pool.
// It logs the closure operation and returns any errors encountered during shutdown.
// This method should be called when the application terminates to clean up resources.
//
// Returns:
//   - error: Connection closure error, if any
func (c *Client) Close() error {
	if err := c.rdb.Close(); err != nil {
		c.logger.WithError(err).Error("Failed to close Redis connection")
		return err
	}
	c.logger.Info("Redis connection closed")
	return nil
}

// Ping tests connectivity to the Redis server by sending a PING command.
// This method is used for health checks and connection validation.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//
// Returns:
//   - error: Network or Redis server error, if any
func (c *Client) Ping(ctx context.Context) error {
	status := c.rdb.Ping(ctx)
	if status.Err() != nil {
		return fmt.Errorf("redis ping failed: %w", status.Err())
	}
	return nil
}

// GetRedisClient returns the underlying go-redis client for advanced operations
// like rate limiting with redis_rate. Returns nil if not using Redis store.
//
// Returns:
//   - *redis.Client: The underlying go-redis client
func (c *Client) GetRedisClient() *redis.Client {
	return c.rdb
}

// StoreClient persists an OAuth2 client registration in Redis without expiration.
// The client data is JSON-serialized and stored using the key pattern "auth:client:{id}".
// Client registrations are permanent and remain until explicitly deleted.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - client: OAuth2 client data to store
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StoreClient(ctx context.Context, client *models.Client) error {
	key := clientKey(client.ID)
	data, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, 0).Err(); setErr != nil {
		return fmt.Errorf("failed to store client: %w", setErr)
	}

	c.logger.WithField("client_id", client.ID).Debug("Client stored successfully")
	return nil
}

// GetClient retrieves an OAuth2 client registration by client ID.
// Returns a specific "client not found" error if the client doesn't exist in Redis.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - clientID: Unique identifier of the OAuth2 client
//
// Returns:
//   - *models.Client: Client data if found, nil if not found
//   - error: "client not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetClient(ctx context.Context, clientID string) (*models.Client, error) {
	key := clientKey(clientID)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	var client models.Client
	if unmarshalErr := json.Unmarshal([]byte(data), &client); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", unmarshalErr)
	}

	return &client, nil
}

// DeleteClient removes an OAuth2 client registration from Redis.
// This operation is idempotent - it doesn't return an error if the client doesn't exist.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - clientID: Unique identifier of the OAuth2 client to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeleteClient(ctx context.Context, clientID string) error {
	key := clientKey(clientID)
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	c.logger.WithField("client_id", clientID).Debug("Client deleted successfully")
	return nil
}

// StoreAuthorizationCode persists an OAuth2 authorization code with automatic expiration.
// The code is JSON-serialized and stored using the key pattern "auth:code:{code}".
// Authorization codes have short TTLs (typically 10 minutes) as per OAuth2 security best practices.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - code: Authorization code data including client, user, and scope information
//   - ttl: Time-to-live duration after which the code expires automatically
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StoreAuthorizationCode(ctx context.Context, code *models.AuthorizationCode, ttl time.Duration) error {
	key := authCodeKey(code.Code)
	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization code: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, ttl).Err(); setErr != nil {
		return fmt.Errorf("failed to store authorization code: %w", setErr)
	}

	c.logger.WithField("code", code.Code).Debug("Authorization code stored successfully")
	return nil
}

// GetAuthorizationCode retrieves an authorization code and its associated metadata.
// Returns a specific "authorization code not found" error if the code has expired or doesn't exist.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - code: Authorization code string to retrieve
//
// Returns:
//   - *models.AuthorizationCode: Code data if found and not expired, nil otherwise
//   - error: "authorization code not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	key := authCodeKey(code)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("authorization code not found")
		}
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}

	var authCode models.AuthorizationCode
	if unmarshalErr := json.Unmarshal([]byte(data), &authCode); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization code: %w", unmarshalErr)
	}

	return &authCode, nil
}

// DeleteAuthorizationCode removes an authorization code from Redis.
// This method is typically called immediately after successful token exchange
// to prevent authorization code replay attacks.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - code: Authorization code string to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeleteAuthorizationCode(ctx context.Context, code string) error {
	key := authCodeKey(code)
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete authorization code: %w", err)
	}

	c.logger.WithField("code", code).Debug("Authorization code deleted successfully")
	return nil
}

// StoreAccessToken persists an OAuth2 access token with automatic expiration.
// The token is JSON-serialized and stored using the key pattern "auth:access_token:{token}".
// Token values are masked in logs for security purposes.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Access token data including client, user, scope, and expiration information
//   - ttl: Time-to-live duration after which the token expires automatically
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StoreAccessToken(ctx context.Context, token *models.AccessToken, ttl time.Duration) error {
	key := accessTokenKey(token.Token)
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal access token: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, ttl).Err(); setErr != nil {
		return fmt.Errorf("failed to store access token: %w", setErr)
	}

	c.logger.WithField("token", maskToken(token.Token)).Debug("Access token stored successfully")
	return nil
}

// GetAccessToken retrieves an access token and its associated metadata.
// Returns a specific "access token not found" error if the token has expired or doesn't exist.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Access token string to retrieve
//
// Returns:
//   - *models.AccessToken: Token data if found and not expired, nil otherwise
//   - error: "access token not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	key := accessTokenKey(token)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("access token not found")
		}
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	var accessToken models.AccessToken
	if unmarshalErr := json.Unmarshal([]byte(data), &accessToken); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal access token: %w", unmarshalErr)
	}

	return &accessToken, nil
}

// DeleteAccessToken removes an access token from Redis immediately.
// This provides immediate token invalidation, unlike revocation which marks the token as revoked.
// Token values are masked in logs for security purposes.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Access token string to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeleteAccessToken(ctx context.Context, token string) error {
	key := accessTokenKey(token)
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}

	c.logger.WithField("token", maskToken(token)).Debug("Access token deleted successfully")
	return nil
}

// RevokeAccessToken marks an access token as revoked without removing it from Redis.
// The token remains in storage with its revoked status until the original expiration time.
// This approach allows for audit trails and prevents token reuse while maintaining history.
//
// The TTL is calculated as the time remaining until the token's original expiration.
// If the token is already expired, this operation will fail.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Access token string to revoke
//
// Returns:
//   - error: Token retrieval, JSON marshaling, or Redis operation error
func (c *Client) RevokeAccessToken(ctx context.Context, token string) error {
	key := accessTokenKey(token)
	accessToken, err := c.GetAccessToken(ctx, token)
	if err != nil {
		return err
	}

	accessToken.Revoked = true
	data, err := json.Marshal(accessToken)
	if err != nil {
		return fmt.Errorf("failed to marshal revoked access token: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, time.Until(accessToken.ExpiresAt)).Err(); setErr != nil {
		return fmt.Errorf("failed to revoke access token: %w", setErr)
	}

	c.logger.WithField("token", maskToken(token)).Debug("Access token revoked successfully")
	return nil
}

// StoreRefreshToken persists an OAuth2 refresh token with automatic expiration.
// The token is JSON-serialized and stored using the key pattern "auth:refresh_token:{token}".
// Refresh tokens typically have longer TTLs than access tokens (hours to days).
// Token values are masked in logs for security purposes.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Refresh token data including client, user, and scope information
//   - ttl: Time-to-live duration after which the token expires automatically
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StoreRefreshToken(ctx context.Context, token *models.RefreshToken, ttl time.Duration) error {
	key := refreshTokenKey(token.Token)
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, ttl).Err(); setErr != nil {
		return fmt.Errorf("failed to store refresh token: %w", setErr)
	}

	c.logger.WithField("token", maskToken(token.Token)).Debug("Refresh token stored successfully")
	return nil
}

// GetRefreshToken retrieves a refresh token and its associated metadata.
// Returns a specific "refresh token not found" error if the token has expired or doesn't exist.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Refresh token string to retrieve
//
// Returns:
//   - *models.RefreshToken: Token data if found and not expired, nil otherwise
//   - error: "refresh token not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	key := refreshTokenKey(token)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("refresh token not found")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	var refreshToken models.RefreshToken
	if unmarshalErr := json.Unmarshal([]byte(data), &refreshToken); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", unmarshalErr)
	}

	return &refreshToken, nil
}

// DeleteRefreshToken removes a refresh token from Redis immediately.
// This method is typically called during token refresh to invalidate the old refresh token
// as per OAuth2 security best practices (refresh token rotation).
// Token values are masked in logs for security purposes.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Refresh token string to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeleteRefreshToken(ctx context.Context, token string) error {
	key := refreshTokenKey(token)
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	c.logger.WithField("token", maskToken(token)).Debug("Refresh token deleted successfully")
	return nil
}

// RevokeRefreshToken marks a refresh token as revoked without removing it from Redis.
// The token remains in storage with its revoked status until the original expiration time.
// This approach allows for audit trails and prevents token reuse while maintaining history.
//
// The TTL is calculated as the time remaining until the token's original expiration.
// If the token is already expired, this operation will fail.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Refresh token string to revoke
//
// Returns:
//   - error: Token retrieval, JSON marshaling, or Redis operation error
func (c *Client) RevokeRefreshToken(ctx context.Context, token string) error {
	key := refreshTokenKey(token)
	refreshToken, err := c.GetRefreshToken(ctx, token)
	if err != nil {
		return err
	}

	refreshToken.Revoked = true
	data, err := json.Marshal(refreshToken)
	if err != nil {
		return fmt.Errorf("failed to marshal revoked refresh token: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, time.Until(refreshToken.ExpiresAt)).Err(); setErr != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", setErr)
	}

	c.logger.WithField("token", maskToken(token)).Debug("Refresh token revoked successfully")
	return nil
}

// StoreSession persists a user session with automatic expiration.
// The session is JSON-serialized and stored using the key pattern "auth:session:{id}".
// Sessions track user authentication state and can contain user preferences and metadata.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - session: Session data including user ID, creation time, and metadata
//   - ttl: Time-to-live duration after which the session expires automatically
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StoreSession(ctx context.Context, session *models.Session, ttl time.Duration) error {
	key := sessionKey(session.ID)
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, ttl).Err(); setErr != nil {
		return fmt.Errorf("failed to store session: %w", setErr)
	}

	c.logger.WithField("session_id", session.ID).Debug("Session stored successfully")
	return nil
}

// GetSession retrieves a user session by session ID.
// Returns a specific "session not found" error if the session has expired or doesn't exist.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - sessionID: Unique session identifier
//
// Returns:
//   - *models.Session: Session data if found and not expired, nil otherwise
//   - error: "session not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetSession(ctx context.Context, sessionID string) (*models.Session, error) {
	key := sessionKey(sessionID)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session models.Session
	if unmarshalErr := json.Unmarshal([]byte(data), &session); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", unmarshalErr)
	}

	return &session, nil
}

// DeleteSession removes a user session from Redis immediately.
// This method is typically called during user logout to invalidate the session.
// Session cleanup helps prevent unauthorized access and maintains security.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - sessionID: Unique session identifier to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeleteSession(ctx context.Context, sessionID string) error {
	key := sessionKey(sessionID)
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	c.logger.WithField("session_id", sessionID).Debug("Session deleted successfully")
	return nil
}

// IsTokenBlacklisted checks if a token exists in the blacklist.
// The blacklist is used to track revoked or compromised tokens that should be rejected.
// Uses the EXISTS command for efficient checking without retrieving the actual value.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Token string to check against the blacklist
//
// Returns:
//   - bool: true if the token is blacklisted, false otherwise
//   - error: Redis operation error, if any
func (c *Client) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	key := blacklistKey(token)
	exists, err := c.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	return exists == 1, nil
}

// BlacklistToken adds a token to the blacklist with automatic expiration.
// Blacklisted tokens are stored with the value "revoked" and expire after the specified TTL.
// The TTL should typically match the token's original expiration time.
// Token values are masked in logs for security purposes.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Token string to add to the blacklist
//   - ttl: Time-to-live duration for the blacklist entry
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) BlacklistToken(ctx context.Context, token string, ttl time.Duration) error {
	key := blacklistKey(token)
	if err := c.rdb.Set(ctx, key, "revoked", ttl).Err(); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	c.logger.WithField("token", maskToken(token)).Debug("Token blacklisted successfully")
	return nil
}

// clientKey generates a Redis key for OAuth2 client storage.
// Uses the pattern "auth:client:{clientID}" to organize client data.
//
// Parameters:
//   - clientID: Unique OAuth2 client identifier
//
// Returns:
//   - string: Redis key for client storage
func clientKey(clientID string) string {
	return fmt.Sprintf("auth:client:%s", clientID)
}

// authCodeKey generates a Redis key for authorization code storage.
// Uses the pattern "auth:code:{code}" to organize authorization code data.
//
// Parameters:
//   - code: Authorization code string
//
// Returns:
//   - string: Redis key for authorization code storage
func authCodeKey(code string) string {
	return fmt.Sprintf("auth:code:%s", code)
}

// accessTokenKey generates a Redis key for access token storage.
// Uses the pattern "auth:access_token:{token}" to organize access token data.
//
// Parameters:
//   - token: Access token string
//
// Returns:
//   - string: Redis key for access token storage
func accessTokenKey(token string) string {
	return fmt.Sprintf("auth:access_token:%s", token)
}

// refreshTokenKey generates a Redis key for refresh token storage.
// Uses the pattern "auth:refresh_token:{token}" to organize refresh token data.
//
// Parameters:
//   - token: Refresh token string
//
// Returns:
//   - string: Redis key for refresh token storage
func refreshTokenKey(token string) string {
	return fmt.Sprintf("auth:refresh_token:%s", token)
}

// sessionKey generates a Redis key for user session storage.
// Uses the pattern "auth:session:{sessionID}" to organize session data.
//
// Parameters:
//   - sessionID: Unique session identifier
//
// Returns:
//   - string: Redis key for session storage
func sessionKey(sessionID string) string {
	return fmt.Sprintf("auth:session:%s", sessionID)
}

// blacklistKey generates a Redis key for token blacklist storage.
// Uses the pattern "auth:blacklist:{token}" to organize blacklisted tokens.
//
// Parameters:
//   - token: Token string to blacklist
//
// Returns:
//   - string: Redis key for blacklist storage
func blacklistKey(token string) string {
	return fmt.Sprintf("auth:blacklist:%s", token)
}

// maskToken obscures sensitive token values for safe logging.
// Shows only the first 4 and last 4 characters of tokens longer than 8 characters.
// Tokens with 8 or fewer characters are completely masked for security.
//
// This prevents accidental exposure of sensitive tokens in log files while
// still providing enough information for debugging and correlation.
//
// Examples:
//   - "abc123xyz789" -> "abc1***x789"
//   - "short" -> "***"
//
// Parameters:
//   - token: Token string to mask
//
// Returns:
//   - string: Masked token safe for logging
func maskToken(token string) string {
	if len(token) <= MinTokenLengthForMasking {
		return "***"
	}
	return token[:4] + "***" + token[len(token)-4:]
}

// StoreUser persists a user with password in Redis without expiration.
// The user data is JSON-serialized and stored using both username and email as keys.
// User registrations are permanent and remain until explicitly deleted.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - user: User data with password to store
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StoreUser(ctx context.Context, user *models.UserWithPassword) error {
	usernameKey := userKey(user.Username)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	if setErr := c.rdb.Set(ctx, usernameKey, data, 0).Err(); setErr != nil {
		return fmt.Errorf("failed to store user: %w", setErr)
	}

	// Also store by email if email is provided
	if user.Email != nil && *user.Email != "" {
		emailKey := userEmailKey(*user.Email)
		if setErr := c.rdb.Set(ctx, emailKey, data, 0).Err(); setErr != nil {
			return fmt.Errorf("failed to store user by email: %w", setErr)
		}
	}

	c.logger.WithField("username", user.Username).Debug("User stored successfully")
	return nil
}

// GetUser retrieves a user by username.
// Returns a specific "user not found" error if the user doesn't exist in Redis.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - username: Username of the user to retrieve
//
// Returns:
//   - *models.UserWithPassword: User data if found, nil if not found
//   - error: "user not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetUser(ctx context.Context, username string) (*models.UserWithPassword, error) {
	key := userKey(username)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var user models.UserWithPassword
	if unmarshalErr := json.Unmarshal([]byte(data), &user); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", unmarshalErr)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email address.
// Returns a specific "user not found" error if the user doesn't exist in Redis.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - email: Email address of the user to retrieve
//
// Returns:
//   - *models.UserWithPassword: User data if found, nil if not found
//   - error: "user not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetUserByEmail(ctx context.Context, email string) (*models.UserWithPassword, error) {
	key := userEmailKey(email)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	var user models.UserWithPassword
	if unmarshalErr := json.Unmarshal([]byte(data), &user); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", unmarshalErr)
	}

	return &user, nil
}

// UpdateUser updates an existing user's information.
// Updates both username and email keys if email has changed.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - user: Updated user data
//
// Returns:
//   - error: User retrieval, JSON marshaling, or Redis operation error
func (c *Client) UpdateUser(ctx context.Context, user *models.UserWithPassword) error {
	// Get existing user to check for email changes
	existingUser, err := c.GetUser(ctx, user.Username)
	if err != nil {
		return fmt.Errorf("failed to get existing user: %w", err)
	}

	// Update the user data
	usernameKey := userKey(user.Username)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	if setErr := c.rdb.Set(ctx, usernameKey, data, 0).Err(); setErr != nil {
		return fmt.Errorf("failed to update user: %w", setErr)
	}

	// Handle email key updates
	oldEmail := c.getEmailString(existingUser.Email)
	newEmail := c.getEmailString(user.Email)

	if oldEmail != newEmail {
		if updateErr := c.updateEmailKeys(ctx, oldEmail, newEmail, data); updateErr != nil {
			return updateErr
		}
	}

	c.logger.WithField("username", user.Username).Debug("User updated successfully")
	return nil
}

// DeleteUser removes a user from Redis.
// Removes both username and email keys.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - username: Username of the user to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	// Get user to find email for cleanup
	user, err := c.GetUser(ctx, username)
	if err != nil && !errors.Is(err, errors.New("user not found")) {
		return fmt.Errorf("failed to get user for deletion: %w", err)
	}

	// Delete username key
	usernameKey := userKey(username)
	if delErr := c.rdb.Del(ctx, usernameKey).Err(); delErr != nil {
		return fmt.Errorf("failed to delete user: %w", delErr)
	}

	// Delete email key if it exists
	if user != nil && user.Email != nil && *user.Email != "" {
		emailKey := userEmailKey(*user.Email)
		if delErr := c.rdb.Del(ctx, emailKey).Err(); delErr != nil {
			c.logger.WithError(delErr).Warn("Failed to delete user email key")
		}
	}

	c.logger.WithField("username", username).Debug("User deleted successfully")
	return nil
}

// StorePasswordResetToken persists a password reset token with automatic expiration.
// The token is JSON-serialized and stored using the key pattern "auth:password_reset:{token}".
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Password reset token data
//   - ttl: Time-to-live duration after which the token expires automatically
//
// Returns:
//   - error: JSON marshaling or Redis operation error
func (c *Client) StorePasswordResetToken(
	ctx context.Context,
	token *models.PasswordResetToken,
	ttl time.Duration,
) error {
	key := passwordResetKey(token.Token)
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal password reset token: %w", err)
	}

	if setErr := c.rdb.Set(ctx, key, data, ttl).Err(); setErr != nil {
		return fmt.Errorf("failed to store password reset token: %w", setErr)
	}

	c.logger.WithField("token", maskToken(token.Token)).Debug("Password reset token stored successfully")
	return nil
}

// GetPasswordResetToken retrieves a password reset token and its associated metadata.
// Returns a specific "password reset token not found" error if the token has expired or doesn't exist.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Password reset token string to retrieve
//
// Returns:
//   - *models.PasswordResetToken: Token data if found and not expired, nil otherwise
//   - error: "password reset token not found", JSON unmarshaling, or Redis operation error
func (c *Client) GetPasswordResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error) {
	key := passwordResetKey(token)
	data, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("password reset token not found")
		}
		return nil, fmt.Errorf("failed to get password reset token: %w", err)
	}

	var resetToken models.PasswordResetToken
	if unmarshalErr := json.Unmarshal([]byte(data), &resetToken); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal password reset token: %w", unmarshalErr)
	}

	return &resetToken, nil
}

// DeletePasswordResetToken removes a password reset token from Redis.
// This method is typically called immediately after successful password reset
// to prevent token replay attacks.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: Password reset token string to delete
//
// Returns:
//   - error: Redis operation error, if any
func (c *Client) DeletePasswordResetToken(ctx context.Context, token string) error {
	key := passwordResetKey(token)
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete password reset token: %w", err)
	}

	c.logger.WithField("token", maskToken(token)).Debug("Password reset token deleted successfully")
	return nil
}

// userKey generates a Redis key for user storage by username.
// Uses the pattern "auth:user:{username}" to organize user data.
//
// Parameters:
//   - username: Username for key generation
//
// Returns:
//   - string: Redis key for user storage
func userKey(username string) string {
	return fmt.Sprintf("auth:user:%s", username)
}

// userEmailKey generates a Redis key for user storage by email.
// Uses the pattern "auth:user:email:{email}" to organize user data by email.
//
// Parameters:
//   - email: Email address for key generation
//
// Returns:
//   - string: Redis key for user storage by email
func userEmailKey(email string) string {
	return fmt.Sprintf("auth:user:email:%s", email)
}

// passwordResetKey generates a Redis key for password reset token storage.
// Uses the pattern "auth:password_reset:{token}" to organize password reset tokens.
//
// Parameters:
//   - token: Password reset token string
//
// Returns:
//   - string: Redis key for password reset token storage
func passwordResetKey(token string) string {
	return fmt.Sprintf("auth:password_reset:%s", token)
}

// getEmailString safely extracts email string from pointer, returning empty string if nil.
func (c *Client) getEmailString(email *string) string {
	if email == nil {
		return ""
	}
	return *email
}

// updateEmailKeys handles the deletion of old email key and creation of new email key.
func (c *Client) updateEmailKeys(ctx context.Context, oldEmail, newEmail string, data []byte) error {
	// Delete old email key if it exists
	if oldEmail != "" {
		oldEmailKey := userEmailKey(oldEmail)
		if delErr := c.rdb.Del(ctx, oldEmailKey).Err(); delErr != nil {
			c.logger.WithError(delErr).Warn("Failed to delete old email key")
		}
	}

	// Set new email key if email is provided
	if newEmail != "" {
		newEmailKey := userEmailKey(newEmail)
		if setErr := c.rdb.Set(ctx, newEmailKey, data, 0).Err(); setErr != nil {
			return fmt.Errorf("failed to update user by email: %w", setErr)
		}
	}

	return nil
}
