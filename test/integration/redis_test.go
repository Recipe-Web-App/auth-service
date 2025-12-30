package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	redisClient "github.com/jsamuelsen11/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/pkg/logger"
)

const testClient = "test-client"
const testUser = "test-user"

func TestRedisIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	ctx := context.Background()

	// Start Redis container
	redisContainer, err := redis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	defer func() {
		if err = redisContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Redis container: %v", err)
		}
	}()

	// Get connection string
	connectionString, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	// Create Redis client
	cfg := &config.RedisConfig{
		URL:          connectionString,
		MaxRetries:   3,
		PoolSize:     10,
		MinIdleConn:  5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
		IdleTimeout:  300 * time.Second,
	}

	log := logger.New("info", "json", "stdout")
	store, err := redisClient.NewClient(cfg, log)
	require.NoError(t, err)
	defer store.Close()

	// Test ping
	err = store.Ping(ctx)
	require.NoError(t, err)

	t.Run("ClientOperations", func(t *testing.T) {
		testClientOperations(ctx, t, store)
	})

	t.Run("AuthorizationCodeOperations", func(t *testing.T) {
		testAuthorizationCodeOperations(ctx, t, store)
	})

	t.Run("AccessTokenOperations", func(t *testing.T) {
		testAccessTokenOperations(ctx, t, store)
	})

	t.Run("RefreshTokenOperations", func(t *testing.T) {
		testRefreshTokenOperations(ctx, t, store)
	})

	t.Run("SessionOperations", func(t *testing.T) {
		testSessionOperations(ctx, t, store)
	})

	t.Run("TokenBlacklist", func(t *testing.T) {
		testTokenBlacklist(ctx, t, store)
	})

	t.Run("ClearAllSessions", func(t *testing.T) {
		testClearAllSessions(ctx, t, store)
	})
}

func testClientOperations(ctx context.Context, t *testing.T, store redisClient.Store) {
	// Create test client
	client := models.NewClient(
		"Test Client",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"},
		[]string{"authorization_code", "refresh_token"},
	)

	// Store client
	err := store.StoreClient(ctx, client)
	require.NoError(t, err)

	// Retrieve client
	retrievedClient, err := store.GetClient(ctx, client.ID)
	require.NoError(t, err)
	assert.Equal(t, client.ID, retrievedClient.ID)
	assert.Equal(t, client.Name, retrievedClient.Name)
	assert.Equal(t, client.RedirectURIs, retrievedClient.RedirectURIs)
	assert.Equal(t, client.Scopes, retrievedClient.Scopes)
	assert.Equal(t, client.GrantTypes, retrievedClient.GrantTypes)

	// Delete client
	err = store.DeleteClient(ctx, client.ID)
	require.NoError(t, err)

	// Verify client is deleted
	_, err = store.GetClient(ctx, client.ID)
	assert.Error(t, err)
}

func testAuthorizationCodeOperations(ctx context.Context, t *testing.T, store redisClient.Store) {
	// Create test authorization code
	authCode := models.NewAuthorizationCode(models.AuthorizationCodeParams{
		ClientID:            testClient,
		UserID:              testUser,
		RedirectURI:         "http://localhost:3000/callback",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		State:               "state",
		Nonce:               "nonce",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})

	// Store authorization code
	ttl := 10 * time.Minute
	err := store.StoreAuthorizationCode(ctx, authCode, ttl)
	require.NoError(t, err)

	// Retrieve authorization code
	retrievedCode, err := store.GetAuthorizationCode(ctx, authCode.Code)
	require.NoError(t, err)
	assert.Equal(t, authCode.Code, retrievedCode.Code)
	assert.Equal(t, authCode.ClientID, retrievedCode.ClientID)
	assert.Equal(t, authCode.UserID, retrievedCode.UserID)
	assert.Equal(t, authCode.Scopes, retrievedCode.Scopes)
	assert.Equal(t, authCode.CodeChallenge, retrievedCode.CodeChallenge)

	// Delete authorization code
	err = store.DeleteAuthorizationCode(ctx, authCode.Code)
	require.NoError(t, err)

	// Verify code is deleted
	_, err = store.GetAuthorizationCode(ctx, authCode.Code)
	assert.Error(t, err)
}

func testAccessTokenOperations(ctx context.Context, t *testing.T, store redisClient.Store) {
	// Create test access token
	accessToken := &models.AccessToken{
		Token:     "test-access-token-123",
		ClientID:  testClient,
		UserID:    testUser,
		Scopes:    []string{"read", "write"},
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
		TokenType: models.TokenTypeBearer,
		Claims:    map[string]interface{}{"custom": "value"},
		Revoked:   false,
	}

	// Store access token
	ttl := 15 * time.Minute
	err := store.StoreAccessToken(ctx, accessToken, ttl)
	require.NoError(t, err)

	// Retrieve access token
	retrievedToken, err := store.GetAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, accessToken.Token, retrievedToken.Token)
	assert.Equal(t, accessToken.ClientID, retrievedToken.ClientID)
	assert.Equal(t, accessToken.UserID, retrievedToken.UserID)
	assert.Equal(t, accessToken.Scopes, retrievedToken.Scopes)

	// Revoke access token
	err = store.RevokeAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)

	// Verify token is revoked
	revokedToken, err := store.GetAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)
	assert.True(t, revokedToken.Revoked)

	// Delete access token
	err = store.DeleteAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)

	// Verify token is deleted
	_, err = store.GetAccessToken(ctx, accessToken.Token)
	assert.Error(t, err)
}

func testRefreshTokenOperations(ctx context.Context, t *testing.T, store redisClient.Store) {
	// Create test refresh token
	refreshToken := &models.RefreshToken{
		Token:         "test-refresh-token-123",
		AccessToken:   "test-access-token-123",
		ClientID:      testClient,
		UserID:        testUser,
		Scopes:        []string{"read", "write"},
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		CreatedAt:     time.Now(),
		Revoked:       false,
		RotationCount: 0,
	}

	// Store refresh token
	ttl := 24 * time.Hour
	err := store.StoreRefreshToken(ctx, refreshToken, ttl)
	require.NoError(t, err)

	// Retrieve refresh token
	retrievedToken, err := store.GetRefreshToken(ctx, refreshToken.Token)
	require.NoError(t, err)
	assert.Equal(t, refreshToken.Token, retrievedToken.Token)
	assert.Equal(t, refreshToken.ClientID, retrievedToken.ClientID)
	assert.Equal(t, refreshToken.UserID, retrievedToken.UserID)
	assert.Equal(t, refreshToken.Scopes, retrievedToken.Scopes)

	// Revoke refresh token
	err = store.RevokeRefreshToken(ctx, refreshToken.Token)
	require.NoError(t, err)

	// Verify token is revoked
	revokedToken, err := store.GetRefreshToken(ctx, refreshToken.Token)
	require.NoError(t, err)
	assert.True(t, revokedToken.Revoked)

	// Delete refresh token
	err = store.DeleteRefreshToken(ctx, refreshToken.Token)
	require.NoError(t, err)

	// Verify token is deleted
	_, err = store.GetRefreshToken(ctx, refreshToken.Token)
	assert.Error(t, err)
}

func testSessionOperations(ctx context.Context, t *testing.T, store redisClient.Store) {
	// Create test session
	session := models.NewSession(testUser, testClient)
	session.Data["custom"] = "value"

	// Store session
	ttl := 1 * time.Hour
	err := store.StoreSession(ctx, session, ttl)
	require.NoError(t, err)

	// Retrieve session
	retrievedSession, err := store.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrievedSession.ID)
	assert.Equal(t, session.UserID, retrievedSession.UserID)
	assert.Equal(t, session.ClientID, retrievedSession.ClientID)
	assert.Equal(t, session.Data["custom"], retrievedSession.Data["custom"])

	// Delete session
	err = store.DeleteSession(ctx, session.ID)
	require.NoError(t, err)

	// Verify session is deleted
	_, err = store.GetSession(ctx, session.ID)
	assert.Error(t, err)
}

func testTokenBlacklist(ctx context.Context, t *testing.T, store redisClient.Store) {
	token := "test-blacklist-token-123"

	// Check token is not blacklisted initially
	blacklisted, err := store.IsTokenBlacklisted(ctx, token)
	require.NoError(t, err)
	assert.False(t, blacklisted)

	// Blacklist token
	ttl := 1 * time.Hour
	err = store.BlacklistToken(ctx, token, ttl)
	require.NoError(t, err)

	// Check token is now blacklisted
	blacklisted, err = store.IsTokenBlacklisted(ctx, token)
	require.NoError(t, err)
	assert.True(t, blacklisted)
}

func testClearAllSessions(ctx context.Context, t *testing.T, store redisClient.Store) {
	t.Run("EmptyStore", func(t *testing.T) {
		// Clear should work on empty store
		count, err := store.ClearAllSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("WithSessions", func(t *testing.T) {
		// Create test sessions
		for i := range 5 {
			session := models.NewSession("user-"+string(rune('a'+i)), testClient)
			err := store.StoreSession(ctx, session, time.Hour)
			require.NoError(t, err)
		}

		// Verify sessions exist
		stats, err := store.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 5, stats.TotalSessions)

		// Clear all sessions
		count, err := store.ClearAllSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5, count)

		// Verify sessions are cleared
		stats, err = store.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 0, stats.TotalSessions)
	})

	t.Run("DoesNotAffectOtherKeys", func(t *testing.T) {
		// Store a client (not a session)
		client := models.NewClient(
			"Test Client For ClearSessions",
			[]string{"http://localhost:3000/callback"},
			[]string{"read"},
			[]string{"authorization_code"},
		)
		err := store.StoreClient(ctx, client)
		require.NoError(t, err)

		// Store a session
		session := models.NewSession(testUser, testClient)
		err = store.StoreSession(ctx, session, time.Hour)
		require.NoError(t, err)

		// Clear sessions
		count, err := store.ClearAllSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Verify client still exists
		retrievedClient, err := store.GetClient(ctx, client.ID)
		require.NoError(t, err)
		assert.Equal(t, client.ID, retrievedClient.ID)

		// Cleanup
		_ = store.DeleteClient(ctx, client.ID)
	})
}
