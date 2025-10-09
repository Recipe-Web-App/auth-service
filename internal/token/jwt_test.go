package token_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/token"
)

const (
	jwtSecret  = "test-secret-key-for-jwt-testing-purposes-123456789" // pragma: allowlist secret
	issuer     = "test-issuer"
	testClient = "test-client"
	testUser   = "test-user"
)

func TestNewJWTService(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:             jwtSecret,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
		Issuer:             issuer,
		Algorithm:          "HS256",
	}

	service := token.NewJWTService(cfg)
	require.NotNil(t, service)

	jwtService, ok := service.(*token.JWTService)
	require.True(t, ok)
	assert.NotNil(t, jwtService)
}

func TestJWTServiceGenerateAccessToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:             jwtSecret,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
		Issuer:             issuer,
		Algorithm:          "HS256",
	}

	service := token.NewJWTService(cfg)

	tests := []struct {
		name     string
		clientID string
		userID   string
		scopes   []string
		claims   map[string]interface{}
		wantErr  bool
	}{
		{
			name:     "valid_token",
			clientID: testClient,
			userID:   testUser,
			scopes:   []string{"read", "write"},
			claims:   map[string]interface{}{"custom": "value"},
			wantErr:  false,
		},
		{
			name:     "empty_client_id",
			clientID: "",
			userID:   testUser,
			scopes:   []string{"read"},
			claims:   nil,
			wantErr:  false,
		},
		{
			name:     "empty_user_id",
			clientID: testClient,
			userID:   "",
			scopes:   []string{"read"},
			claims:   nil,
			wantErr:  false,
		},
		{
			name:     "nil_claims",
			clientID: testClient,
			userID:   testUser,
			scopes:   []string{"read"},
			claims:   nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, accessToken, err := service.GenerateAccessToken(
				tt.clientID, tt.userID, tt.scopes, tt.claims,
			)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, tokenString)
			require.NotNil(t, accessToken)

			// Verify token structure
			assert.Equal(t, tokenString, accessToken.Token)
			assert.Equal(t, tt.clientID, accessToken.ClientID)
			assert.Equal(t, tt.userID, accessToken.UserID)
			assert.Equal(t, tt.scopes, accessToken.Scopes)
			// Verify claims
			if tt.claims != nil {
				assert.Equal(t, tt.claims, accessToken.Claims)
			}

			// Verify JWT structure
			assert.Len(t, strings.Split(tokenString, "."), 3)
		})
	}
}

func TestJWTServiceValidateAccessToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:             jwtSecret,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
		Issuer:             issuer,
		Algorithm:          "HS256",
	}

	service := token.NewJWTService(cfg)

	// Generate a valid token first
	validTokenString, _, err := service.GenerateAccessToken(testClient, testUser, []string{"read"}, nil)
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
	}{
		{
			name:        "valid_token",
			tokenString: validTokenString,
			wantErr:     false,
		},
		{
			name:        "empty_token",
			tokenString: "",
			wantErr:     true,
		},
		{
			name:        "invalid_format",
			tokenString: "invalid.token",
			wantErr:     true,
		},
		{
			name:        "invalid_signature",
			tokenString: strings.Replace(validTokenString, validTokenString[len(validTokenString)-5:], "wrong", 1),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessToken, jwtToken, validateErr := service.ValidateAccessToken(tt.tokenString)

			if tt.wantErr {
				require.Error(t, validateErr)
				assert.Nil(t, accessToken)
				assert.Nil(t, jwtToken)
				return
			}

			require.NoError(t, validateErr)
			require.NotNil(t, accessToken)
			require.NotNil(t, jwtToken)

			assert.Equal(t, tt.tokenString, accessToken.Token)
			assert.Equal(t, testClient, accessToken.ClientID)
			assert.Equal(t, testUser, accessToken.UserID)
			assert.Equal(t, []string{"read"}, accessToken.Scopes)
			assert.True(t, jwtToken.Valid)
		})
	}
}

func TestJWTServiceGenerateRefreshToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:             jwtSecret,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
		Issuer:             issuer,
		Algorithm:          "HS256",
	}

	service := token.NewJWTService(cfg)

	tokenString, refreshToken, err := service.GenerateRefreshToken(
		"access-token", testClient, testUser, []string{"read", "write"},
	)

	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	require.NotNil(t, refreshToken)

	// Verify refresh token structure
	assert.Equal(t, tokenString, refreshToken.Token)
	assert.Equal(t, "access-token", refreshToken.AccessToken)
	assert.Equal(t, testClient, refreshToken.ClientID)
	assert.Equal(t, testUser, refreshToken.UserID)
	assert.Equal(t, []string{"read", "write"}, refreshToken.Scopes)
	assert.False(t, refreshToken.Revoked)
	assert.Equal(t, 0, refreshToken.RotationCount)
	assert.WithinDuration(t, time.Now().Add(cfg.RefreshTokenExpiry), refreshToken.ExpiresAt, 5*time.Second)

	// Refresh token should be opaque (base64 encoded, not JWT)
	assert.NotEqual(t, 3, len(strings.Split(tokenString, ".")))
}

func TestJWTServiceGenerateAuthorizationCode(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:             jwtSecret,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 24 * time.Hour,
		Issuer:             issuer,
		Algorithm:          "HS256",
	}

	service := token.NewJWTService(cfg)

	code, authCode, err := service.GenerateAuthorizationCode(token.AuthorizationCodeInput{
		ClientID:            testClient,
		UserID:              testUser,
		RedirectURI:         "http://localhost:3000/callback",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		State:               "state123",
		Nonce:               "nonce456",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, code)
	require.NotNil(t, authCode)

	// Verify authorization code structure
	assert.Equal(t, code, authCode.Code)
	assert.Equal(t, testClient, authCode.ClientID)
	assert.Equal(t, testUser, authCode.UserID)
	assert.Equal(t, "http://localhost:3000/callback", authCode.RedirectURI)
	assert.Equal(t, []string{"openid", "profile"}, authCode.Scopes)
	assert.Equal(t, "challenge", authCode.CodeChallenge)
	assert.Equal(t, "S256", authCode.CodeChallengeMethod)
	assert.Equal(t, "state123", authCode.State)
	assert.Equal(t, "nonce456", authCode.Nonce)
	assert.False(t, authCode.Used)
	assert.True(t, authCode.ExpiresAt.After(time.Now()))

	// Authorization code should be opaque
	assert.NotEqual(t, 3, len(strings.Split(code, ".")))
}

func TestJWTServiceGenerateOpaqueToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:    "test-secret",
		Algorithm: "HS256",
	}

	service := token.NewJWTService(cfg)

	token1, err1 := service.GenerateOpaqueToken()
	token2, err2 := service.GenerateOpaqueToken()

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)
	assert.NotEqual(t, token1, token2) // Should be unique

	// Should be base64 URL encoded
	assert.NotContains(t, token1, "/")
	assert.NotContains(t, token1, "+")
	assert.NotContains(t, token2, "/")
	assert.NotContains(t, token2, "+")
}

func TestJWTServiceGenerateIDToken(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:            jwtSecret,
		AccessTokenExpiry: 15 * time.Minute,
		Issuer:            issuer,
		Algorithm:         "HS256",
	}

	service := token.NewJWTService(cfg)

	tests := []struct {
		name     string
		userID   string
		clientID string
		nonce    string
		claims   map[string]interface{}
	}{
		{
			name:     "with_nonce_and_claims",
			userID:   testUser,
			clientID: testClient,
			nonce:    "nonce123",
			claims:   map[string]interface{}{"name": "John Doe", "email": "john@example.com"},
		},
		{
			name:     "without_nonce",
			userID:   testUser,
			clientID: testClient,
			nonce:    "",
			claims:   map[string]interface{}{"name": "Jane Doe"},
		},
		{
			name:     "minimal",
			userID:   testUser,
			clientID: testClient,
			nonce:    "",
			claims:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idToken, err := service.GenerateIDToken(tt.userID, tt.clientID, tt.nonce, tt.claims)

			require.NoError(t, err)
			assert.NotEmpty(t, idToken)

			// ID token should be a JWT
			parts := strings.Split(idToken, ".")
			assert.Len(t, parts, 3)

			// Parse the token to verify claims
			parsedToken, err := jwt.ParseWithClaims(idToken, &token.Claims{}, func(_ *jwt.Token) (interface{}, error) {
				return []byte(cfg.Secret), nil
			})
			require.NoError(t, err)
			require.True(t, parsedToken.Valid)

			claims, ok := parsedToken.Claims.(*token.Claims)
			require.True(t, ok)

			assert.Equal(t, tt.userID, claims.UserID)
			assert.Equal(t, tt.clientID, claims.ClientID)
			assert.Equal(t, "id_token", claims.Type)
			assert.Equal(t, cfg.Issuer, claims.Issuer)

			if tt.nonce != "" && tt.claims != nil {
				assert.Equal(t, tt.nonce, claims.Claims["nonce"])
			}
		})
	}
}

func TestJWTServiceExtractClaims(t *testing.T) {
	cfg := &config.JWTConfig{
		Secret:            jwtSecret,
		Algorithm:         "HS256",
		Issuer:            issuer,
		AccessTokenExpiry: 15 * time.Minute, // Add expiry to prevent immediate expiration
	}

	service := token.NewJWTService(cfg)

	// Generate a token first
	tokenString, _, err := service.GenerateAccessToken(testClient, testUser, []string{"read"}, map[string]interface{}{
		"custom": "value",
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
	}{
		{
			name:        "valid_token",
			tokenString: tokenString,
			wantErr:     false,
		},
		{
			name:        "invalid_token",
			tokenString: "invalid.jwt.token",
			wantErr:     true,
		},
		{
			name:        "empty_token",
			tokenString: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, extractErr := service.ExtractClaims(tt.tokenString)

			if tt.wantErr {
				require.Error(t, extractErr)
				assert.Nil(t, claims)
				return
			}

			require.NoError(t, extractErr)
			require.NotNil(t, claims)

			// Verify standard claims
			assert.Equal(t, issuer, claims["iss"])
			assert.Equal(t, testUser, claims["sub"])
			assert.Contains(t, claims, "iat")
			assert.Contains(t, claims, "exp")
			assert.Contains(t, claims, "jti")
		})
	}
}
