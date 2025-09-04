package models_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	models "github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
)

const (
	testRedirectURL = "http://localhost:3000/callback"
	testHost        = "http://localhost"
)

func TestNewClient(t *testing.T) {
	name := "Test Client"
	redirectURIs := []string{testRedirectURL}
	scopes := []string{"read", "write"}
	grantTypes := []string{"authorization_code", "refresh_token"}

	client := models.NewClient(name, redirectURIs, scopes, grantTypes)

	require.NotNil(t, client)
	assert.NotEmpty(t, client.ID)
	assert.NotEmpty(t, client.Secret)
	assert.Equal(t, name, client.Name)
	assert.Equal(t, redirectURIs, client.RedirectURIs)
	assert.Equal(t, scopes, client.Scopes)
	assert.Equal(t, grantTypes, client.GrantTypes)
	assert.True(t, client.IsActive)
	assert.False(t, client.CreatedAt.IsZero())
	assert.False(t, client.UpdatedAt.IsZero())
	assert.Equal(t, client.CreatedAt, client.UpdatedAt)
}

func TestNewClientWithNewScopes(t *testing.T) {
	tests := []struct {
		name       string
		clientName string
		scopes     []string
	}{
		{
			name:       "client_with_media_scopes",
			clientName: "Media Service Client",
			scopes:     []string{"media:read", "media:write"},
		},
		{
			name:       "client_with_user_scopes",
			clientName: "User Service Client",
			scopes:     []string{"user:read", "user:write"},
		},
		{
			name:       "client_with_admin_scope",
			clientName: "Admin Client",
			scopes:     []string{"admin"},
		},
		{
			name:       "client_with_mixed_scopes",
			clientName: "Mixed Service Client",
			scopes:     []string{"read", "write", "media:read", "user:write", "admin"},
		},
		{
			name:       "client_with_all_new_scopes",
			clientName: "Full Scope Client",
			scopes:     []string{"media:read", "media:write", "user:read", "user:write", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURIs := []string{testRedirectURL}
			grantTypes := []string{"authorization_code", "client_credentials"}

			client := models.NewClient(tt.clientName, redirectURIs, tt.scopes, grantTypes)

			require.NotNil(t, client)
			assert.NotEmpty(t, client.ID)
			assert.NotEmpty(t, client.Secret)
			assert.Equal(t, tt.clientName, client.Name)
			assert.Equal(t, redirectURIs, client.RedirectURIs)
			assert.Equal(t, tt.scopes, client.Scopes)
			assert.Equal(t, grantTypes, client.GrantTypes)
			assert.True(t, client.IsActive)
			assert.False(t, client.CreatedAt.IsZero())
			assert.False(t, client.UpdatedAt.IsZero())

			// Test that the client has all expected scopes
			for _, scope := range tt.scopes {
				assert.True(t, client.HasScope(scope), "Client should have scope: %s", scope)
			}
		})
	}
}

func TestNewAuthorizationCode(t *testing.T) {
	clientID := "test-client"
	userID := "test-user"
	redirectURI := testRedirectURL
	scopes := []string{"openid", "profile"}
	codeChallenge := "challenge"
	codeChallengeMethod := "S256"
	state := "random-state"
	nonce := "random-nonce"
	expiresAt := time.Now().Add(10 * time.Minute)

	authCode := models.NewAuthorizationCode(models.AuthorizationCodeParams{
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		State:               state,
		Nonce:               nonce,
		ExpiresAt:           expiresAt,
	})

	require.NotNil(t, authCode)
	assert.NotEmpty(t, authCode.Code)
	assert.Equal(t, clientID, authCode.ClientID)
	assert.Equal(t, userID, authCode.UserID)
	assert.Equal(t, redirectURI, authCode.RedirectURI)
	assert.Equal(t, scopes, authCode.Scopes)
	assert.Equal(t, codeChallenge, authCode.CodeChallenge)
	assert.Equal(t, codeChallengeMethod, authCode.CodeChallengeMethod)
	assert.Equal(t, state, authCode.State)
	assert.Equal(t, nonce, authCode.Nonce)
	assert.Equal(t, expiresAt, authCode.ExpiresAt)
	assert.False(t, authCode.Used)
	assert.False(t, authCode.CreatedAt.IsZero())
	assert.NotNil(t, authCode.Claims)
}

func TestNewAuthorizationCodeWithNewScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
	}{
		{
			name:   "auth_code_with_media_scopes",
			scopes: []string{"media:read", "media:write"},
		},
		{
			name:   "auth_code_with_user_scopes",
			scopes: []string{"user:read", "user:write"},
		},
		{
			name:   "auth_code_with_admin_scope",
			scopes: []string{"admin"},
		},
		{
			name:   "auth_code_with_mixed_new_scopes",
			scopes: []string{"openid", "profile", "media:read", "user:write", "admin"},
		},
		{
			name:   "auth_code_with_all_new_scopes",
			scopes: []string{"media:read", "media:write", "user:read", "user:write", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientID := "test-client"
			userID := "test-user"
			redirectURI := testRedirectURL
			codeChallenge := "challenge"
			codeChallengeMethod := "S256"
			state := "random-state"
			nonce := "random-nonce"
			expiresAt := time.Now().Add(10 * time.Minute)

			authCode := models.NewAuthorizationCode(models.AuthorizationCodeParams{
				ClientID:            clientID,
				UserID:              userID,
				RedirectURI:         redirectURI,
				Scopes:              tt.scopes,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
				State:               state,
				Nonce:               nonce,
				ExpiresAt:           expiresAt,
			})

			require.NotNil(t, authCode)
			assert.NotEmpty(t, authCode.Code)
			assert.Equal(t, clientID, authCode.ClientID)
			assert.Equal(t, userID, authCode.UserID)
			assert.Equal(t, redirectURI, authCode.RedirectURI)
			assert.Equal(t, tt.scopes, authCode.Scopes)
			assert.Equal(t, codeChallenge, authCode.CodeChallenge)
			assert.Equal(t, codeChallengeMethod, authCode.CodeChallengeMethod)
			assert.Equal(t, state, authCode.State)
			assert.Equal(t, nonce, authCode.Nonce)
			assert.Equal(t, expiresAt, authCode.ExpiresAt)
			assert.False(t, authCode.Used)
			assert.False(t, authCode.CreatedAt.IsZero())
			assert.NotNil(t, authCode.Claims)
		})
	}
}

func TestNewSession(t *testing.T) {
	userID := "test-user"
	clientID := "test-client"

	session := models.NewSession(userID, clientID)

	require.NotNil(t, session)
	assert.NotEmpty(t, session.ID)
	assert.Equal(t, userID, session.UserID)
	assert.Equal(t, clientID, session.ClientID)
	assert.NotNil(t, session.Data)
	assert.False(t, session.CreatedAt.IsZero())
	assert.False(t, session.UpdatedAt.IsZero())
	assert.True(t, session.ExpiresAt.After(time.Now()))
}

func TestClientValidateRedirectURI(t *testing.T) {
	client := &models.Client{
		RedirectURIs: []string{
			testRedirectURL,
			"https://example.com/oauth/callback",
		},
	}

	tests := []struct {
		name        string
		uri         string
		expectValid bool
	}{
		{
			name:        "valid_uri_first",
			uri:         testRedirectURL,
			expectValid: true,
		},
		{
			name:        "valid_uri_second",
			uri:         "https://example.com/oauth/callback",
			expectValid: true,
		},
		{
			name:        "invalid_uri",
			uri:         "http://malicious.com/callback",
			expectValid: false,
		},
		{
			name:        "empty_uri",
			uri:         "",
			expectValid: false,
		},
		{
			name:        "partial_match",
			uri:         "http://localhost:3000",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.ValidateRedirectURI(tt.uri)
			assert.Equal(t, tt.expectValid, result)
		})
	}
}

func TestClientHasScope(t *testing.T) {
	client := &models.Client{
		Scopes: []string{"read", "write", "admin", "media:read", "media:write", "user:read", "user:write"},
	}

	tests := []struct {
		name        string
		scope       string
		expectValid bool
	}{
		{
			name:        "valid_scope_read",
			scope:       "read",
			expectValid: true,
		},
		{
			name:        "valid_scope_write",
			scope:       "write",
			expectValid: true,
		},
		{
			name:        "valid_scope_admin",
			scope:       "admin",
			expectValid: true,
		},
		{
			name:        "valid_scope_media_read",
			scope:       "media:read",
			expectValid: true,
		},
		{
			name:        "valid_scope_media_write",
			scope:       "media:write",
			expectValid: true,
		},
		{
			name:        "valid_scope_user_read",
			scope:       "user:read",
			expectValid: true,
		},
		{
			name:        "valid_scope_user_write",
			scope:       "user:write",
			expectValid: true,
		},
		{
			name:        "invalid_scope",
			scope:       "delete",
			expectValid: false,
		},
		{
			name:        "empty_scope",
			scope:       "",
			expectValid: false,
		},
		{
			name:        "case_sensitive_media_scope",
			scope:       "Media:Read",
			expectValid: false,
		},
		{
			name:        "invalid_colon_scope",
			scope:       "invalid:scope",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.HasScope(tt.scope)
			assert.Equal(t, tt.expectValid, result)
		})
	}
}

func TestClientHasGrantType(t *testing.T) {
	client := &models.Client{
		GrantTypes: []string{"authorization_code", "refresh_token"},
	}

	tests := []struct {
		name        string
		grantType   models.GrantType
		expectValid bool
	}{
		{
			name:        "valid_authorization_code",
			grantType:   models.GrantTypeAuthorizationCode,
			expectValid: true,
		},
		{
			name:        "valid_refresh_token",
			grantType:   models.GrantTypeRefreshToken,
			expectValid: true,
		},
		{
			name:        "invalid_client_credentials",
			grantType:   models.GrantTypeClientCredentials,
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.HasGrantType(tt.grantType)
			assert.Equal(t, tt.expectValid, result)
		})
	}
}

func TestAuthorizationCodeIsExpired(t *testing.T) {
	tests := []struct {
		name          string
		expiresAt     time.Time
		expectExpired bool
	}{
		{
			name:          "not_expired",
			expiresAt:     time.Now().Add(5 * time.Minute),
			expectExpired: false,
		},
		{
			name:          "expired",
			expiresAt:     time.Now().Add(-5 * time.Minute),
			expectExpired: true,
		},
		{
			name:          "just_expired",
			expiresAt:     time.Now().Add(-1 * time.Second),
			expectExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCode := &models.AuthorizationCode{
				ExpiresAt: tt.expiresAt,
			}
			result := authCode.IsExpired()
			assert.Equal(t, tt.expectExpired, result)
		})
	}
}

func TestAccessTokenIsExpired(t *testing.T) {
	tests := []struct {
		name          string
		expiresAt     time.Time
		expectExpired bool
	}{
		{
			name:          "not_expired",
			expiresAt:     time.Now().Add(15 * time.Minute),
			expectExpired: false,
		},
		{
			name:          "expired",
			expiresAt:     time.Now().Add(-1 * time.Minute),
			expectExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &models.AccessToken{
				ExpiresAt: tt.expiresAt,
			}
			result := token.IsExpired()
			assert.Equal(t, tt.expectExpired, result)
		})
	}
}

func TestRefreshTokenIsExpired(t *testing.T) {
	tests := []struct {
		name          string
		expiresAt     time.Time
		expectExpired bool
	}{
		{
			name:          "not_expired",
			expiresAt:     time.Now().Add(24 * time.Hour),
			expectExpired: false,
		},
		{
			name:          "expired",
			expiresAt:     time.Now().Add(-1 * time.Hour),
			expectExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &models.RefreshToken{
				ExpiresAt: tt.expiresAt,
			}
			result := token.IsExpired()
			assert.Equal(t, tt.expectExpired, result)
		})
	}
}

func TestSessionIsExpired(t *testing.T) {
	tests := []struct {
		name          string
		expiresAt     time.Time
		expectExpired bool
	}{
		{
			name:          "not_expired",
			expiresAt:     time.Now().Add(1 * time.Hour),
			expectExpired: false,
		},
		{
			name:          "expired",
			expiresAt:     time.Now().Add(-1 * time.Hour),
			expectExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &models.Session{
				ExpiresAt: tt.expiresAt,
			}
			result := session.IsExpired()
			assert.Equal(t, tt.expectExpired, result)
		})
	}
}

func TestGrantTypeConstants(t *testing.T) {
	assert.Equal(t, "authorization_code", string(models.GrantTypeAuthorizationCode))
	assert.Equal(t, "client_credentials", string(models.GrantTypeClientCredentials))
	assert.Equal(t, "refresh_token", string(models.GrantTypeRefreshToken))
}

func TestResponseTypeConstants(t *testing.T) {
	assert.Equal(t, "code", string(models.ResponseTypeCode))
}

func TestTokenTypeConstants(t *testing.T) {
	assert.Equal(t, "Bearer", string(models.TokenTypeBearer))
}

func TestUniqueIDGeneration(t *testing.T) {
	// Test that multiple calls generate unique IDs
	client1 := models.NewClient("Test1", []string{testHost}, []string{"read"}, []string{"authorization_code"})
	client2 := models.NewClient("Test2", []string{testHost}, []string{"read"}, []string{"authorization_code"})

	assert.NotEqual(t, client1.ID, client2.ID)
	assert.NotEqual(t, client1.Secret, client2.Secret)

	// Test authorization codes
	authCode1 := models.NewAuthorizationCode(models.AuthorizationCodeParams{
		ClientID:            "client1",
		UserID:              "user1",
		RedirectURI:         testHost,
		Scopes:              []string{"read"},
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		State:               "",
		Nonce:               "",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})
	authCode2 := models.NewAuthorizationCode(models.AuthorizationCodeParams{
		ClientID:            "client2",
		UserID:              "user2",
		RedirectURI:         testHost,
		Scopes:              []string{"write"},
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		State:               "",
		Nonce:               "",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})

	assert.NotEqual(t, authCode1.Code, authCode2.Code)

	// Test sessions
	session1 := models.NewSession("user1", "client1")
	session2 := models.NewSession("user2", "client2")

	assert.NotEqual(t, session1.ID, session2.ID)
}
