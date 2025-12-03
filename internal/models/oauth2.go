// Package models defines the core data structures for OAuth2 authentication
// including clients, tokens, authorization codes, sessions, and request/response models.
// All models support JSON marshaling and Redis storage with appropriate struct tags.
package models

import (
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultSessionExpiry is the default session duration.
	DefaultSessionExpiry = 24 * time.Hour
)

// GrantType represents the OAuth2 grant type for token requests.
type GrantType string

// ResponseType represents the OAuth2 response type for authorization requests.
type ResponseType string

// TokenType represents the type of access token (typically "Bearer").
type TokenType string

const (
	// GrantTypeAuthorizationCode represents the authorization code grant type.
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeClientCredentials represents the client credentials grant type.
	GrantTypeClientCredentials GrantType = "client_credentials"
	// GrantTypeRefreshToken represents the refresh token grant type.
	GrantTypeRefreshToken GrantType = "refresh_token"

	// ResponseTypeCode represents the authorization code response type.
	ResponseTypeCode ResponseType = "code"

	// TokenTypeBearer represents the Bearer token type.
	TokenTypeBearer TokenType = "Bearer"
)

// Client represents an OAuth2 client with its configuration and credentials.
// The Secret field is excluded from JSON serialization for security.
type Client struct {
	// ID is the unique client identifier.
	ID string `json:"id"            redis:"id"`
	// Secret is the client secret for authentication (excluded from JSON).
	Secret string `json:"-"             redis:"secret"`
	// Name is the human-readable client name.
	Name string `json:"name"          redis:"name"`
	// RedirectURIs are the allowed redirect URIs for this client.
	RedirectURIs []string `json:"redirect_uris" redis:"redirect_uris"`
	// Scopes are the OAuth2 scopes this client is allowed to request.
	Scopes []string `json:"scopes"        redis:"scopes"`
	// GrantTypes are the OAuth2 grant types this client supports.
	GrantTypes []string `json:"grant_types"   redis:"grant_types"`
	// CreatedAt is the client creation timestamp.
	CreatedAt time.Time `json:"created_at"    redis:"created_at"`
	// UpdatedAt is the last modification timestamp.
	UpdatedAt time.Time `json:"updated_at"    redis:"updated_at"`
	// IsActive indicates if the client is currently active.
	IsActive bool `json:"is_active"     redis:"is_active"`
	// CreatedBy tracks who or what system created this client (for audit trail).
	CreatedBy *string `json:"created_by,omitempty" redis:"created_by"`
	// Metadata provides extensible storage for additional client-specific data.
	Metadata map[string]interface{} `json:"metadata,omitempty"   redis:"metadata"`
}

// ClientCacheEntry is used for internal caching and includes the secret hash.
// Unlike Client, this struct includes the secret field in JSON serialization.
// This should NEVER be used in HTTP responses - only for Redis caching.
type ClientCacheEntry struct {
	ID           string                 `json:"id"`
	Secret       string                 `json:"secret"` // Included for caching (unlike Client)
	Name         string                 `json:"name"`
	RedirectURIs []string               `json:"redirect_uris"`
	Scopes       []string               `json:"scopes"`
	GrantTypes   []string               `json:"grant_types"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	IsActive     bool                   `json:"is_active"`
	CreatedBy    *string                `json:"created_by,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ToClient converts a cache entry to a Client (for internal use).
func (c *ClientCacheEntry) ToClient() *Client {
	return &Client{
		ID:           c.ID,
		Secret:       c.Secret,
		Name:         c.Name,
		RedirectURIs: c.RedirectURIs,
		Scopes:       c.Scopes,
		GrantTypes:   c.GrantTypes,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		IsActive:     c.IsActive,
		CreatedBy:    c.CreatedBy,
		Metadata:     c.Metadata,
	}
}

// ToCacheEntry converts a Client to a cache entry for Redis storage.
func (c *Client) ToCacheEntry() *ClientCacheEntry {
	return &ClientCacheEntry{
		ID:           c.ID,
		Secret:       c.Secret,
		Name:         c.Name,
		RedirectURIs: c.RedirectURIs,
		Scopes:       c.Scopes,
		GrantTypes:   c.GrantTypes,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		IsActive:     c.IsActive,
		CreatedBy:    c.CreatedBy,
		Metadata:     c.Metadata,
	}
}

// AuthorizationCode represents a temporary authorization code used in the
// OAuth2 authorization code flow, including PKCE support.
type AuthorizationCode struct {
	// Code is the unique authorization code string.
	Code string `json:"code"                  redis:"code"`
	// ClientID is the ID of the client that requested this code.
	ClientID string `json:"client_id"             redis:"client_id"`
	// UserID is the ID of the user who authorized the request.
	UserID string `json:"user_id"               redis:"user_id"`
	// RedirectURI is the redirect URI used in the authorization request.
	RedirectURI string `json:"redirect_uri"          redis:"redirect_uri"`
	// Scopes are the authorized scopes for this code.
	Scopes []string `json:"scopes"                redis:"scopes"`
	// CodeChallenge is the PKCE code challenge.
	CodeChallenge string `json:"code_challenge"        redis:"code_challenge"`
	// CodeChallengeMethod is the PKCE code challenge method (plain or S256).
	CodeChallengeMethod string `json:"code_challenge_method" redis:"code_challenge_method"`
	// State is the client-provided state parameter.
	State string `json:"state"                 redis:"state"`
	// Nonce is the OpenID Connect nonce parameter.
	Nonce string `json:"nonce"                 redis:"nonce"`
	// ExpiresAt is when this authorization code expires.
	ExpiresAt time.Time `json:"expires_at"            redis:"expires_at"`
	// CreatedAt is when this authorization code was created.
	CreatedAt time.Time `json:"created_at"            redis:"created_at"`
	// Used indicates if this authorization code has been exchanged for tokens.
	Used bool `json:"used"                  redis:"used"`
	// Claims contains additional claims to include in issued tokens.
	Claims map[string]interface{} `json:"claims"                redis:"claims"`
}

// AccessToken represents an OAuth2 access token with associated metadata.
type AccessToken struct {
	// Token is the access token string (typically a JWT).
	Token string `json:"token"             redis:"token"`
	// ClientID is the ID of the client this token was issued to.
	ClientID string `json:"client_id"         redis:"client_id"`
	// UserID is the ID of the user (empty for client credentials tokens).
	UserID string `json:"user_id,omitempty" redis:"user_id"`
	// Scopes are the granted scopes for this token.
	Scopes []string `json:"scopes"            redis:"scopes"`
	// ExpiresAt is when this access token expires.
	ExpiresAt time.Time `json:"expires_at"        redis:"expires_at"`
	// CreatedAt is when this access token was created.
	CreatedAt time.Time `json:"created_at"        redis:"created_at"`
	// TokenType is the type of token (typically "Bearer").
	TokenType TokenType `json:"token_type"        redis:"token_type"`
	// Claims contains additional claims included in the token.
	Claims map[string]interface{} `json:"claims"            redis:"claims"`
	// Revoked indicates if this token has been revoked.
	Revoked bool `json:"revoked"           redis:"revoked"`
}

// RefreshToken represents an opaque refresh token used to obtain new access tokens.
// Refresh tokens have longer lifetimes than access tokens and support rotation for enhanced security.
type RefreshToken struct {
	// Token is the refresh token string (opaque identifier).
	Token string `json:"token"                  redis:"token"`
	// AccessToken is the associated access token that this refresh token can renew.
	AccessToken string `json:"access_token"           redis:"access_token"`
	// ClientID is the ID of the client this refresh token was issued to.
	ClientID string `json:"client_id"              redis:"client_id"`
	// UserID is the ID of the user (empty for client credentials tokens).
	UserID string `json:"user_id,omitempty"      redis:"user_id"`
	// Scopes are the granted scopes for this refresh token.
	Scopes []string `json:"scopes"                 redis:"scopes"`
	// ExpiresAt is when this refresh token expires.
	ExpiresAt time.Time `json:"expires_at"             redis:"expires_at"`
	// CreatedAt is when this refresh token was created.
	CreatedAt time.Time `json:"created_at"             redis:"created_at"`
	// LastUsedAt is when this refresh token was last used to obtain new tokens.
	LastUsedAt *time.Time `json:"last_used_at,omitempty" redis:"last_used_at"`
	// Revoked indicates if this refresh token has been revoked.
	Revoked bool `json:"revoked"                redis:"revoked"`
	// RotationCount tracks how many times this token has been rotated for security.
	RotationCount int `json:"rotation_count"         redis:"rotation_count"`
}

// Session represents a user session during the OAuth2 authorization flow.
// Sessions are used to maintain state between authorization requests and user consent.
type Session struct {
	// ID is the unique session identifier.
	ID string `json:"id"         redis:"id"`
	// UserID is the ID of the authenticated user.
	UserID string `json:"user_id"    redis:"user_id"`
	// ClientID is the ID of the client requesting authorization.
	ClientID string `json:"client_id"  redis:"client_id"`
	// Data contains arbitrary session data for the authorization flow.
	Data map[string]interface{} `json:"data"       redis:"data"`
	// ExpiresAt is when this session expires.
	ExpiresAt time.Time `json:"expires_at" redis:"expires_at"`
	// CreatedAt is when this session was created.
	CreatedAt time.Time `json:"created_at" redis:"created_at"`
	// UpdatedAt is when this session was last updated.
	UpdatedAt time.Time `json:"updated_at" redis:"updated_at"`
}

// TokenRequest represents a request to the token endpoint for obtaining access tokens.
// Supports all OAuth2 grant types including authorization code, client credentials, and refresh token.
type TokenRequest struct {
	// GrantType specifies the OAuth2 grant type being used.
	GrantType GrantType `json:"grant_type"              form:"grant_type"`
	// Code is the authorization code (required for authorization_code grant).
	Code string `json:"code,omitempty"          form:"code"`
	// RedirectURI must match the redirect URI used in the authorization request.
	RedirectURI string `json:"redirect_uri,omitempty"  form:"redirect_uri"`
	// ClientID is the client identifier.
	ClientID string `json:"client_id"               form:"client_id"`
	// ClientSecret is the client secret for authentication (optional for public clients).
	ClientSecret string `json:"client_secret,omitempty" form:"client_secret"`
	// RefreshToken is used to obtain new access tokens (required for refresh_token grant).
	RefreshToken string `json:"refresh_token,omitempty" form:"refresh_token"`
	// Scope specifies the requested scopes (space-delimited).
	Scope string `json:"scope,omitempty"         form:"scope"`
	// CodeVerifier is the PKCE code verifier for public clients.
	CodeVerifier string `json:"code_verifier,omitempty" form:"code_verifier"`
}

// TokenResponse represents a successful response from the token endpoint.
// Contains the issued access token and associated metadata as per OAuth2 specification.
type TokenResponse struct {
	// AccessToken is the issued access token.
	AccessToken string `json:"access_token"`
	// TokenType is the type of token issued (typically "Bearer").
	TokenType TokenType `json:"token_type"`
	// ExpiresIn is the lifetime of the access token in seconds.
	ExpiresIn int `json:"expires_in"`
	// RefreshToken is issued if the client is authorized to receive one.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Scope contains the granted scopes (space-delimited).
	Scope string `json:"scope,omitempty"`
	// IDToken is the OpenID Connect ID token (if OpenID scope was requested).
	IDToken string `json:"id_token,omitempty"`
}

// AuthorizeRequest represents a request to the authorization endpoint.
// Initiates the OAuth2 authorization code flow with optional PKCE and OpenID Connect support.
type AuthorizeRequest struct {
	// ResponseType specifies the desired response type (typically "code").
	ResponseType ResponseType `json:"response_type"                   form:"response_type"`
	// ClientID is the client identifier.
	ClientID string `json:"client_id"                       form:"client_id"`
	// RedirectURI is where the user will be redirected after authorization.
	RedirectURI string `json:"redirect_uri"                    form:"redirect_uri"`
	// Scope contains the requested scopes (space-delimited).
	Scope string `json:"scope,omitempty"                 form:"scope"`
	// State is an opaque value for CSRF protection and state maintenance.
	State string `json:"state,omitempty"                 form:"state"`
	// Nonce is used in OpenID Connect for replay attack prevention.
	Nonce string `json:"nonce,omitempty"                 form:"nonce"`
	// CodeChallenge is the PKCE code challenge for public clients.
	CodeChallenge string `json:"code_challenge,omitempty"        form:"code_challenge"`
	// CodeChallengeMethod specifies how the code challenge was generated (plain or S256).
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" form:"code_challenge_method"`
}

// AuthorizeResponse represents a successful response from the authorization endpoint.
// Contains the authorization code that can be exchanged for tokens.
type AuthorizeResponse struct {
	// Code is the authorization code that can be exchanged for an access token.
	Code string `json:"code"`
	// State is the state parameter from the authorization request for CSRF protection.
	State string `json:"state,omitempty"`
}

// ErrorResponse represents an OAuth2 error response as defined in RFC 6749.
// Used to communicate errors from authorization and token endpoints.
type ErrorResponse struct {
	// Error is the error code as defined in the OAuth2 specification.
	Error string `json:"error"`
	// ErrorDescription provides additional human-readable error information.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI provides a URI with more information about the error.
	ErrorURI string `json:"error_uri,omitempty"`
	// State is included if the error occurred during authorization with state parameter.
	State string `json:"state,omitempty"`
}

// IntrospectionRequest represents a request to the token introspection endpoint (RFC 7662).
// Used to determine the active state and metadata of a given token.
type IntrospectionRequest struct {
	// Token is the token to be introspected.
	Token string `json:"token"                     form:"token"`
	// TokenTypeHint provides a hint about the type of token being introspected.
	TokenTypeHint string `json:"token_type_hint,omitempty" form:"token_type_hint"`
	// ClientID is the client identifier for authentication.
	ClientID string `json:"client_id"                 form:"client_id"`
	// ClientSecret is the client secret for authentication.
	ClientSecret string `json:"client_secret,omitempty"   form:"client_secret"`
}

// IntrospectionResponse represents a response from the token introspection endpoint (RFC 7662).
// Provides metadata about the token including its active state and associated claims.
type IntrospectionResponse struct {
	// Active indicates whether the token is currently active.
	Active bool `json:"active"`
	// ClientID is the client identifier the token was issued to.
	ClientID string `json:"client_id,omitempty"`
	// Username is the human-readable identifier for the resource owner.
	Username string `json:"username,omitempty"`
	// Scope contains the scopes associated with the token (space-delimited).
	Scope string `json:"scope,omitempty"`
	// TokenType is the type of the token (e.g., "Bearer").
	TokenType TokenType `json:"token_type,omitempty"`
	// ExpiresAt is the token expiration time as a Unix timestamp.
	ExpiresAt int64 `json:"exp,omitempty"`
	// IssuedAt is when the token was issued as a Unix timestamp.
	IssuedAt int64 `json:"iat,omitempty"`
	// NotBefore indicates the token is not valid before this Unix timestamp.
	NotBefore int64 `json:"nbf,omitempty"`
	// Subject is the subject identifier for the token.
	Subject string `json:"sub,omitempty"`
	// Audience contains the intended audiences for the token.
	Audience []string `json:"aud,omitempty"`
	// Issuer is the issuer identifier for the token.
	Issuer string `json:"iss,omitempty"`
	// JWTID is the unique identifier for JWT tokens.
	JWTID string `json:"jti,omitempty"`
	// Extra contains additional token metadata not covered by standard fields.
	Extra map[string]interface{} `json:"-"`
}

// RevocationRequest represents a request to the token revocation endpoint (RFC 7009).
// Used to revoke access or refresh tokens, making them invalid for future use.
type RevocationRequest struct {
	// Token is the token to be revoked (access token or refresh token).
	Token string `json:"token"                     form:"token"`
	// TokenTypeHint provides a hint about the type of token being revoked.
	TokenTypeHint string `json:"token_type_hint,omitempty" form:"token_type_hint"`
	// ClientID is the client identifier for authentication.
	ClientID string `json:"client_id"                 form:"client_id"`
	// ClientSecret is the client secret for authentication.
	ClientSecret string `json:"client_secret,omitempty"   form:"client_secret"`
}

// UserInfo represents user information as defined in the OpenID Connect specification.
// Returned by the userinfo endpoint to provide claims about the authenticated user.
type UserInfo struct {
	// Subject is the unique identifier for the user within the issuer.
	Subject string `json:"sub"`
	// Name is the user's full name in displayable form.
	Name string `json:"name,omitempty"`
	// GivenName is the user's first name.
	GivenName string `json:"given_name,omitempty"`
	// FamilyName is the user's last name.
	FamilyName string `json:"family_name,omitempty"`
	// MiddleName is the user's middle name.
	MiddleName string `json:"middle_name,omitempty"`
	// Nickname is the user's casual name.
	Nickname string `json:"nickname,omitempty"`
	// PreferredUsername is the user's preferred username.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Profile is the URL of the user's profile page.
	Profile string `json:"profile,omitempty"`
	// Picture is the URL of the user's profile picture.
	Picture string `json:"picture,omitempty"`
	// Website is the URL of the user's website or blog.
	Website string `json:"website,omitempty"`
	// Email is the user's email address.
	Email string `json:"email,omitempty"`
	// EmailVerified indicates whether the email address has been verified.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Gender is the user's gender.
	Gender string `json:"gender,omitempty"`
	// Birthdate is the user's birthday in ISO 8601 YYYY-MM-DD format.
	Birthdate string `json:"birthdate,omitempty"`
	// Zoneinfo is the user's time zone (e.g., "America/Los_Angeles").
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// Locale is the user's locale (e.g., "en-US").
	Locale string `json:"locale,omitempty"`
	// PhoneNumber is the user's phone number in E.164 format.
	PhoneNumber string `json:"phone_number,omitempty"`
	// PhoneNumberVerified indicates whether the phone number has been verified.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	// Address is the user's postal address.
	Address *Address `json:"address,omitempty"`
	// UpdatedAt is when the user information was last updated as a Unix timestamp.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

// Address represents a user's postal address as defined in the OpenID Connect specification.
// Contains structured address information that can be used for various purposes.
type Address struct {
	// Formatted is the full mailing address formatted for display.
	Formatted string `json:"formatted,omitempty"`
	// StreetAddress is the street address component.
	StreetAddress string `json:"street_address,omitempty"`
	// Locality is the city or locality component.
	Locality string `json:"locality,omitempty"`
	// Region is the state, province, prefecture, or region component.
	Region string `json:"region,omitempty"`
	// PostalCode is the zip code or postal code component.
	PostalCode string `json:"postal_code,omitempty"`
	// Country is the country name component.
	Country string `json:"country,omitempty"`
}

// NewClient creates a new OAuth2 client with the specified configuration.
// Generates unique ID and secret, sets creation timestamps, and marks as active.
// All parameters are required for proper client functionality.
func NewClient(name string, redirectURIs []string, scopes []string, grantTypes []string) *Client {
	now := time.Now()
	return &Client{
		ID:           uuid.New().String(),
		Secret:       uuid.New().String(),
		Name:         name,
		RedirectURIs: redirectURIs,
		Scopes:       scopes,
		GrantTypes:   grantTypes,
		CreatedAt:    now,
		UpdatedAt:    now,
		IsActive:     true,
	}
}

// AuthorizationCodeParams groups parameters for creating a new authorization code.
type AuthorizationCodeParams struct {
	ClientID            string
	UserID              string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Nonce               string
	ExpiresAt           time.Time
}

// NewAuthorizationCode creates a new authorization code for the OAuth2 authorization code flow.
// Accepts an AuthorizationCodeParams struct to reduce the number of parameters.
func NewAuthorizationCode(params AuthorizationCodeParams) *AuthorizationCode {
	return &AuthorizationCode{
		Code:                uuid.New().String(),
		ClientID:            params.ClientID,
		UserID:              params.UserID,
		RedirectURI:         params.RedirectURI,
		Scopes:              params.Scopes,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		State:               params.State,
		Nonce:               params.Nonce,
		ExpiresAt:           params.ExpiresAt,
		CreatedAt:           time.Now(),
		Used:                false,
		Claims:              make(map[string]interface{}),
	}
}

// NewSession creates a new session for maintaining state during the OAuth2 authorization flow.
// Sessions expire after 24 hours by default and include empty data map for storing flow-specific information.
// Used to track user authentication and consent across authorization requests.
func NewSession(userID, clientID string) *Session {
	now := time.Now()
	return &Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		ClientID:  clientID,
		Data:      make(map[string]interface{}),
		ExpiresAt: now.Add(DefaultSessionExpiry),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ValidateRedirectURI checks if the provided URI is in the client's list of allowed redirect URIs.
// Returns true if the URI matches exactly one of the registered redirect URIs.
// This validation is critical for preventing redirect attacks in OAuth2 flows.
func (c *Client) ValidateRedirectURI(uri string) bool {
	for _, allowedURI := range c.RedirectURIs {
		if allowedURI == uri {
			return true
		}
	}
	return false
}

// HasScope checks if the client is authorized to request the specified scope.
// Returns true if the scope is in the client's list of allowed scopes.
// Used during authorization to validate requested scopes against client configuration.
func (c *Client) HasScope(scope string) bool {
	for _, allowedScope := range c.Scopes {
		if allowedScope == scope {
			return true
		}
	}
	return false
}

// HasGrantType checks if the client supports the specified OAuth2 grant type.
// Returns true if the grant type is in the client's list of allowed grant types.
// Used to validate token requests against client capabilities.
func (c *Client) HasGrantType(grantType GrantType) bool {
	for _, allowedGrantType := range c.GrantTypes {
		if allowedGrantType == string(grantType) {
			return true
		}
	}
	return false
}

// IsExpired checks if the authorization code has passed its expiration time.
// Returns true if the current time is after the ExpiresAt timestamp.
// Expired codes should not be accepted for token exchange.
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// IsExpired checks if the access token has passed its expiration time.
// Returns true if the current time is after the ExpiresAt timestamp.
// Expired tokens should be rejected by resource servers.
func (at *AccessToken) IsExpired() bool {
	return time.Now().After(at.ExpiresAt)
}

// IsExpired checks if the refresh token has passed its expiration time.
// Returns true if the current time is after the ExpiresAt timestamp.
// Expired refresh tokens cannot be used to obtain new access tokens.
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsExpired checks if the session has passed its expiration time.
// Returns true if the current time is after the ExpiresAt timestamp.
// Expired sessions should trigger re-authentication.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
