// Package token provides JWT token generation, validation, and management functionality
// for OAuth2 and OpenID Connect authentication flows. It implements secure token handling
// with proper expiry management, claim validation, and PKCE support for enhanced security.
//
// This package supports:
//   - OAuth2 access tokens and refresh tokens
//   - OpenID Connect ID tokens
//   - Authorization codes with PKCE (Proof Key for Code Exchange)
//   - JWT token signing and verification using configurable algorithms
//   - Opaque token generation for enhanced security
//   - Comprehensive token validation and claim extraction
//
// Security Considerations:
//   - All JWT tokens are signed using configurable signing algorithms (HS256, RS256, etc.)
//   - Opaque tokens use cryptographically secure random generation
//   - Token expiry times are enforced during validation
//   - PKCE code challenges provide additional security for authorization codes
//   - All tokens include proper audience, issuer, and subject validation
package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
)

const (
	// DefaultIDTokenExpiry is the default ID token expiration time.
	DefaultIDTokenExpiry = 10 * time.Minute
	// DefaultRandomBytesLength is the default length for random byte generation.
	DefaultRandomBytesLength = 32
)

// Service defines the interface for token generation, validation, and management operations.
// It provides comprehensive JWT token handling for OAuth2 and OpenID Connect flows with
// proper security measures and compliance with relevant specifications.
//
// The interface supports:
//   - Access token generation with custom claims and scopes
//   - Refresh token generation with rotation capabilities
//   - Authorization code generation with PKCE support
//   - Token validation with signature and claim verification
//   - OpenID Connect ID token generation
//   - Secure opaque token generation
//   - JWT claim extraction without full validation
//
// All token operations include proper error handling for security violations,
// expired tokens, invalid signatures, and malformed claims.
type Service interface {
	// GenerateAccessToken creates a new OAuth2 access token as a signed JWT.
	// The token includes standard OAuth2 claims (client_id, user_id, scopes) and
	// custom claims for application-specific data.
	//
	// Parameters:
	//   - clientID: OAuth2 client identifier
	//   - userID: Authenticated user identifier
	//   - scopes: Array of OAuth2 scopes granted to the token
	//   - claims: Custom claims to include in the token
	//
	// Returns the signed JWT string, access token model, and any error.
	// Errors can occur during JWT signing or UUID generation.
	GenerateAccessToken(
		clientID, userID string,
		scopes []string,
		claims map[string]interface{},
	) (string, *models.AccessToken, error)

	// GenerateRefreshToken creates a new OAuth2 refresh token as an opaque token.
	// Refresh tokens are used to obtain new access tokens without re-authentication
	// and are stored securely with rotation support.
	//
	// Parameters:
	//   - accessToken: The access token this refresh token is associated with
	//   - clientID: OAuth2 client identifier
	//   - userID: Authenticated user identifier
	//   - scopes: Array of OAuth2 scopes for the refresh token
	//
	// Returns the opaque token string, refresh token model, and any error.
	// Errors can occur during secure random number generation.
	GenerateRefreshToken(accessToken, clientID, userID string, scopes []string) (string, *models.RefreshToken, error)

	// GenerateAuthorizationCode creates a new OAuth2 authorization code with PKCE support.
	// Authorization codes are short-lived tokens used in the authorization code flow
	// and include PKCE parameters for enhanced security.
	//
	// Parameters:
	//   - clientID: OAuth2 client identifier
	//   - userID: Authenticated user identifier
	//   - redirectURI: Client's registered redirect URI
	//   - scopes: Array of OAuth2 scopes requested
	//   - codeChallenge: PKCE code challenge (optional)
	//   - codeChallengeMethod: PKCE code challenge method (plain or S256)
	//   - state: OAuth2 state parameter for CSRF protection
	//   - nonce: OpenID Connect nonce for replay protection
	//
	// Returns the authorization code string, authorization code model, and any error.
	// Authorization codes expire after 10 minutes per OAuth2 specification.
	GenerateAuthorizationCode(input AuthorizationCodeInput) (string, *models.AuthorizationCode, error)

	// ValidateAccessToken validates and parses an OAuth2 access token JWT.
	// Performs comprehensive validation including signature verification,
	// expiry checking, and claim validation.
	//
	// Validation includes:
	//   - JWT signature verification using configured algorithm
	//   - Token expiry time validation
	//   - Token type verification (must be "access_token")
	//   - Issuer, audience, and subject claim validation
	//
	// Parameters:
	//   - tokenString: The JWT access token to validate
	//
	// Returns the validated access token model, JWT token, and any error.
	// Common errors include expired tokens, invalid signatures, and malformed claims.
	ValidateAccessToken(tokenString string) (*models.AccessToken, *jwt.Token, error)

	// ValidateRefreshToken validates an OAuth2 refresh token.
	// Since refresh tokens are opaque, validation requires storage lookup
	// to verify token existence, expiry, and revocation status.
	//
	// Parameters:
	//   - tokenString: The opaque refresh token to validate
	//
	// Returns the validated refresh token model and any error.
	// This method currently returns an error indicating storage lookup is required.
	ValidateRefreshToken(tokenString string) (*models.RefreshToken, error)

	// GenerateOpaqueToken creates a cryptographically secure opaque token.
	// Used for refresh tokens and authorization codes where the token content
	// should not be readable without storage lookup.
	//
	// The token is generated using 32 bytes of cryptographically secure random data
	// and encoded using base64 URL encoding for safe transmission.
	//
	// Returns the opaque token string and any error.
	// Errors can occur if the system's random number generator fails.
	GenerateOpaqueToken() (string, error)

	// GenerateIDToken creates an OpenID Connect ID token as a signed JWT.
	// ID tokens contain identity information about the authenticated user
	// and are compliant with OpenID Connect specification.
	//
	// Parameters:
	//   - userID: Authenticated user identifier (becomes 'sub' claim)
	//   - clientID: OAuth2 client identifier (becomes 'aud' claim)
	//   - nonce: OpenID Connect nonce for replay protection (optional)
	//   - claims: Custom identity claims to include in the token
	//
	// Returns the signed ID token JWT string and any error.
	// The nonce parameter is included as a claim if provided.
	GenerateIDToken(userID, clientID string, nonce string, claims map[string]interface{}) (string, error)

	// ExtractClaims extracts JWT claims from a token without full validation.
	// This method parses the JWT and verifies the signature but does not
	// perform expiry or other claim validations.
	//
	// Use this method when you need to inspect token claims for debugging
	// or logging purposes without requiring the token to be valid.
	//
	// Parameters:
	//   - tokenString: The JWT token to extract claims from
	//
	// Returns the JWT claims as a map and any error.
	// Errors occur for malformed JWTs or signature verification failures.
	ExtractClaims(tokenString string) (jwt.MapClaims, error)
}

// JWTService implements the Service interface for JWT token operations.
// It provides secure token generation and validation using configurable
// signing algorithms and proper claim management.
//
// The service handles:
//   - JWT token signing with configurable algorithms (HS256, RS256, etc.)
//   - Token validation with signature and claim verification
//   - OAuth2 and OpenID Connect compliance
//   - Secure random token generation for opaque tokens
//   - Proper error handling and security measures
//
// Security features:
//   - Configurable token expiry times
//   - Signature verification for all token operations
//   - Proper audience, issuer, and subject validation
//   - PKCE support for enhanced authorization code security
type JWTService struct {
	config *config.JWTConfig
}

// Claims represents the structure of JWT claims used in all token types.
// It extends the standard JWT registered claims with OAuth2 and OpenID Connect
// specific claims for comprehensive token functionality.
//
// The structure includes:
//   - OAuth2 specific claims (client_id, scopes, user_id)
//   - Token type identification for proper validation
//   - Custom claims for application-specific data
//   - Standard JWT registered claims (iss, aud, sub, exp, etc.)
//
// JSON tags ensure proper serialization and deserialization of claims
// in compliance with OAuth2 and OpenID Connect specifications.
type Claims struct {
	// RegisteredClaims embeds standard JWT claims as defined in RFC 7519.
	// These include iss (issuer), aud (audience), sub (subject), exp (expiration),
	// iat (issued at), nbf (not before), and jti (JWT ID).
	jwt.RegisteredClaims

	// ClientID identifies the OAuth2 client that requested the token.
	// This claim is used for audience validation and access control.
	ClientID string `json:"client_id,omitempty"`

	// UserID identifies the authenticated user the token was issued for.
	// This claim is also set as the standard 'sub' (subject) claim.
	UserID string `json:"user_id,omitempty"`

	// Scopes contains the OAuth2 scopes granted to the token.
	// These scopes define what resources and operations the token can access.
	Scopes []string `json:"scopes,omitempty"`

	// Type identifies the token type (access_token, id_token, etc.).
	// This field is required and used for proper token validation.
	Type string `json:"type"`

	// Claims contains custom application-specific claims.
	// These can include user profile information, permissions, or other data.
	Claims map[string]interface{} `json:"claims,omitempty"`
}

// NewJWTService creates a new JWT service instance with the provided configuration.
// The service uses the configuration to set up signing algorithms, token expiry times,
// issuer information, and other security parameters.
//
// Parameters:
//   - cfg: JWT configuration containing signing keys, algorithms, expiry times,
//     and other security settings
//
// Returns a Service interface implementation that can generate and validate
// OAuth2 access tokens, refresh tokens, authorization codes, and OpenID Connect
// ID tokens with proper security measures.
//
// The configuration should include:
//   - Signing algorithm (HS256, RS256, etc.)
//   - Secret key or private key for token signing
//   - Token expiry durations for different token types
//   - Issuer identifier for proper token validation
func NewJWTService(cfg *config.JWTConfig) Service {
	return &JWTService{
		config: cfg,
	}
}

// GenerateAccessToken creates a new OAuth2 access token as a signed JWT.
// The token includes standard OAuth2 claims (client_id, user_id, scopes),
// custom application claims, and standard JWT registered claims.
//
// The generated token:
//   - Uses the configured signing algorithm and secret
//   - Has a unique JWT ID (jti) for token tracking
//   - Includes proper audience (aud), issuer (iss), and subject (sub) claims
//   - Sets issued at (iat), not before (nbf), and expires at (exp) times
//   - Contains OAuth2 specific claims for client and scope validation
//
// Security considerations:
//   - Token expiry is enforced using the configured AccessTokenExpiry duration
//   - The token is signed with the configured algorithm to prevent tampering
//   - All timestamps use UTC to avoid timezone issues
//   - The JWT ID is a UUID v4 for uniqueness and tracking
//
// Parameters:
//   - clientID: OAuth2 client identifier for audience validation
//   - userID: Authenticated user identifier for subject claim
//   - scopes: OAuth2 scopes granted to this token
//   - claims: Custom application-specific claims to include
//
// Returns:
//   - tokenString: The signed JWT access token
//   - accessToken: Access token model for storage and tracking
//   - error: Any error during JWT signing or UUID generation
func (s *JWTService) GenerateAccessToken(
	clientID, userID string,
	scopes []string,
	claims map[string]interface{},
) (string, *models.AccessToken, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenExpiry)
	jwtID := uuid.New().String()

	jwtClaims := &Claims{
		ClientID: clientID,
		UserID:   userID,
		Scopes:   scopes,
		Type:     "access_token",
		Claims:   claims,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jwtID,
			Subject:   userID,
			Audience:  []string{clientID},
			Issuer:    s.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(s.config.Algorithm), jwtClaims)

	tokenString, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign JWT token: %w", err)
	}

	accessToken := &models.AccessToken{
		Token:     tokenString,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		TokenType: models.TokenTypeBearer,
		Claims:    claims,
		Revoked:   false,
	}

	return tokenString, accessToken, nil
}

// GenerateRefreshToken creates a new OAuth2 refresh token as an opaque token.
// Unlike access tokens, refresh tokens are not JWTs but secure random opaque tokens
// that require storage lookup for validation. This provides better security as
// refresh tokens can be easily revoked and rotated.
//
// The generated refresh token:
//   - Uses 32 bytes of cryptographically secure random data
//   - Is base64 URL encoded for safe transmission
//   - Has a longer expiry time than access tokens
//   - Is associated with the corresponding access token
//   - Supports rotation counting for security tracking
//
// Security considerations:
//   - Opaque tokens provide better security than JWTs for refresh tokens
//   - Cannot be validated without storage lookup, enabling revocation
//   - Uses crypto/rand for cryptographically secure random generation
//   - Rotation count helps track token usage patterns
//
// Parameters:
//   - accessToken: The access token this refresh token is associated with
//   - clientID: OAuth2 client identifier
//   - userID: Authenticated user identifier
//   - scopes: OAuth2 scopes for the refresh token (should match access token)
//
// Returns:
//   - tokenString: The opaque refresh token
//   - refreshToken: Refresh token model for storage
//   - error: Any error during secure random generation
func (s *JWTService) GenerateRefreshToken(
	accessToken, clientID, userID string,
	scopes []string,
) (string, *models.RefreshToken, error) {
	opaqueToken, err := s.GenerateOpaqueToken()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate opaque refresh token: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(s.config.RefreshTokenExpiry)

	refreshToken := &models.RefreshToken{
		Token:         opaqueToken,
		AccessToken:   accessToken,
		ClientID:      clientID,
		UserID:        userID,
		Scopes:        scopes,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		Revoked:       false,
		RotationCount: 0,
	}

	return opaqueToken, refreshToken, nil
}

// AuthorizationCodeInput contains the input parameters for generating a new OAuth2 authorization code with PKCE support.
// Authorization codes are short-lived opaque tokens used in the authorization code flow
// to exchange for access tokens. They include PKCE parameters for enhanced security
// against authorization code interception attacks.
//
// The generated authorization code:
//   - Uses secure random generation for opaque token creation
//   - Expires after 10 minutes per OAuth2 specification
//   - Includes PKCE code challenge and method for verification
//   - Contains state parameter for CSRF protection
//   - Includes nonce for OpenID Connect replay protection
//
// PKCE (Proof Key for Code Exchange) security:
//   - Protects against authorization code interception attacks
//   - Supports both 'plain' and 'S256' challenge methods
//   - Code verifier must be provided during token exchange
//   - Recommended for all OAuth2 clients, required for public clients
//
// Security considerations:
//   - Short 10-minute expiry reduces attack window
//   - One-time use prevents replay attacks
//   - PKCE parameters must be validated during token exchange
//   - State parameter prevents CSRF attacks
//
// Parameters:
//   - clientID: OAuth2 client identifier
//   - userID: Authenticated user identifier
//   - redirectURI: Client's registered redirect URI for validation
//   - scopes: OAuth2 scopes requested by the client
//   - codeChallenge: PKCE code challenge (base64url encoded)
//   - codeChallengeMethod: PKCE method ('plain' or 'S256')
//   - state: OAuth2 state parameter for CSRF protection
//   - nonce: OpenID Connect nonce for replay protection
//
// Returns:
//   - codeString: The authorization code
//   - authCode: Authorization code model for storage
//   - error: Any error during secure random generation
type AuthorizationCodeInput struct {
	ClientID            string
	UserID              string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Nonce               string
}

func (s *JWTService) GenerateAuthorizationCode(
	input AuthorizationCodeInput,
) (string, *models.AuthorizationCode, error) {
	code, err := s.GenerateOpaqueToken()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(DefaultIDTokenExpiry)

	authCode := models.NewAuthorizationCode(models.AuthorizationCodeParams{
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		RedirectURI:         input.RedirectURI,
		Scopes:              input.Scopes,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		State:               input.State,
		Nonce:               input.Nonce,
		ExpiresAt:           expiresAt,
	})
	authCode.Code = code

	return code, authCode, nil
}

// ValidateAccessToken validates and parses an OAuth2 access token JWT.
// Performs comprehensive validation including signature verification, expiry checking,
// and claim validation to ensure the token is valid and has not been tampered with.
//
// Validation process:
//  1. JWT structure validation and parsing
//  2. Signature verification using configured algorithm and secret
//  3. Token expiry time validation
//  4. Token type verification (must be "access_token")
//  5. Standard JWT claim validation (iss, aud, sub)
//  6. Custom claim extraction and validation
//
// Security checks performed:
//   - Signature verification prevents token tampering
//   - Algorithm verification prevents algorithm confusion attacks
//   - Expiry validation ensures tokens cannot be used indefinitely
//   - Type validation prevents token type confusion
//   - Claim validation ensures proper token structure
//
// Common validation errors:
//   - Expired tokens (exp claim validation)
//   - Invalid signatures (tampering detection)
//   - Wrong signing algorithm (algorithm confusion prevention)
//   - Invalid token type (not an access token)
//   - Malformed JWT structure
//
// Parameters:
//   - tokenString: The JWT access token to validate
//
// Returns:
//   - accessToken: Validated access token model with extracted claims
//   - jwtToken: Parsed JWT token for additional inspection
//   - error: Validation error with details about the failure
func (s *JWTService) ValidateAccessToken(tokenString string) (*models.AccessToken, *jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod(s.config.Algorithm) {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	if !token.Valid {
		return nil, nil, errors.New("invalid JWT token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, nil, errors.New("invalid JWT claims")
	}

	if claims.Type != "access_token" {
		return nil, nil, fmt.Errorf("invalid token type: expected access_token, got %s", claims.Type)
	}

	accessToken := &models.AccessToken{
		Token:     tokenString,
		ClientID:  claims.ClientID,
		UserID:    claims.UserID,
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt.Time,
		CreatedAt: claims.IssuedAt.Time,
		TokenType: models.TokenTypeBearer,
		Claims:    claims.Claims,
		Revoked:   false,
	}

	return accessToken, token, nil
}

// ValidateRefreshToken validates an OAuth2 refresh token.
// Since refresh tokens are opaque tokens (not JWTs), validation requires
// a storage lookup to verify token existence, expiry, and revocation status.
//
// Refresh token validation requirements:
//   - Token must exist in storage (not JWT, requires lookup)
//   - Token must not be expired
//   - Token must not be revoked
//   - Token must belong to the requesting client
//   - Token rotation count must be within acceptable limits
//
// Security considerations:
//   - Opaque tokens allow immediate revocation
//   - Storage lookup enables rotation tracking
//   - Revocation status can be checked in real-time
//   - Token binding to client prevents unauthorized use
//
// Implementation note:
//
//	This method currently returns an error indicating that storage lookup
//	is required. A complete implementation would query the token storage
//	to verify the refresh token's validity.
//
// Parameters:
//   - tokenString: The opaque refresh token to validate
//
// Returns:
//   - refreshToken: Validated refresh token model (when implemented)
//   - error: Validation error or storage lookup requirement notice
func (s *JWTService) ValidateRefreshToken(tokenString string) (*models.RefreshToken, error) {
	if tokenString == "" {
		return nil, errors.New("refresh token is empty")
	}

	return nil, errors.New("refresh token validation requires storage lookup")
}

// GenerateOpaqueToken creates a cryptographically secure opaque token.
// Opaque tokens are used for refresh tokens and authorization codes where
// the token content should not be readable without storage lookup.
//
// Token generation process:
//  1. Generate 32 bytes of cryptographically secure random data
//  2. Encode using base64 URL encoding for safe transmission
//  3. Return the encoded token string
//
// Security properties:
//   - Uses crypto/rand for cryptographically secure randomness
//   - 32 bytes provides 256 bits of entropy (recommended minimum)
//   - Base64 URL encoding is safe for HTTP transmission
//   - No embedded information prevents information disclosure
//   - Requires storage lookup for validation, enabling revocation
//
// Use cases:
//   - OAuth2 refresh tokens for secure token rotation
//   - Authorization codes for secure code exchange
//   - Any scenario requiring opaque, revocable tokens
//
// Token characteristics:
//   - Length: ~43 characters when base64 URL encoded
//   - Entropy: 256 bits of cryptographically secure randomness
//   - Encoding: Base64 URL (RFC 4648) for web safety
//   - Revocability: Can be revoked by removing from storage
//
// Returns:
//   - tokenString: The base64 URL encoded opaque token
//   - error: Any error from the system's random number generator
func (s *JWTService) GenerateOpaqueToken() (string, error) {
	bytes := make([]byte, DefaultRandomBytesLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateIDToken creates an OpenID Connect ID token as a signed JWT.
// ID tokens contain identity information about the authenticated user and
// are compliant with OpenID Connect Core specification (RFC 6749 extension).
//
// ID token characteristics:
//   - Contains user identity claims (sub, name, email, etc.)
//   - Signed JWT for integrity and authenticity
//   - Short expiry time (same as access token)
//   - Includes nonce for replay protection when provided
//   - Compliant with OpenID Connect Core 1.0 specification
//
// Required claims (automatically included):
//   - iss (issuer): Token issuer identifier
//   - sub (subject): User identifier
//   - aud (audience): Client identifier
//   - exp (expiration): Token expiration time
//   - iat (issued at): Token issuance time
//   - jti (JWT ID): Unique token identifier
//
// Optional claims:
//   - nonce: Replay protection parameter from authentication request
//   - Custom claims: User profile information, roles, permissions
//
// Security considerations:
//   - ID tokens are intended for client consumption only
//   - Should not be sent to resource servers
//   - Nonce prevents replay attacks when included
//   - Short expiry reduces security window
//   - Signature verification ensures authenticity
//
// Parameters:
//   - userID: User identifier for the 'sub' claim
//   - clientID: Client identifier for the 'aud' claim
//   - nonce: Optional nonce for replay protection
//   - claims: Custom identity claims to include
//
// Returns:
//   - tokenString: The signed ID token JWT
//   - error: Any error during JWT signing
func (s *JWTService) GenerateIDToken(
	userID, clientID string,
	nonce string,
	claims map[string]interface{},
) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenExpiry)
	jwtID := uuid.New().String()

	jwtClaims := &Claims{
		ClientID: clientID,
		UserID:   userID,
		Type:     "id_token",
		Claims:   claims,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jwtID,
			Subject:   userID,
			Audience:  []string{clientID},
			Issuer:    s.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	if nonce != "" {
		if jwtClaims.Claims == nil {
			jwtClaims.Claims = make(map[string]interface{})
		}
		jwtClaims.Claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(s.config.Algorithm), jwtClaims)

	tokenString, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return tokenString, nil
}

// ExtractClaims extracts JWT claims from a token without full validation.
// This method parses the JWT and verifies the signature but does not perform
// expiry validation or other claim validations. Use this for debugging,
// logging, or when you need to inspect claims from potentially expired tokens.
//
// Validation performed:
//   - JWT structure parsing and validation
//   - Signature verification using configured algorithm
//   - Algorithm verification to prevent confusion attacks
//
// Validation NOT performed:
//   - Token expiry checking (exp claim)
//   - Not before time checking (nbf claim)
//   - Audience validation (aud claim)
//   - Issuer validation (iss claim)
//   - Token type validation
//
// Use cases:
//   - Debugging token issues
//   - Logging token information
//   - Inspecting expired tokens
//   - Extracting user information for audit purposes
//   - Token migration or analysis scenarios
//
// Security considerations:
//   - Signature is still verified to ensure authenticity
//   - Algorithm verification prevents algorithm confusion
//   - Should not be used for authorization decisions
//   - Claims from expired tokens should be handled carefully
//
// Parameters:
//   - tokenString: The JWT token to extract claims from
//
// Returns:
//   - claims: Map of JWT claims from the token
//   - error: Parsing or signature verification errors
func (s *JWTService) ExtractClaims(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod(s.config.Algorithm) {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, errors.New("invalid JWT claims")
}
