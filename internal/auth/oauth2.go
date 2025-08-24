// Package auth provides the core OAuth2 authentication service implementation
// including authorization code flow with PKCE, client credentials flow,
// token validation, and client management.
package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/token"
)

const tokenFailureErrorMsg = "Failed to generate or store token"

// Service defines the OAuth2 authentication service interface providing
// methods for authorization code flow, token generation, validation, and client management.
type Service interface {
	// Authorization Code Flow
	Authorize(ctx context.Context, req *models.AuthorizeRequest, userID string) (*models.AuthorizeResponse, error)
	Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResponse, error)

	// Token Operations
	IntrospectToken(ctx context.Context, req *models.IntrospectionRequest) (*models.IntrospectionResponse, error)
	RevokeToken(ctx context.Context, req *models.RevocationRequest) error
	GetUserInfo(ctx context.Context, accessToken string) (*models.UserInfo, error)

	// Client Management
	RegisterClient(
		ctx context.Context,
		name string,
		redirectURIs []string,
		scopes []string,
		grantTypes []string,
	) (*models.Client, error)
	GetClient(ctx context.Context, clientID string) (*models.Client, error)
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*models.Client, error)

	// PKCE Support
	ValidatePKCE(codeVerifier, codeChallenge, method string) bool

	// Scope Operations
	ValidateScopes(requestedScopes []string, clientScopes []string) ([]string, error)
}

// OAuth2Service implements the OAuth2 authentication service with Redis storage
// and JWT token generation capabilities.
type OAuth2Service struct {
	config   *config.Config
	store    redis.Store
	tokenSvc token.Service
	pkceSvc  token.PKCEService
	logger   *logrus.Logger
}

// NewOAuth2Service creates a new OAuth2 service instance with the provided dependencies.
func NewOAuth2Service(
	cfg *config.Config,
	store redis.Store,
	tokenSvc token.Service,
	pkceSvc token.PKCEService,
	logger *logrus.Logger,
) Service {
	return &OAuth2Service{
		config:   cfg,
		store:    store,
		tokenSvc: tokenSvc,
		pkceSvc:  pkceSvc,
		logger:   logger,
	}
}

// Authorize handles the OAuth2 authorization request with PKCE support.
// It validates the client, redirect URI, scopes, and PKCE parameters,
// then generates an authorization code for token exchange.
func (s *OAuth2Service) Authorize(
	ctx context.Context,
	req *models.AuthorizeRequest,
	userID string,
) (*models.AuthorizeResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"client_id": req.ClientID,
		"user_id":   userID,
		"scope":     req.Scope,
	}).Info("Processing authorization request")

	// Validate request parameters
	if err := s.validateAuthorizeRequest(req); err != nil {
		return nil, err
	}

	// Get and validate client
	client, err := s.store.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, models.NewInvalidClient("Client not found")
	}

	if !client.IsActive {
		return nil, models.NewInvalidClient("Client is inactive")
	}

	// Validate redirect URI
	if !client.ValidateRedirectURI(req.RedirectURI) {
		return nil, models.NewInvalidRequest("Invalid redirect_uri")
	}

	// Validate response type
	if req.ResponseType != models.ResponseTypeCode {
		return nil, models.ErrUnsupportedResponseType.WithDescription("Only 'code' response type is supported")
	}

	// Validate and normalize scopes
	scopes, err := s.ValidateScopes(strings.Fields(req.Scope), client.Scopes)
	if err != nil {
		return nil, err
	}

	// Validate PKCE if required
	if s.config.OAuth2.PKCERequired {
		if req.CodeChallenge == "" {
			return nil, models.NewInvalidRequest("code_challenge is required")
		}
		if req.CodeChallengeMethod == "" {
			req.CodeChallengeMethod = "plain"
		}
		if err = s.pkceSvc.ValidateCodeChallengeMethod(req.CodeChallengeMethod); err != nil {
			return nil, models.NewInvalidRequest(fmt.Sprintf("Invalid code_challenge_method: %v", err))
		}
	}

	// Generate authorization code
	var code string
	var authCode *models.AuthorizationCode
	code, authCode, err = s.tokenSvc.GenerateAuthorizationCode(token.AuthorizationCodeInput{
		ClientID:            client.ID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scopes:              scopes,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		State:               req.State,
		Nonce:               req.Nonce,
	})
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate authorization code")
		return nil, models.NewServerError("Failed to generate authorization code")
	}

	// Store authorization code in Redis
	storeErr := s.store.StoreAuthorizationCode(ctx, authCode, s.config.OAuth2.AuthorizationCodeExpiry)
	if storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store authorization code")
		return nil, models.NewServerError("Failed to store authorization code")
	}

	s.logger.WithFields(logrus.Fields{
		"client_id": req.ClientID,
		"user_id":   userID,
		"code":      code[:8] + "...", // Log only first 8 chars for security
	}).Info("Authorization code generated successfully")

	return &models.AuthorizeResponse{
		Code:  code,
		State: req.State,
	}, nil
}

// Token handles token requests for all supported grant types including
// authorization_code, client_credentials, and refresh_token flows.
func (s *OAuth2Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"grant_type": req.GrantType,
		"client_id":  req.ClientID,
	}).Info("Processing token request")

	// Validate basic request parameters
	if err := s.validateTokenRequest(req); err != nil {
		return nil, err
	}

	// Validate client
	client, err := s.validateTokenClient(ctx, req)
	if err != nil {
		return nil, err
	}

	// Handle different grant types
	switch req.GrantType {
	case models.GrantTypeAuthorizationCode:
		return s.handleAuthorizationCodeGrant(ctx, req, client)
	case models.GrantTypeClientCredentials:
		return s.handleClientCredentialsGrant(ctx, req, client)
	case models.GrantTypeRefreshToken:
		return s.handleRefreshTokenGrant(ctx, req, client)
	default:
		msg := fmt.Sprintf("Grant type %s is not supported", req.GrantType)
		return nil, models.ErrUnsupportedGrantType.WithDescription(msg)
	}
}

// handleAuthorizationCodeGrant processes authorization code grant requests with PKCE validation.
func (s *OAuth2Service) handleAuthorizationCodeGrant(
	ctx context.Context,
	req *models.TokenRequest,
	client *models.Client,
) (*models.TokenResponse, error) {
	// Validate required parameters
	if req.Code == "" {
		return nil, models.NewInvalidRequest("code is required for authorization_code grant")
	}
	if req.RedirectURI == "" {
		return nil, models.NewInvalidRequest("redirect_uri is required for authorization_code grant")
	}

	// Fetch and validate the authorization code (including PKCE)
	authCode, err := s.fetchAndValidateAuthCode(ctx, req, client)
	if err != nil {
		return nil, err
	}

	// Mark authorization code as used (best-effort persistence/cleanup)
	s.markAuthorizationCodeUsed(ctx, req.Code, authCode)

	// Generate and store tokens
	accessToken, refreshToken, idToken, expiresIn, scope, err := s.generateAndStoreTokensFromAuthCode(
		ctx,
		client,
		authCode,
	)
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    models.TokenTypeBearer,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        scope,
		IDToken:      idToken,
	}, nil
}

// fetchAndValidateAuthCode retrieves the authorization code and performs validations including PKCE.
func (s *OAuth2Service) fetchAndValidateAuthCode(
	ctx context.Context,
	req *models.TokenRequest,
	client *models.Client,
) (*models.AuthorizationCode, error) {
	authCode, err := s.store.GetAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, models.NewInvalidGrant("Invalid or expired authorization code")
	}

	if authCode.Used {
		_ = s.store.DeleteAuthorizationCode(ctx, req.Code) // Intentionally ignore error on cleanup
		return nil, models.NewInvalidGrant("Authorization code has already been used")
	}

	if authCode.IsExpired() {
		_ = s.store.DeleteAuthorizationCode(ctx, req.Code) // Intentionally ignore error on cleanup
		return nil, models.NewInvalidGrant("Authorization code has expired")
	}

	if authCode.ClientID != client.ID {
		return nil, models.NewInvalidGrant("Authorization code was issued to different client")
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, models.NewInvalidGrant("redirect_uri does not match authorization request")
	}

	// Validate PKCE if code challenge was provided
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, models.NewInvalidRequest("code_verifier is required when code_challenge was provided")
		}
		if !s.ValidatePKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, models.NewInvalidGrant("Invalid code_verifier")
		}
	} else if s.config.OAuth2.PKCERequired {
		return nil, models.NewInvalidRequest("PKCE is required but code_challenge was not provided in authorization request")
	}

	return authCode, nil
}

// markAuthorizationCodeUsed marks the code as used and attempts to persist and cleanup (best-effort).
func (s *OAuth2Service) markAuthorizationCodeUsed(
	ctx context.Context,
	reqCode string,
	authCode *models.AuthorizationCode,
) {
	authCode.Used = true
	_ = s.store.StoreAuthorizationCode(ctx, authCode, time.Until(authCode.ExpiresAt)) // Best effort update
	_ = s.store.DeleteAuthorizationCode(ctx, reqCode)                                 // Best effort cleanup
}

// generateAndStoreTokensFromAuthCode encapsulates token generation and storage logic for the authorization code flow.
func (s *OAuth2Service) generateAndStoreTokensFromAuthCode(
	ctx context.Context,
	client *models.Client,
	authCode *models.AuthorizationCode,
) (string, string, string, int, string, error) {
	accessToken, accessTokenObj, err := s.tokenSvc.GenerateAccessToken(
		client.ID, authCode.UserID, authCode.Scopes, authCode.Claims,
	)
	if err != nil {
		s.logger.WithError(err).Error(tokenFailureErrorMsg)
		return "", "", "", 0, "", models.NewServerError(tokenFailureErrorMsg)
	}

	refreshToken, refreshTokenObj, err := s.tokenSvc.GenerateRefreshToken(
		accessToken, client.ID, authCode.UserID, authCode.Scopes,
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return "", "", "", 0, "", models.NewServerError("Failed to generate refresh token")
	}

	// Store tokens
	storeErr := s.store.StoreAccessToken(ctx, accessTokenObj, s.config.JWT.AccessTokenExpiry)
	if storeErr != nil {
		s.logger.WithError(storeErr).Error(tokenFailureErrorMsg)
		return "", "", "", 0, "", models.NewServerError(tokenFailureErrorMsg)
	}

	if refreshErr := s.store.StoreRefreshToken(ctx, refreshTokenObj, s.config.JWT.RefreshTokenExpiry); refreshErr != nil {
		s.logger.WithError(refreshErr).Error(tokenFailureErrorMsg)
		return "", "", "", 0, "", models.NewServerError(tokenFailureErrorMsg)
	}

	// Generate ID token if openid scope is requested
	var idToken string
	if s.containsScope(authCode.Scopes, "openid") {
		idToken, err = s.tokenSvc.GenerateIDToken(authCode.UserID, client.ID, authCode.Nonce, authCode.Claims)
		if err != nil {
			s.logger.WithError(err).Error("Failed to generate ID token")
			// Don't fail the request, just omit the ID token
			idToken = ""
		}
	}

	s.logger.WithFields(logrus.Fields{
		"client_id": client.ID,
		"user_id":   authCode.UserID,
		"scopes":    strings.Join(authCode.Scopes, " "),
	}).Info("Access token issued successfully")

	return accessToken, refreshToken, idToken, int(
			s.config.JWT.AccessTokenExpiry.Seconds(),
		), strings.Join(
			authCode.Scopes,
			" ",
		), nil
}

// handleClientCredentialsGrant processes client credentials grant requests for service-to-service authentication.
func (s *OAuth2Service) handleClientCredentialsGrant(
	ctx context.Context,
	req *models.TokenRequest,
	client *models.Client,
) (*models.TokenResponse, error) {
	// Validate that client supports client credentials grant
	if !client.HasGrantType(models.GrantTypeClientCredentials) {
		return nil, models.ErrUnauthorizedClient.WithDescription(
			"Client is not authorized for client_credentials grant",
		)
	}

	// Parse and validate scopes
	var scopes []string
	if req.Scope != "" {
		scopes = strings.Fields(req.Scope)
	} else {
		scopes = s.config.OAuth2.DefaultScopes
	}

	validatedScopes, err := s.ValidateScopes(scopes, client.Scopes)
	if err != nil {
		return nil, err
	}

	// Generate access token (no refresh token for client credentials)
	accessToken, accessTokenObj, err := s.tokenSvc.GenerateAccessToken(
		client.ID, "", validatedScopes, nil,
	)
	if err != nil {
		s.logger.WithError(err).Error(tokenFailureErrorMsg)
		return nil, models.NewServerError(tokenFailureErrorMsg)
	}

	// Override expiry for client credentials
	accessTokenObj.ExpiresAt = time.Now().Add(s.config.OAuth2.ClientCredentialsExpiry)

	// Store access token
	if storeErr := s.store.StoreAccessToken(ctx, accessTokenObj, s.config.OAuth2.ClientCredentialsExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error(tokenFailureErrorMsg)
		return nil, models.NewServerError(tokenFailureErrorMsg)
	}

	s.logger.WithFields(logrus.Fields{
		"client_id": client.ID,
		"scopes":    strings.Join(validatedScopes, " "),
	}).Info("Client credentials access token issued successfully")

	return &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   models.TokenTypeBearer,
		ExpiresIn:   int(s.config.OAuth2.ClientCredentialsExpiry.Seconds()),
		Scope:       strings.Join(validatedScopes, " "),
	}, nil
}

// handleRefreshTokenGrant processes refresh token grant requests to issue new access tokens.
func (s *OAuth2Service) handleRefreshTokenGrant(
	ctx context.Context,
	req *models.TokenRequest,
	client *models.Client,
) (*models.TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, models.NewInvalidRequest("refresh_token is required")
	}

	// Retrieve refresh token
	refreshTokenObj, err := s.store.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, models.NewInvalidGrant("Invalid refresh token")
	}

	// Validate refresh token
	if refreshTokenObj.Revoked {
		return nil, models.NewInvalidGrant("Refresh token has been revoked")
	}

	if refreshTokenObj.IsExpired() {
		_ = s.store.DeleteRefreshToken(ctx, req.RefreshToken) // Best effort cleanup
		return nil, models.NewInvalidGrant("Refresh token has expired")
	}

	if refreshTokenObj.ClientID != client.ID {
		return nil, models.NewInvalidGrant("Refresh token was issued to different client")
	}

	// Parse requested scopes (must be subset of original scopes)
	var requestedScopes []string
	if req.Scope != "" {
		requestedScopes = strings.Fields(req.Scope)
		if !s.isScopeSubset(requestedScopes, refreshTokenObj.Scopes) {
			return nil, models.NewInvalidScope("Requested scopes exceed original grant")
		}
	} else {
		requestedScopes = refreshTokenObj.Scopes
	}

	// Generate new access token
	accessToken, accessTokenObj, err := s.tokenSvc.GenerateAccessToken(
		client.ID, refreshTokenObj.UserID, requestedScopes, nil,
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate access token")
		return nil, models.NewServerError("Failed to generate access token")
	}

	// Store new access token
	if storeErr := s.store.StoreAccessToken(ctx, accessTokenObj, s.config.JWT.AccessTokenExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store access token")
		return nil, models.NewServerError("Failed to store access token")
	}

	// Update refresh token usage
	now := time.Now()
	refreshTokenObj.LastUsedAt = &now
	refreshTokenObj.RotationCount++
	refreshTokenObj.AccessToken = accessToken

	if storeErr := s.store.StoreRefreshToken(ctx, refreshTokenObj, time.Until(refreshTokenObj.ExpiresAt)); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to update refresh token")
	}

	s.logger.WithFields(logrus.Fields{
		"client_id": client.ID,
		"user_id":   refreshTokenObj.UserID,
		"scopes":    strings.Join(requestedScopes, " "),
	}).Info("Access token refreshed successfully")

	return &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    models.TokenTypeBearer,
		ExpiresIn:    int(s.config.JWT.AccessTokenExpiry.Seconds()),
		RefreshToken: req.RefreshToken, // Return same refresh token
		Scope:        strings.Join(requestedScopes, " "),
	}, nil
}

// ValidatePKCE validates PKCE code verifier against code challenge using the specified method.
func (s *OAuth2Service) ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
	return s.pkceSvc.ValidateCodeChallenge(codeVerifier, codeChallenge, method)
}

// ValidateScopes validates requested scopes against allowed client scopes and returns the intersection.
func (s *OAuth2Service) ValidateScopes(requestedScopes []string, clientScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		return s.config.OAuth2.DefaultScopes, nil
	}

	var validScopes []string
	for _, scope := range requestedScopes {
		// Check if scope is supported by the server
		if !s.containsScope(s.config.OAuth2.SupportedScopes, scope) {
			return nil, models.NewInvalidScope(fmt.Sprintf("Unsupported scope: %s", scope))
		}

		// Check if client is allowed to request this scope
		if !s.containsScope(clientScopes, scope) {
			return nil, models.NewInvalidScope(fmt.Sprintf("Client not authorized for scope: %s", scope))
		}

		validScopes = append(validScopes, scope)
	}

	return validScopes, nil
}

// validateAuthorizeRequest validates the authorization request parameters.
func (s *OAuth2Service) validateAuthorizeRequest(req *models.AuthorizeRequest) error {
	if req.ClientID == "" {
		return models.NewInvalidRequest("client_id is required")
	}

	if req.RedirectURI == "" {
		return models.NewInvalidRequest("redirect_uri is required")
	}

	// Validate redirect URI format
	if _, err := url.ParseRequestURI(req.RedirectURI); err != nil {
		return models.NewInvalidRequest("Invalid redirect_uri format")
	}

	if req.ResponseType == "" {
		return models.NewInvalidRequest("response_type is required")
	}

	return nil
}

// validateTokenRequest validates the token request parameters.
func (s *OAuth2Service) validateTokenRequest(req *models.TokenRequest) error {
	if req.GrantType == "" {
		return models.NewInvalidRequest("grant_type is required")
	}

	if req.ClientID == "" {
		return models.NewInvalidRequest("client_id is required")
	}

	return nil
}

// validateTokenClient validates the client for token requests including secret verification.
func (s *OAuth2Service) validateTokenClient(ctx context.Context, req *models.TokenRequest) (*models.Client, error) {
	client, err := s.store.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, models.NewInvalidClient("Client not found")
	}

	if !client.IsActive {
		return nil, models.NewInvalidClient("Client is inactive")
	}

	// Verify client secret for confidential clients
	if req.ClientSecret != "" {
		if client.Secret != req.ClientSecret { // pragma: allowlist secret
			return nil, models.NewInvalidClient("Invalid client credentials")
		}
	}

	// Check if client supports the requested grant type
	if !client.HasGrantType(req.GrantType) {
		return nil, models.ErrUnauthorizedClient.WithDescription(
			fmt.Sprintf("Client not authorized for %s grant", req.GrantType),
		)
	}

	return client, nil
}

// containsScope checks if a scope exists in a slice of scopes.
func (s *OAuth2Service) containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// isScopeSubset checks if all requestedScopes exist in allowedScopes.
func (s *OAuth2Service) isScopeSubset(requestedScopes, allowedScopes []string) bool {
	for _, requested := range requestedScopes {
		if !s.containsScope(allowedScopes, requested) {
			return false
		}
	}
	return true
}
