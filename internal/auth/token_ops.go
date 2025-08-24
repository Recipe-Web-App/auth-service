package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/token"
)

// IntrospectToken validates and returns information about an access token.
// This endpoint is used by resource servers to validate tokens and get token metadata.
func (s *OAuth2Service) IntrospectToken(
	ctx context.Context,
	req *models.IntrospectionRequest,
) (*models.IntrospectionResponse, error) {
	s.logger.WithFields(map[string]interface{}{
		"client_id":       req.ClientID,
		"token_type_hint": req.TokenTypeHint,
	}).Debug("Processing token introspection request")

	// Validate client
	if _, err := s.ValidateClient(ctx, req.ClientID, req.ClientSecret); err != nil {
		return nil, err
	}

	if req.Token == "" {
		return nil, models.NewInvalidRequest("token is required")
	}

	// First check if token is blacklisted
	if blacklisted, err := s.store.IsTokenBlacklisted(ctx, req.Token); err == nil && blacklisted {
		return &models.IntrospectionResponse{Active: false}, nil
	} else if err != nil {
		s.logger.WithError(err).Error("Failed to check token blacklist")
	}

	// Try JWT validation
	if resp, err := s.introspectJWTToken(req.Token); err == nil {
		return resp, nil
	}

	// Try opaque token validation
	if resp, err := s.introspectOpaqueToken(ctx, req.Token); err == nil {
		return resp, nil
	}

	// Token not found or invalid
	return &models.IntrospectionResponse{Active: false}, nil
}

// introspectJWTToken validates JWT access token and returns introspection response.
func (s *OAuth2Service) introspectJWTToken(tokenStr string) (*models.IntrospectionResponse, error) {
	accessToken, jwtToken, err := s.tokenSvc.ValidateAccessToken(tokenStr)
	if err != nil || jwtToken == nil {
		return nil, err
	}
	if accessToken.IsExpired() || accessToken.Revoked {
		return &models.IntrospectionResponse{Active: false}, nil
	}
	claims, ok := jwtToken.Claims.(*token.Claims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	response := &models.IntrospectionResponse{
		Active:    true,
		ClientID:  accessToken.ClientID,
		Username:  accessToken.UserID,
		Scope:     strings.Join(accessToken.Scopes, " "),
		TokenType: models.TokenTypeBearer,
		ExpiresAt: accessToken.ExpiresAt.Unix(),
		IssuedAt:  accessToken.CreatedAt.Unix(),
		Subject:   accessToken.UserID,
		Issuer:    claims.Issuer,
		JWTID:     claims.ID,
	}
	if len(accessToken.Scopes) > 0 {
		response.Audience = []string{accessToken.ClientID}
	}
	return response, nil
}

// introspectOpaqueToken validates opaque access token and returns introspection response.
func (s *OAuth2Service) introspectOpaqueToken(
	ctx context.Context,
	tokenStr string,
) (*models.IntrospectionResponse, error) {
	storedToken, err := s.store.GetAccessToken(ctx, tokenStr)
	if err != nil {
		return nil, err
	}
	if storedToken.IsExpired() || storedToken.Revoked {
		return &models.IntrospectionResponse{Active: false}, nil
	}
	response := &models.IntrospectionResponse{
		Active:    true,
		ClientID:  storedToken.ClientID,
		Username:  storedToken.UserID,
		Scope:     strings.Join(storedToken.Scopes, " "),
		TokenType: storedToken.TokenType,
		ExpiresAt: storedToken.ExpiresAt.Unix(),
		IssuedAt:  storedToken.CreatedAt.Unix(),
		Subject:   storedToken.UserID,
	}
	if len(storedToken.Scopes) > 0 {
		response.Audience = []string{storedToken.ClientID}
	}
	return response, nil
}

// RevokeToken revokes an access token or refresh token, making it invalid for future use.
func (s *OAuth2Service) RevokeToken(ctx context.Context, req *models.RevocationRequest) error {
	s.logger.WithFields(map[string]interface{}{
		"client_id":       req.ClientID,
		"token_type_hint": req.TokenTypeHint,
	}).Info("Processing token revocation request")

	// Validate client
	_, err := s.ValidateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	if req.Token == "" {
		return models.NewInvalidRequest("token is required")
	}

	// Determine token type and revoke accordingly
	switch req.TokenTypeHint {
	case "access_token", "":
		// Try to revoke as access token first
		if accessErr := s.revokeAccessToken(ctx, req.Token); accessErr == nil {
			s.logger.Info("Access token revoked successfully")
			return nil
		}
		// If not found as access token, try as refresh token
		fallthrough
	case "refresh_token":
		if refreshErr := s.revokeRefreshToken(ctx, req.Token); refreshErr == nil {
			s.logger.Info("Refresh token revoked successfully")
			return nil
		}
	}

	// Even if token is not found, RFC 7009 requires returning success
	// to prevent token scanning attacks
	s.logger.Debug("Token not found for revocation (returning success per RFC 7009)")
	return nil
}

// revokeAccessToken revokes an access token by marking it as revoked and blacklisting it.
func (s *OAuth2Service) revokeAccessToken(ctx context.Context, tokenString string) error {
	// First, try to validate the token to get expiration info
	accessToken, _, err := s.tokenSvc.ValidateAccessToken(tokenString)
	if err != nil {
		// Try to get from storage (for opaque tokens)
		accessToken, err = s.store.GetAccessToken(ctx, tokenString)
		if err != nil {
			return errors.New("token not found")
		}
	}

	// Revoke the token in storage
	if revokeErr := s.store.RevokeAccessToken(ctx, tokenString); revokeErr != nil {
		s.logger.WithError(revokeErr).Error("Failed to revoke access token in storage")
	}

	// Blacklist the token to prevent use even if it's a valid JWT
	ttl := time.Until(accessToken.ExpiresAt)
	if ttl > 0 {
		if blErr := s.store.BlacklistToken(ctx, tokenString, ttl); blErr != nil {
			s.logger.WithError(blErr).Error("Failed to blacklist access token")
			return fmt.Errorf("failed to blacklist token: %w", blErr)
		}
	}

	return nil
}

// revokeRefreshToken revokes a refresh token by marking it as revoked.
func (s *OAuth2Service) revokeRefreshToken(ctx context.Context, tokenString string) error {
	// Get refresh token
	refreshToken, err := s.store.GetRefreshToken(ctx, tokenString)
	if err != nil {
		return errors.New("refresh token not found")
	}

	// Revoke the refresh token
	if revokeErr := s.store.RevokeRefreshToken(ctx, tokenString); revokeErr != nil {
		s.logger.WithError(revokeErr).Error("Failed to revoke refresh token")
		return fmt.Errorf("failed to revoke refresh token: %w", revokeErr)
	}

	// Also revoke the associated access token if it exists
	if refreshToken.AccessToken != "" {
		if accessErr := s.revokeAccessToken(ctx, refreshToken.AccessToken); accessErr != nil {
			s.logger.WithError(accessErr).Warn("Failed to revoke associated access token")
		}
	}

	return nil
}

// GetUserInfo returns user information for a valid access token with openid scope.
// This implements the OpenID Connect UserInfo endpoint.
func (s *OAuth2Service) GetUserInfo(ctx context.Context, accessToken string) (*models.UserInfo, error) {
	s.logger.Debug("Processing UserInfo request")

	if accessToken == "" {
		return nil, models.NewInvalidRequest("Access token is required")
	}

	// Validate token and check permissions
	tokenObj, jwtToken, err := s.validateTokenForUserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Build UserInfo response
	userInfo := s.buildUserInfoFromToken(tokenObj, jwtToken)

	s.logger.WithFields(map[string]interface{}{
		"user_id":   tokenObj.UserID,
		"client_id": tokenObj.ClientID,
	}).Debug("UserInfo request processed successfully")

	return userInfo, nil
}

// validateTokenForUserInfo validates the access token and checks required permissions for UserInfo endpoint.
func (s *OAuth2Service) validateTokenForUserInfo(
	ctx context.Context,
	accessToken string,
) (*models.AccessToken, *jwt.Token, error) {
	// First check if token is blacklisted
	blacklisted, err := s.store.IsTokenBlacklisted(ctx, accessToken)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check token blacklist")
	}
	if blacklisted {
		return nil, nil, models.NewInvalidGrant("Token has been revoked")
	}

	// Validate access token
	tokenObj, jwtToken, err := s.tokenSvc.ValidateAccessToken(accessToken)
	if err != nil {
		// Try to get from storage for opaque tokens
		tokenObj, err = s.store.GetAccessToken(ctx, accessToken)
		if err != nil {
			return nil, nil, models.NewInvalidGrant("Invalid access token")
		}
		jwtToken = nil
	}

	// Check if token is expired or revoked
	if tokenObj.IsExpired() || tokenObj.Revoked {
		return nil, nil, models.NewInvalidGrant("Access token is expired or revoked")
	}

	// Check if token has openid scope
	if !s.containsScope(tokenObj.Scopes, "openid") {
		return nil, nil, models.NewInvalidScope("Access token must have 'openid' scope for UserInfo endpoint")
	}

	return tokenObj, jwtToken, nil
}

// buildUserInfoFromToken builds UserInfo response from token claims.
func (s *OAuth2Service) buildUserInfoFromToken(tokenObj *models.AccessToken, jwtToken *jwt.Token) *models.UserInfo {
	userInfo := &models.UserInfo{
		Subject: tokenObj.UserID,
	}

	// Extract claims from JWT token or stored claims
	var claims map[string]interface{}
	if jwtToken != nil {
		if tokenClaims, ok := jwtToken.Claims.(*token.Claims); ok && tokenClaims.Claims != nil {
			claims = tokenClaims.Claims
		}
	} else if tokenObj.Claims != nil {
		claims = tokenObj.Claims
	}

	if claims != nil {
		s.populateUserInfoClaims(userInfo, claims)
	}

	return userInfo
}

// populateUserInfoClaims populates UserInfo with claims from the token.
func (s *OAuth2Service) populateUserInfoClaims(userInfo *models.UserInfo, claims map[string]interface{}) {
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		userInfo.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		userInfo.FamilyName = familyName
	}
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		userInfo.EmailVerified = emailVerified
	}
	if picture, ok := claims["picture"].(string); ok {
		userInfo.Picture = picture
	}
	if updatedAt, ok := claims["updated_at"].(float64); ok {
		userInfo.UpdatedAt = int64(updatedAt)
	}
}
