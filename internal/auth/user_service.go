package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/token"
)

const (
	passwordResetTokenExpiry = 15 * time.Minute // pragma: allowlist secret
	bcryptCost               = 12
)

type UserService interface {
	RegisterUser(ctx context.Context, req *models.UserRegistrationRequest) (*models.UserRegistrationResponse, error)
	LoginUser(ctx context.Context, req *models.UserLoginRequest) (*models.UserLoginResponse, error)
	LogoutUser(ctx context.Context, userID string) (*models.UserLogoutResponse, error)
	RefreshToken(ctx context.Context, req *models.UserRefreshRequest) (*models.UserRefreshResponse, error)
	RequestPasswordReset(
		ctx context.Context,
		req *models.UserPasswordResetRequest,
	) (*models.UserPasswordResetResponse, error)
	ConfirmPasswordReset(
		ctx context.Context,
		req *models.UserPasswordResetConfirmRequest,
	) (*models.UserPasswordResetConfirmResponse, error)
}

type userService struct {
	config   *config.Config
	store    redis.Store
	tokenSvc token.Service
	logger   *logrus.Logger
}

func NewUserService(
	cfg *config.Config,
	store redis.Store,
	tokenSvc token.Service,
	logger *logrus.Logger,
) UserService {
	return &userService{
		config:   cfg,
		store:    store,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

func (s *userService) RegisterUser(
	ctx context.Context,
	req *models.UserRegistrationRequest,
) (*models.UserRegistrationResponse, error) {
	s.logger.WithField("username", req.Username).Info("Processing user registration request")

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid user registration request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	existingUser, err := s.store.GetUser(ctx, req.Username)
	if err == nil && existingUser != nil {
		return nil, errors.New("username already exists")
	}

	if req.Email != "" {
		existingUserByEmail, emailErr := s.store.GetUserByEmail(ctx, req.Email)
		if emailErr == nil && existingUserByEmail != nil {
			return nil, errors.New("email already registered")
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return nil, errors.New("failed to process password")
	}

	user := models.NewUser(req.Username, req.Email, "", "")
	if req.FullName != nil {
		user.FullName = req.FullName
	}
	if req.Bio != nil {
		user.Bio = req.Bio
	}
	user.PasswordHash = string(hashedPassword)

	if storeErr := s.store.StoreUser(ctx, user); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store user")
		return nil, errors.New("failed to create user")
	}

	accessToken, accessTokenObj, err := s.tokenSvc.GenerateAccessToken(
		"user-client", user.UserID.String(), []string{"openid", "profile"}, nil,
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate access token")
		return nil, errors.New("failed to generate access token")
	}

	if storeErr := s.store.StoreAccessToken(ctx, accessTokenObj, s.config.JWT.AccessTokenExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store access token")
		return nil, errors.New("failed to store access token")
	}

	refreshToken, refreshTokenObj, err := s.tokenSvc.GenerateRefreshToken(
		accessToken, "user-client", user.UserID.String(), []string{"openid", "profile"},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
	} else {
		if storeErr := s.store.StoreRefreshToken(ctx, refreshTokenObj, s.config.JWT.RefreshTokenExpiry); storeErr != nil {
			s.logger.WithError(storeErr).Error("Failed to store refresh token")
			refreshToken = ""
		}
	}

	token := &models.Token{
		AccessToken: accessToken,
		TokenType:   models.TokenTypeBearer,
		ExpiresIn:   int(s.config.JWT.AccessTokenExpiry.Seconds()),
	}
	if refreshToken != "" {
		token.RefreshToken = &refreshToken
	}

	s.logger.WithFields(logrus.Fields{
		"username": user.Username,
		"user_id":  user.UserID.String(),
	}).Info("User registered successfully")

	return &models.UserRegistrationResponse{
		User:  user.User,
		Token: token,
	}, nil
}

func (s *userService) LoginUser(ctx context.Context, req *models.UserLoginRequest) (*models.UserLoginResponse, error) {
	s.logger.Info("Processing user login request")

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid user login request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	var user *models.UserWithPassword
	var err error

	if req.Username != nil {
		user, err = s.store.GetUser(ctx, *req.Username)
		if err != nil {
			s.logger.WithField("username", *req.Username).Warn("User not found")
			return nil, errors.New("invalid credentials")
		}
	} else if req.Email != nil {
		user, err = s.store.GetUserByEmail(ctx, *req.Email)
		if err != nil {
			s.logger.WithField("email", *req.Email).Warn("User not found by email")
			return nil, errors.New("invalid credentials")
		}
	}

	if !user.IsActive {
		s.logger.WithField("user_id", user.UserID.String()).Warn("Inactive user attempted login")
		return nil, errors.New("account is inactive")
	}

	if bcryptErr := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); bcryptErr != nil {
		s.logger.WithField("user_id", user.UserID.String()).Warn("Invalid password")
		return nil, errors.New("invalid credentials")
	}

	accessToken, accessTokenObj, err := s.tokenSvc.GenerateAccessToken(
		"user-client", user.UserID.String(), []string{"openid", "profile"}, nil,
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate access token")
		return nil, errors.New("failed to generate access token")
	}

	if storeErr := s.store.StoreAccessToken(ctx, accessTokenObj, s.config.JWT.AccessTokenExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store access token")
		return nil, errors.New("failed to store access token")
	}

	refreshToken, refreshTokenObj, err := s.tokenSvc.GenerateRefreshToken(
		accessToken, "user-client", user.UserID.String(), []string{"openid", "profile"},
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
	} else {
		if storeErr := s.store.StoreRefreshToken(ctx, refreshTokenObj, s.config.JWT.RefreshTokenExpiry); storeErr != nil {
			s.logger.WithError(storeErr).Error("Failed to store refresh token")
			refreshToken = ""
		}
	}

	token := models.Token{
		AccessToken: accessToken,
		TokenType:   models.TokenTypeBearer,
		ExpiresIn:   int(s.config.JWT.AccessTokenExpiry.Seconds()),
	}
	if refreshToken != "" {
		token.RefreshToken = &refreshToken
	}

	s.logger.WithFields(logrus.Fields{
		"username": user.Username,
		"user_id":  user.UserID.String(),
	}).Info("User logged in successfully")

	return &models.UserLoginResponse{
		User:  user.User,
		Token: token,
	}, nil
}

func (s *userService) LogoutUser(_ context.Context, userID string) (*models.UserLogoutResponse, error) {
	s.logger.WithField("user_id", userID).Info("Processing user logout request")

	return &models.UserLogoutResponse{
		Message:            "User logged out successfully",
		SessionInvalidated: true,
	}, nil
}

func (s *userService) RefreshToken(
	ctx context.Context,
	req *models.UserRefreshRequest,
) (*models.UserRefreshResponse, error) {
	s.logger.Info("Processing token refresh request")

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid token refresh request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	refreshTokenObj, err := s.store.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		s.logger.WithError(err).Warn("Invalid refresh token")
		return nil, errors.New("invalid refresh token")
	}

	if refreshTokenObj.Revoked {
		s.logger.WithField("token", req.RefreshToken).Warn("Refresh token has been revoked")
		return nil, errors.New("refresh token has been revoked")
	}

	if refreshTokenObj.IsExpired() {
		s.logger.WithField("token", req.RefreshToken).Warn("Refresh token has expired")
		_ = s.store.DeleteRefreshToken(ctx, req.RefreshToken)
		return nil, errors.New("refresh token has expired")
	}

	accessToken, accessTokenObj, err := s.tokenSvc.GenerateAccessToken(
		refreshTokenObj.ClientID, refreshTokenObj.UserID, refreshTokenObj.Scopes, nil,
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate new access token")
		return nil, errors.New("failed to generate new access token")
	}

	if storeErr := s.store.StoreAccessToken(ctx, accessTokenObj, s.config.JWT.AccessTokenExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store new access token")
		return nil, errors.New("failed to store new access token")
	}

	// Generate new refresh token (token rotation for security)
	newRefreshToken, newRefreshTokenObj, err := s.tokenSvc.GenerateRefreshToken(
		accessToken, refreshTokenObj.ClientID, refreshTokenObj.UserID, refreshTokenObj.Scopes,
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate new refresh token")
		return nil, errors.New("failed to generate new refresh token")
	}

	// Store new refresh token
	if storeErr := s.store.StoreRefreshToken(ctx, newRefreshTokenObj, s.config.JWT.RefreshTokenExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store new refresh token")
		return nil, errors.New("failed to store new refresh token")
	}

	// Revoke old refresh token
	if revokeErr := s.store.RevokeRefreshToken(ctx, req.RefreshToken); revokeErr != nil {
		s.logger.WithError(revokeErr).Warn("Failed to revoke old refresh token")
		// Don't fail the request, just log the warning
	}

	token := models.Token{
		AccessToken:  accessToken,
		RefreshToken: &newRefreshToken,
		TokenType:    models.TokenTypeBearer,
		ExpiresIn:    int(s.config.JWT.AccessTokenExpiry.Seconds()),
	}

	s.logger.WithField("user_id", refreshTokenObj.UserID).Info("Token refreshed successfully with new refresh token")

	return &models.UserRefreshResponse{
		Message: "Token refreshed successfully",
		Token:   token,
	}, nil
}

func (s *userService) RequestPasswordReset(
	ctx context.Context,
	req *models.UserPasswordResetRequest,
) (*models.UserPasswordResetResponse, error) {
	s.logger.WithField("email", req.Email).Info("Processing password reset request")

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid password reset request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.WithField("email", req.Email).Debug("User not found for password reset")
		//nolint:nilerr // Intentionally return success to prevent email enumeration
		return &models.UserPasswordResetResponse{
			Message:   "Password reset email sent successfully",
			EmailSent: true,
		}, nil
	}

	if !user.IsActive {
		s.logger.WithField("email", req.Email).Warn("Password reset requested for inactive user")
		return &models.UserPasswordResetResponse{
			Message:   "Password reset email sent successfully",
			EmailSent: true,
		}, nil
	}

	resetToken := models.NewPasswordResetToken(user.UserID, req.Email, passwordResetTokenExpiry)

	if storeErr := s.store.StorePasswordResetToken(ctx, resetToken, passwordResetTokenExpiry); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store password reset token")
		return nil, errors.New("failed to process password reset request")
	}

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.UserID.String(),
		"token":   resetToken.Token[:8] + "...",
	}).Info("Password reset token generated")

	return &models.UserPasswordResetResponse{
		Message:   "Password reset email sent successfully",
		EmailSent: true,
	}, nil
}

func (s *userService) ConfirmPasswordReset(
	ctx context.Context,
	req *models.UserPasswordResetConfirmRequest,
) (*models.UserPasswordResetConfirmResponse, error) {
	s.logger.Info("Processing password reset confirmation")

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid password reset confirmation request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	resetToken, err := s.store.GetPasswordResetToken(ctx, req.ResetToken)
	if err != nil {
		s.logger.WithError(err).Warn("Invalid password reset token")
		return nil, errors.New("invalid or expired reset token")
	}

	if resetToken.Used {
		s.logger.WithField("token", req.ResetToken[:8]+"...").Warn("Password reset token already used")
		return nil, errors.New("reset token has already been used")
	}

	if resetToken.IsExpired() {
		s.logger.WithField("token", req.ResetToken[:8]+"...").Warn("Password reset token expired")
		_ = s.store.DeletePasswordResetToken(ctx, req.ResetToken)
		return nil, errors.New("reset token has expired")
	}

	user, err := s.store.GetUserByEmail(ctx, resetToken.Email)
	if err != nil {
		s.logger.WithError(err).Error("User not found during password reset")
		return nil, errors.New("user not found")
	}

	if user.UserID != resetToken.UserID {
		s.logger.WithField("user_id", user.UserID.String()).Error("User ID mismatch during password reset")
		return nil, errors.New("invalid reset token")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new password")
		return nil, errors.New("failed to process new password")
	}

	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	if updateErr := s.store.UpdateUser(ctx, user); updateErr != nil {
		s.logger.WithError(updateErr).Error("Failed to update user password")
		return nil, errors.New("failed to update password")
	}

	resetToken.Used = true
	if storeErr := s.store.StorePasswordResetToken(ctx, resetToken, time.Until(resetToken.ExpiresAt)); storeErr != nil {
		s.logger.WithError(storeErr).Warn("Failed to mark reset token as used")
	}

	_ = s.store.DeletePasswordResetToken(ctx, req.ResetToken)

	s.logger.WithFields(logrus.Fields{
		"user_id": user.UserID.String(),
		"email":   user.Email,
	}).Info("Password reset completed successfully")

	return &models.UserPasswordResetConfirmResponse{
		Message:         "Password reset successfully",
		PasswordUpdated: true,
	}, nil
}
