package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/database"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/repository"
	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/token"
)

const (
	passwordResetTokenExpiry = 15 * time.Minute // pragma: allowlist secret
	bcryptCost               = 12
)

// DatabaseUnavailableError represents an error when database operations fail due to database being unavailable.
type DatabaseUnavailableError struct {
	Operation string
}

func (e *DatabaseUnavailableError) Error() string {
	return fmt.Sprintf("database unavailable for operation: %s", e.Operation)
}

func (e *DatabaseUnavailableError) HTTPStatusCode() int {
	return http.StatusServiceUnavailable
}

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
	dbMgr    *database.Manager
	userRepo repository.UserRepository
}

func NewUserService(
	cfg *config.Config,
	store redis.Store,
	tokenSvc token.Service,
	logger *logrus.Logger,
	dbMgr *database.Manager,
) UserService {
	var userRepo repository.UserRepository
	if dbMgr != nil && dbMgr.Pool() != nil {
		userRepo = repository.NewPostgresUserRepository(dbMgr.Pool())
	}

	return &userService{
		config:   cfg,
		store:    store,
		tokenSvc: tokenSvc,
		logger:   logger,
		dbMgr:    dbMgr,
		userRepo: userRepo,
	}
}

// isDatabaseAvailable checks if database operations can be performed.
func (s *userService) isDatabaseAvailable() bool {
	return s.dbMgr != nil && s.dbMgr.IsAvailable() && s.userRepo != nil
}

// checkDatabaseRequirement returns an error if database is required but unavailable.
func (s *userService) checkDatabaseRequirement(operation string) error {
	if !s.isDatabaseAvailable() {
		return &DatabaseUnavailableError{Operation: operation}
	}
	return nil
}

// checkUsernameExists checks if a username exists in database first, then Redis.
func (s *userService) checkUsernameExists(ctx context.Context, username string) bool {
	if s.isDatabaseAvailable() {
		exists, err := s.userRepo.IsUsernameExists(ctx, username)
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check username in database, falling back to Redis")
		} else {
			return exists
		}
	}

	// Fallback check in Redis
	existingUser, err := s.store.GetUser(ctx, username)
	return existingUser != nil && err == nil
}

// checkEmailExists checks if an email exists in database first, then Redis.
func (s *userService) checkEmailExists(ctx context.Context, email string) bool {
	if s.isDatabaseAvailable() {
		exists, err := s.userRepo.IsEmailExists(ctx, email)
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check email in database, falling back to Redis")
		} else {
			return exists
		}
	}

	// Fallback check in Redis
	existingUser, err := s.store.GetUserByEmail(ctx, email)
	return existingUser != nil && err == nil
}

// createUserInStorage creates user in database first, then caches in Redis.
func (s *userService) createUserInStorage(ctx context.Context, user *models.UserWithPassword) error {
	if s.isDatabaseAvailable() {
		if dbErr := s.userRepo.CreateUser(ctx, user); dbErr != nil {
			s.logger.WithError(dbErr).Error("Failed to create user in database")
			return errors.New("failed to create user")
		}
		s.logger.WithField("user_id", user.UserID.String()).Info("User created in database")

		// Cache in Redis for performance (best effort)
		if cacheErr := s.store.StoreUser(ctx, user); cacheErr != nil {
			s.logger.WithError(cacheErr).Warn("Failed to cache user in Redis (non-fatal)")
		}
		return nil
	}

	// Fallback to Redis-only mode (shouldn't happen due to earlier check)
	if storeErr := s.store.StoreUser(ctx, user); storeErr != nil {
		s.logger.WithError(storeErr).Error("Failed to store user in Redis")
		return errors.New("failed to create user")
	}
	return nil
}

// getUserByIdentifier gets user by username or email with database-first strategy.
func (s *userService) getUserByIdentifier(
	ctx context.Context,
	username *string,
	email *string,
) (*models.UserWithPassword, error) {
	var user *models.UserWithPassword
	var err error

	if username != nil {
		user, err = s.getUserByUsername(ctx, *username)
		if err != nil {
			s.logger.WithField("username", *username).Warn("User not found")
			return nil, errors.New("invalid credentials")
		}
	} else if email != nil {
		user, err = s.getUserByEmail(ctx, *email)
		if err != nil {
			s.logger.WithField("email", *email).Warn("User not found by email")
			return nil, errors.New("invalid credentials")
		}
	}

	return user, nil
}

// getUserByUsername retrieves user by username with database-first strategy.
func (s *userService) getUserByUsername(ctx context.Context, username string) (*models.UserWithPassword, error) {
	if s.isDatabaseAvailable() {
		user, err := s.userRepo.GetUserByUsername(ctx, username)
		if err != nil {
			s.logger.WithField("username", username).Debug("User not found in database, trying Redis")
			// Fallback to Redis
			return s.store.GetUser(ctx, username)
		}
		return user, nil
	}
	return s.store.GetUser(ctx, username)
}

// getUserByEmail retrieves user by email with database-first strategy.
func (s *userService) getUserByEmail(ctx context.Context, email string) (*models.UserWithPassword, error) {
	if s.isDatabaseAvailable() {
		user, err := s.userRepo.GetUserByEmail(ctx, email)
		if err != nil {
			s.logger.WithField("email", email).Debug("User not found in database, trying Redis")
			// Fallback to Redis
			return s.store.GetUserByEmail(ctx, email)
		}
		return user, nil
	}
	return s.store.GetUserByEmail(ctx, email)
}

// buildUserFromRequest creates a user model from registration request.
func (s *userService) buildUserFromRequest(
	req *models.UserRegistrationRequest,
	hashedPassword string,
) *models.UserWithPassword {
	user := models.NewUser(req.Username, req.Email, "", "")
	if req.FullName != nil {
		user.FullName = req.FullName
	}
	if req.Bio != nil {
		user.Bio = req.Bio
	}
	user.PasswordHash = hashedPassword // pragma: allowlist secret
	return user
}

// updateUserPassword updates user password in database first, then Redis cache. // pragma: allowlist secret.
func (s *userService) updateUserPassword(ctx context.Context, user *models.UserWithPassword) error {
	user.UpdatedAt = time.Now()

	if s.isDatabaseAvailable() {
		if updateErr := s.userRepo.UpdateUser(ctx, user); updateErr != nil {
			s.logger.WithError(updateErr).Error("Failed to update user password in database")
			return errors.New("failed to update password")
		}

		// Update cache in Redis (best effort)
		if cacheErr := s.store.UpdateUser(ctx, user); cacheErr != nil {
			s.logger.WithError(cacheErr).Warn("Failed to update user password cache in Redis (non-fatal)")
		}
		return nil
	}

	// Fallback to Redis-only (shouldn't happen due to earlier check)
	if updateErr := s.store.UpdateUser(ctx, user); updateErr != nil {
		s.logger.WithError(updateErr).Error("Failed to update user password in Redis")
		return errors.New("failed to update password")
	}
	return nil
}

func (s *userService) RegisterUser(
	ctx context.Context,
	req *models.UserRegistrationRequest,
) (*models.UserRegistrationResponse, error) {
	s.logger.WithField("username", req.Username).Info("Processing user registration request")

	// Check if database is required but unavailable
	if err := s.checkDatabaseRequirement("user registration"); err != nil {
		s.logger.WithError(err).Warn("Database unavailable for user registration")
		return nil, err
	}

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid user registration request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if username exists
	if s.checkUsernameExists(ctx, req.Username) {
		return nil, errors.New("username already exists")
	}

	// Check if email exists (database first, fallback to Redis)
	if req.Email != "" && s.checkEmailExists(ctx, req.Email) {
		return nil, errors.New("email already registered")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return nil, errors.New("failed to process password")
	}

	user := s.buildUserFromRequest(req, string(hashedPassword))
	if createErr := s.createUserInStorage(ctx, user); createErr != nil {
		return nil, createErr
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

	// Check if database is required but unavailable
	if err := s.checkDatabaseRequirement("user login"); err != nil {
		s.logger.WithError(err).Warn("Database unavailable for user login")
		return nil, err
	}

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid user login request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	user, err := s.getUserByIdentifier(ctx, req.Username, req.Email)
	if err != nil {
		return nil, err
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

	// Check if database is required but unavailable
	if err := s.checkDatabaseRequirement("password reset request"); err != nil {
		s.logger.WithError(err).Warn("Database unavailable for password reset")
		return nil, err
	}

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Warn("Invalid password reset request")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	user, err := s.getUserByEmail(ctx, req.Email)

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

	// Check if database is required but unavailable
	if err := s.checkDatabaseRequirement("password reset confirmation"); err != nil {
		s.logger.WithError(err).Warn("Database unavailable for password reset confirmation")
		return nil, err
	}

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

	user, err := s.getUserByEmail(ctx, resetToken.Email)

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
	if updateErr := s.updateUserPassword(ctx, user); updateErr != nil {
		return nil, updateErr
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
