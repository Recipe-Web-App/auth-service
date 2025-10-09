package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/constants"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/token"
)

const (
	internalServerError = "Internal server error"
)

type UserAuthHandler struct {
	userSvc  auth.UserService
	tokenSvc token.Service
	config   *config.Config
	logger   *logrus.Logger
}

func NewUserAuthHandler(
	userSvc auth.UserService,
	tokenSvc token.Service,
	cfg *config.Config,
	logger *logrus.Logger,
) *UserAuthHandler {
	return &UserAuthHandler{
		userSvc:  userSvc,
		tokenSvc: tokenSvc,
		config:   cfg,
		logger:   logger,
	}
}

func (h *UserAuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing user registration request")

	var req models.UserRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	resp, err := h.userSvc.RegisterUser(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Warn("User registration failed")

		errorMsg := err.Error()
		statusCode := http.StatusBadRequest

		switch {
		case strings.Contains(errorMsg, "username already exists"),
			strings.Contains(errorMsg, "email already registered"):
			statusCode = http.StatusConflict
		case strings.Contains(errorMsg, "validation failed"):
			statusCode = http.StatusUnprocessableEntity
		case strings.Contains(errorMsg, "failed to create user"),
			strings.Contains(errorMsg, "failed to generate"),
			strings.Contains(errorMsg, "failed to store"):
			statusCode = http.StatusInternalServerError
			errorMsg = internalServerError
		}

		h.writeErrorResponse(w, errorMsg, statusCode)
		return
	}

	h.writeJSONResponse(w, resp)
	h.logger.WithField("username", resp.User.Username).Info("User registered successfully")
}

func (h *UserAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing user login request")

	var req models.UserLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	resp, err := h.userSvc.LoginUser(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Warn("User login failed")

		errorMsg := err.Error()
		statusCode := http.StatusUnauthorized

		switch {
		case strings.Contains(errorMsg, "validation failed"):
			statusCode = http.StatusUnprocessableEntity
		case strings.Contains(errorMsg, "invalid credentials"),
			strings.Contains(errorMsg, "account is inactive"):
			statusCode = http.StatusUnauthorized
			errorMsg = "Invalid credentials or inactive account"
		case strings.Contains(errorMsg, "failed to generate"),
			strings.Contains(errorMsg, "failed to store"):
			statusCode = http.StatusInternalServerError
			errorMsg = internalServerError
		}

		h.writeErrorResponse(w, errorMsg, statusCode)
		return
	}

	h.writeJSONResponse(w, resp)
	h.logger.WithField("username", resp.User.Username).Info("User logged in successfully")
}

func (h *UserAuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getCurrentUserID(r)
	if err != nil {
		h.writeErrorResponse(w, "Invalid or missing authorization token", http.StatusUnauthorized)
		return
	}

	h.logger.WithField("user_id", userID).Info("Processing user logout request")

	resp, err := h.userSvc.LogoutUser(ctx, userID)
	if err != nil {
		h.logger.WithError(err).Error("User logout failed")
		h.writeErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, resp)
	h.logger.WithField("user_id", userID).Info("User logged out successfully")
}

func (h *UserAuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing token refresh request")

	var req models.UserRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	resp, err := h.userSvc.RefreshToken(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Warn("Token refresh failed")

		errorMsg := err.Error()
		statusCode := http.StatusUnauthorized

		switch {
		case strings.Contains(errorMsg, "validation failed"):
			statusCode = http.StatusUnprocessableEntity
		case strings.Contains(errorMsg, "invalid refresh token"),
			strings.Contains(errorMsg, "refresh token has been revoked"),
			strings.Contains(errorMsg, "refresh token has expired"):
			statusCode = http.StatusUnauthorized
			errorMsg = "Invalid refresh token or no active session"
		case strings.Contains(errorMsg, "failed to generate"),
			strings.Contains(errorMsg, "failed to store"):
			statusCode = http.StatusInternalServerError
			errorMsg = internalServerError
		}

		h.writeErrorResponse(w, errorMsg, statusCode)
		return
	}

	h.writeJSONResponse(w, resp)
	h.logger.Info("Token refreshed successfully")
}

func (h *UserAuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing password reset request")

	var req models.UserPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	resp, err := h.userSvc.RequestPasswordReset(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Error("Password reset request failed")

		statusCode := http.StatusBadRequest
		switch {
		case strings.Contains(err.Error(), "validation failed"):
			statusCode = http.StatusUnprocessableEntity
		case strings.Contains(err.Error(), "failed to process"):
			statusCode = http.StatusInternalServerError
		}

		h.writeErrorResponse(w, err.Error(), statusCode)
		return
	}

	h.writeJSONResponse(w, resp)
	h.logger.Info("Password reset email sent successfully")
}

func (h *UserAuthHandler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing password reset confirmation")

	var req models.UserPasswordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	resp, err := h.userSvc.ConfirmPasswordReset(ctx, &req)
	if err != nil {
		h.logger.WithError(err).Warn("Password reset confirmation failed")

		errorMsg := err.Error()
		statusCode := http.StatusBadRequest

		switch {
		case strings.Contains(errorMsg, "validation failed"):
			statusCode = http.StatusUnprocessableEntity
		case strings.Contains(errorMsg, "invalid or expired reset token"),
			strings.Contains(errorMsg, "reset token has already been used"),
			strings.Contains(errorMsg, "reset token has expired"),
			strings.Contains(errorMsg, "invalid reset token"):
			statusCode = http.StatusBadRequest
			errorMsg = "Invalid or expired reset token"
		case strings.Contains(errorMsg, "failed to process"),
			strings.Contains(errorMsg, "failed to update"),
			strings.Contains(errorMsg, "user not found"):
			statusCode = http.StatusInternalServerError
			errorMsg = internalServerError
		}

		h.writeErrorResponse(w, errorMsg, statusCode)
		return
	}

	h.writeJSONResponse(w, resp)
	h.logger.Info("Password reset completed successfully")
}

func (h *UserAuthHandler) getCurrentUserID(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", models.NewInvalidRequest("Authorization header required")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", models.NewInvalidRequest("Invalid authorization header format")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return "", models.NewInvalidRequest("Access token required")
	}

	_, jwtToken, err := h.tokenSvc.ValidateAccessToken(tokenString)
	if err != nil {
		return "", models.NewInvalidGrant("Invalid access token")
	}

	claims, ok := jwtToken.Claims.(*token.Claims)
	if !ok {
		return "", models.NewInvalidGrant("Invalid token claims")
	}

	return claims.Subject, nil
}

func (h *UserAuthHandler) writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

func (h *UserAuthHandler) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	errorResponse := map[string]interface{}{
		"error":             "authentication_error",
		"error_description": message,
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		h.logger.WithError(err).Error("Failed to encode error response")
	}

	h.logger.WithFields(logrus.Fields{
		"status_code": statusCode,
		"error":       message,
	}).Warn("Authentication error response sent")
}
