// Package handlers provides HTTP handlers for OAuth2 endpoints including
// authorization, token, introspection, revocation, and UserInfo endpoints.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/constants"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
)

// OAuth2Handler handles all OAuth2-related HTTP requests.
type OAuth2Handler struct {
	authSvc auth.Service
	config  *config.Config
	logger  *logrus.Logger
}

const (
	invalidFormDataError = "Invalid form data"
	encodingFailureError = "Failed to encode response"
)

// NewOAuth2Handler creates a new OAuth2 HTTP handler.
func NewOAuth2Handler(authSvc auth.Service, cfg *config.Config, logger *logrus.Logger) *OAuth2Handler {
	return &OAuth2Handler{
		authSvc: authSvc,
		config:  cfg,
		logger:  logger,
	}
}

// RegisterRoutes registers all OAuth2 endpoints with the provided router.
func (h *OAuth2Handler) RegisterRoutes(r *mux.Router) {
	// OAuth2 endpoints
	r.HandleFunc("/oauth2/authorize", h.Authorize).Methods("GET", "POST")
	r.HandleFunc("/oauth2/token", h.Token).Methods("POST")
	r.HandleFunc("/oauth2/revoke", h.RevokeToken).Methods("POST")
	r.HandleFunc("/oauth2/introspect", h.IntrospectToken).Methods("POST")
	r.HandleFunc("/oauth2/userinfo", h.UserInfo).Methods("GET", "POST")

	// Discovery endpoint
	r.HandleFunc("/.well-known/oauth-authorization-server", h.WellKnownOAuthServer).Methods("GET")

	// Client management endpoints (for development/admin)
	r.HandleFunc("/oauth/clients", h.RegisterClient).Methods("POST")
	r.HandleFunc("/oauth/clients/{client_id}", h.GetClient).Methods("GET")
}

// Authorize handles OAuth2 authorization requests with PKCE support.
// It validates the request parameters, checks client authorization,
// and generates an authorization code for valid requests.
func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"query":  r.URL.RawQuery,
	}).Info("Processing authorization request")

	// Parse request parameters
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, r, models.NewInvalidRequest(invalidFormDataError), "")
		return
	}

	req := &models.AuthorizeRequest{
		ResponseType:        models.ResponseType(r.FormValue("response_type")),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	// For this example, we'll simulate user authentication
	// In a real implementation, you would:
	// 1. Check if user is authenticated (session/cookie)
	// 2. If not authenticated, redirect to login page
	// 3. If authenticated, show consent page (if needed)
	// 4. After user consent, generate authorization code

	// Simulate authenticated user ID (in production, extract from session)
	userID := "user123" // This would come from authentication session

	// Process authorization request
	resp, err := h.authSvc.Authorize(ctx, req, userID)
	if err != nil {
		h.writeOAuth2Error(w, r, err, req.State)
		return
	}

	// Redirect user back to client with authorization code
	redirectURL, _ := url.Parse(req.RedirectURI)
	query := redirectURL.Query()
	query.Set("code", resp.Code)
	if resp.State != "" {
		query.Set("state", resp.State)
	}
	redirectURL.RawQuery = query.Encode()

	h.logger.WithFields(logrus.Fields{
		"client_id":    req.ClientID,
		"redirect_uri": redirectURL.String(),
	}).Info("Authorization successful, redirecting client")

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// Token handles token requests for all supported grant types.
func (h *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.WithField("grant_type", r.FormValue("grant_type")).Info("Processing token request")

	// Parse request
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, r, models.NewInvalidRequest(invalidFormDataError), "")
		return
	}

	// Extract client credentials from Basic Auth or form
	clientID, clientSecret := h.extractClientCredentials(r)

	req := &models.TokenRequest{
		GrantType:    models.GrantType(r.FormValue("grant_type")),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
		CodeVerifier: r.FormValue("code_verifier"),
	}

	// Process token request
	resp, err := h.authSvc.Token(ctx, req)
	if err != nil {
		h.writeOAuth2Error(w, r, err, "")
		return
	}

	// Marshal response first so we can handle errors before writing headers/body.
	payload, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		h.logger.WithError(marshalErr).Error("Failed to marshal token response")
		h.writeOAuth2Error(w, r, models.NewServerError(encodingFailureError), "")
		return
	}

	// Return successful response
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if _, writeErr := w.Write(payload); writeErr != nil {
		h.logger.WithError(writeErr).Error("Failed to write token response")
		// Can't send another HTTP error here because headers/body may already be in-flight.
		return
	}

	h.logger.WithFields(logrus.Fields{
		"client_id":   req.ClientID,
		"grant_type":  req.GrantType,
		"has_refresh": resp.RefreshToken != "",
	}).Info("Token issued successfully")
}

// IntrospectToken handles token introspection requests.
func (h *OAuth2Handler) IntrospectToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Debug("Processing token introspection request")

	// Parse request
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, r, models.NewInvalidRequest(invalidFormDataError), "")
		return
	}

	// Extract client credentials
	clientID, clientSecret := h.extractClientCredentials(r)

	req := &models.IntrospectionRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}

	// Process introspection request
	resp, err := h.authSvc.IntrospectToken(ctx, req)
	if err != nil {
		h.writeOAuth2Error(w, r, err, "")
		return
	}

	// Return response
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	if encodeErr := json.NewEncoder(w).Encode(resp); encodeErr != nil {
		h.logger.WithError(encodeErr).Error("Failed to encode introspection response")
		h.writeOAuth2Error(w, r, models.NewServerError(encodingFailureError), "")
	}
}

// RevokeToken handles token revocation requests.
func (h *OAuth2Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Debug("Processing token revocation request")

	// Parse request
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, r, models.NewInvalidRequest(invalidFormDataError), "")
		return
	}

	// Extract client credentials
	clientID, clientSecret := h.extractClientCredentials(r)

	req := &models.RevocationRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}

	// Process revocation request
	if err := h.authSvc.RevokeToken(ctx, req); err != nil {
		h.writeOAuth2Error(w, r, err, "")
		return
	}

	// RFC 7009 requires 200 OK response for successful revocation
	w.WriteHeader(http.StatusOK)

	h.logger.WithField("client_id", req.ClientID).Info("Token revoked successfully")
}

// UserInfo handles OpenID Connect UserInfo requests.
func (h *OAuth2Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Debug("Processing UserInfo request")

	// Extract access token from Authorization header or form
	accessToken := h.extractAccessToken(r)
	if accessToken == "" {
		h.writeOAuth2Error(w, r, models.NewInvalidRequest("Access token is required"), "")
		return
	}

	// Get user info
	userInfo, err := h.authSvc.GetUserInfo(ctx, accessToken)
	if err != nil {
		h.writeOAuth2Error(w, r, err, "")
		return
	}

	// Return user info
	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	if encodeErr := json.NewEncoder(w).Encode(userInfo); encodeErr != nil {
		h.logger.WithError(encodeErr).Error("Failed to encode UserInfo response")
		h.writeOAuth2Error(w, r, models.NewServerError(encodingFailureError), "")
	}
}

// WellKnownOAuthServer handles OAuth2 authorization server discovery.
func (h *OAuth2Handler) WellKnownOAuthServer(w http.ResponseWriter, r *http.Request) {
	baseURL := "https://" + r.Host
	if h.config.Server.TLSCert == "" {
		baseURL = "http://" + r.Host
	}

	discovery := map[string]interface{}{
		"issuer":                                        baseURL,
		"authorization_endpoint":                        baseURL + "/oauth/authorize",
		"token_endpoint":                                baseURL + "/oauth/token",
		"revocation_endpoint":                           baseURL + "/oauth/revoke",
		"introspection_endpoint":                        baseURL + "/oauth/introspect",
		"userinfo_endpoint":                             baseURL + "/oauth/userinfo",
		"response_types_supported":                      h.config.OAuth2.SupportedResponseTypes,
		"grant_types_supported":                         h.config.OAuth2.SupportedGrantTypes,
		"scopes_supported":                              h.config.OAuth2.SupportedScopes,
		"token_endpoint_auth_methods_supported":         []string{"client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":              []string{"plain", "S256"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_post", "client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		h.logger.WithError(err).Error("Failed to encode discovery response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// RegisterClient handles client registration requests (for development/admin).
func (h *OAuth2Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Processing client registration request")

	var req struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		GrantTypes   []string `json:"grant_types"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	client, err := h.authSvc.RegisterClient(ctx, req.Name, req.RedirectURIs, req.Scopes, req.GrantTypes)
	if err != nil {
		h.logger.WithError(err).Error("Failed to register client")
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create response with secret included (only during registration)
	response := struct {
		ID           string   `json:"id"`
		Secret       string   `json:"secret"`
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		GrantTypes   []string `json:"grant_types"`
		CreatedAt    string   `json:"created_at"`
	}{
		ID:           client.ID,
		Secret:       client.Secret,
		Name:         client.Name,
		RedirectURIs: client.RedirectURIs,
		Scopes:       client.Scopes,
		GrantTypes:   client.GrantTypes,
		CreatedAt:    client.CreatedAt.Format(time.RFC3339),
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		h.logger.WithError(encodeErr).Error("Failed to encode client response")
	}
}

// GetClient handles client retrieval requests.
func (h *OAuth2Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	clientID := vars["client_id"]

	client, err := h.authSvc.GetClient(ctx, clientID)
	if err != nil {
		h.writeError(w, "Client not found", http.StatusNotFound)
		return
	}

	w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
	if encodeErr := json.NewEncoder(w).Encode(client); encodeErr != nil {
		h.logger.WithError(encodeErr).Error("Failed to encode client response")
	}
}

// extractClientCredentials extracts client credentials from Basic Auth or form parameters.
func (h *OAuth2Handler) extractClientCredentials(r *http.Request) (string, string) {
	// Try Basic Auth first
	if basicClientID, basicSecret, ok := r.BasicAuth(); ok {
		return basicClientID, basicSecret
	}

	// Fall back to form parameters
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

// extractAccessToken extracts access token from Authorization header or form.
func (h *OAuth2Handler) extractAccessToken(r *http.Request) string {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Fall back to form parameter
	return r.FormValue("access_token")
}

// writeOAuth2Error writes an OAuth2 error response.
func (h *OAuth2Handler) writeOAuth2Error(w http.ResponseWriter, _ *http.Request, err error, state string) {
	var oauth2Err *models.OAuth2Error
	if !errors.As(err, &oauth2Err) {
		oauth2Err = models.NewServerError(err.Error())
	}

	if state != "" {
		oauth2Err.State = state
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(oauth2Err.StatusCode)

	if encodeErr := json.NewEncoder(w).Encode(oauth2Err); encodeErr != nil {
		h.logger.WithError(encodeErr).Error("Failed to encode error response")
	}

	h.logger.WithFields(logrus.Fields{
		"error":       oauth2Err.Code,
		"description": oauth2Err.Description,
		"status_code": oauth2Err.StatusCode,
	}).Warn("OAuth2 error response")
}

// writeError writes a simple error response.
func (h *OAuth2Handler) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.WithError(err).Error("Failed to encode error response")
	}
}
