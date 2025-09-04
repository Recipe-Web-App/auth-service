// Package redis provides storage implementations for OAuth2 authentication data.
// This file implements an in-memory store that implements the same Store interface
// as the Redis client, allowing for local development without Redis dependencies.
package redis

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/jsamuelsen/recipe-web-app/auth-service/internal/models"
)

const (
	// CleanupInterval is the interval between expired item cleanup runs.
	CleanupInterval = 5 * time.Minute
)

// MemoryStore is an in-memory implementation of the Store interface.
// It provides the same functionality as the Redis store but without persistence.
// All data is stored in memory with TTL support via background cleanup goroutines.
type MemoryStore struct {
	clients        map[string]*models.Client
	authCodes      map[string]*expiringItem[*models.AuthorizationCode]
	accessTokens   map[string]*expiringItem[*models.AccessToken]
	refreshTokens  map[string]*expiringItem[*models.RefreshToken]
	sessions       map[string]*expiringItem[*models.Session]
	blacklist      map[string]*expiringItem[bool]
	rateLimits     map[string]*expiringItem[int]
	users          map[string]*models.UserWithPassword // username -> user
	usersByEmail   map[string]*models.UserWithPassword // email -> user
	passwordResets map[string]*expiringItem[*models.PasswordResetToken]
	logger         *logrus.Logger
	mu             sync.RWMutex
	cleanupTicker  *time.Ticker
	stopCleanup    chan struct{}
}

// expiringItem wraps data with expiration time for TTL support.
type expiringItem[T any] struct {
	Data      T
	ExpiresAt time.Time
}

// isExpired checks if the item has expired.
func (e *expiringItem[T]) isExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// NewMemoryStore creates a new in-memory store with TTL cleanup.
func NewMemoryStore(logger *logrus.Logger) *MemoryStore {
	store := &MemoryStore{
		clients:        make(map[string]*models.Client),
		authCodes:      make(map[string]*expiringItem[*models.AuthorizationCode]),
		accessTokens:   make(map[string]*expiringItem[*models.AccessToken]),
		refreshTokens:  make(map[string]*expiringItem[*models.RefreshToken]),
		sessions:       make(map[string]*expiringItem[*models.Session]),
		blacklist:      make(map[string]*expiringItem[bool]),
		rateLimits:     make(map[string]*expiringItem[int]),
		users:          make(map[string]*models.UserWithPassword),
		usersByEmail:   make(map[string]*models.UserWithPassword),
		passwordResets: make(map[string]*expiringItem[*models.PasswordResetToken]),
		logger:         logger,
		cleanupTicker:  time.NewTicker(CleanupInterval),
		stopCleanup:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupExpiredItems()

	logger.Info("In-memory store initialized with TTL cleanup")
	return store
}

// cleanupExpiredItems runs periodically to remove expired items.
func (m *MemoryStore) cleanupExpiredItems() {
	defer m.cleanupTicker.Stop()

	for {
		select {
		case <-m.cleanupTicker.C:
			m.performCleanup()
		case <-m.stopCleanup:
			return
		}
	}
}

// performCleanup removes expired items from all maps.
func (m *MemoryStore) performCleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expired := 0

	expired += m.cleanAuthCodes(now)
	expired += m.cleanAccessTokens(now)
	expired += m.cleanRefreshTokens(now)
	expired += m.cleanSessions(now)
	expired += m.cleanBlacklist(now)
	expired += m.cleanRateLimits(now)
	expired += m.cleanPasswordResets(now)

	if expired > 0 {
		m.logger.WithField("expired_items", expired).Debug("Cleaned up expired items from memory store")
	}
}

// cleanAuthCodes removes expired authorization codes.
func (m *MemoryStore) cleanAuthCodes(now time.Time) int {
	expired := 0
	for key, item := range m.authCodes {
		if now.After(item.ExpiresAt) {
			delete(m.authCodes, key)
			expired++
		}
	}
	return expired
}

// cleanAccessTokens removes expired access tokens.
func (m *MemoryStore) cleanAccessTokens(now time.Time) int {
	expired := 0
	for key, item := range m.accessTokens {
		if now.After(item.ExpiresAt) {
			delete(m.accessTokens, key)
			expired++
		}
	}
	return expired
}

// cleanRefreshTokens removes expired refresh tokens.
func (m *MemoryStore) cleanRefreshTokens(now time.Time) int {
	expired := 0
	for key, item := range m.refreshTokens {
		if now.After(item.ExpiresAt) {
			delete(m.refreshTokens, key)
			expired++
		}
	}
	return expired
}

// cleanSessions removes expired sessions.
func (m *MemoryStore) cleanSessions(now time.Time) int {
	expired := 0
	for key, item := range m.sessions {
		if now.After(item.ExpiresAt) {
			delete(m.sessions, key)
			expired++
		}
	}
	return expired
}

// cleanBlacklist removes expired blacklist entries.
func (m *MemoryStore) cleanBlacklist(now time.Time) int {
	expired := 0
	for key, item := range m.blacklist {
		if now.After(item.ExpiresAt) {
			delete(m.blacklist, key)
			expired++
		}
	}
	return expired
}

// cleanRateLimits removes expired rate limit entries.
func (m *MemoryStore) cleanRateLimits(now time.Time) int {
	expired := 0
	for key, item := range m.rateLimits {
		if now.After(item.ExpiresAt) {
			delete(m.rateLimits, key)
			expired++
		}
	}
	return expired
}

// cleanPasswordResets removes expired password reset tokens.
func (m *MemoryStore) cleanPasswordResets(now time.Time) int {
	expired := 0
	for key, item := range m.passwordResets {
		if now.After(item.ExpiresAt) {
			delete(m.passwordResets, key)
			expired++
		}
	}
	return expired
}

// Close shuts down the memory store and cleanup goroutine.
func (m *MemoryStore) Close() error {
	close(m.stopCleanup)
	m.logger.Info("Memory store closed")
	return nil
}

// Ping always returns nil for memory store (always available).
func (m *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// StoreClient stores a client in memory without expiration.
func (m *MemoryStore) StoreClient(_ context.Context, client *models.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clients[client.ID] = client
	m.logger.WithField("client_id", client.ID).Debug("Client stored in memory")
	return nil
}

// GetClient retrieves a client from memory.
func (m *MemoryStore) GetClient(_ context.Context, clientID string) (*models.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, exists := m.clients[clientID]
	if !exists {
		return nil, errors.New("client not found")
	}

	return client, nil
}

// DeleteClient removes a client from memory.
func (m *MemoryStore) DeleteClient(_ context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.clients, clientID)
	m.logger.WithField("client_id", clientID).Debug("Client deleted from memory")
	return nil
}

// StoreAuthorizationCode stores an authorization code with TTL.
func (m *MemoryStore) StoreAuthorizationCode(
	_ context.Context,
	code *models.AuthorizationCode,
	ttl time.Duration,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.authCodes[code.Code] = &expiringItem[*models.AuthorizationCode]{
		Data:      code,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.logger.WithField("code", code.Code).Debug("Authorization code stored in memory")
	return nil
}

// GetAuthorizationCode retrieves an authorization code from memory.
func (m *MemoryStore) GetAuthorizationCode(_ context.Context, code string) (*models.AuthorizationCode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.authCodes[code]
	if !exists || item.isExpired() {
		return nil, errors.New("authorization code not found")
	}

	return item.Data, nil
}

// DeleteAuthorizationCode removes an authorization code from memory.
func (m *MemoryStore) DeleteAuthorizationCode(_ context.Context, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.authCodes, code)
	m.logger.WithField("code", code).Debug("Authorization code deleted from memory")
	return nil
}

// StoreAccessToken stores an access token with TTL.
func (m *MemoryStore) StoreAccessToken(_ context.Context, token *models.AccessToken, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.accessTokens[token.Token] = &expiringItem[*models.AccessToken]{
		Data:      token,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.logger.WithField("token", maskToken(token.Token)).Debug("Access token stored in memory")
	return nil
}

// GetAccessToken retrieves an access token from memory.
func (m *MemoryStore) GetAccessToken(_ context.Context, token string) (*models.AccessToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.accessTokens[token]
	if !exists || item.isExpired() {
		return nil, errors.New("access token not found")
	}

	return item.Data, nil
}

// DeleteAccessToken removes an access token from memory.
func (m *MemoryStore) DeleteAccessToken(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.accessTokens, token)
	m.logger.WithField("token", maskToken(token)).Debug("Access token deleted from memory")
	return nil
}

// RevokeAccessToken marks an access token as revoked.
func (m *MemoryStore) RevokeAccessToken(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.accessTokens[token]
	if !exists || item.isExpired() {
		return errors.New("access token not found")
	}

	item.Data.Revoked = true
	m.logger.WithField("token", maskToken(token)).Debug("Access token revoked in memory")
	return nil
}

// StoreRefreshToken stores a refresh token with TTL.
func (m *MemoryStore) StoreRefreshToken(_ context.Context, token *models.RefreshToken, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.refreshTokens[token.Token] = &expiringItem[*models.RefreshToken]{
		Data:      token,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.logger.WithField("token", maskToken(token.Token)).Debug("Refresh token stored in memory")
	return nil
}

// GetRefreshToken retrieves a refresh token from memory.
func (m *MemoryStore) GetRefreshToken(_ context.Context, token string) (*models.RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.refreshTokens[token]
	if !exists || item.isExpired() {
		return nil, errors.New("refresh token not found")
	}

	return item.Data, nil
}

// DeleteRefreshToken removes a refresh token from memory.
func (m *MemoryStore) DeleteRefreshToken(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.refreshTokens, token)
	m.logger.WithField("token", maskToken(token)).Debug("Refresh token deleted from memory")
	return nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (m *MemoryStore) RevokeRefreshToken(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.refreshTokens[token]
	if !exists || item.isExpired() {
		return errors.New("refresh token not found")
	}

	item.Data.Revoked = true
	m.logger.WithField("token", maskToken(token)).Debug("Refresh token revoked in memory")
	return nil
}

// StoreSession stores a session with TTL.
func (m *MemoryStore) StoreSession(_ context.Context, session *models.Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.ID] = &expiringItem[*models.Session]{
		Data:      session,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.logger.WithField("session_id", session.ID).Debug("Session stored in memory")
	return nil
}

// GetSession retrieves a session from memory.
func (m *MemoryStore) GetSession(_ context.Context, sessionID string) (*models.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.sessions[sessionID]
	if !exists || item.isExpired() {
		return nil, errors.New("session not found")
	}

	return item.Data, nil
}

// DeleteSession removes a session from memory.
func (m *MemoryStore) DeleteSession(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)
	m.logger.WithField("session_id", sessionID).Debug("Session deleted from memory")
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted.
func (m *MemoryStore) IsTokenBlacklisted(_ context.Context, token string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.blacklist[token]
	if !exists || item.isExpired() {
		return false, nil
	}

	return item.Data, nil
}

// BlacklistToken adds a token to the blacklist with TTL.
func (m *MemoryStore) BlacklistToken(_ context.Context, token string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.blacklist[token] = &expiringItem[bool]{
		Data:      true,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.logger.WithField("token", maskToken(token)).Debug("Token blacklisted in memory")
	return nil
}

// SetRateLimit sets a rate limit counter with TTL.
func (m *MemoryStore) SetRateLimit(_ context.Context, key string, limit int, window time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rateLimits[key] = &expiringItem[int]{
		Data:      limit,
		ExpiresAt: time.Now().Add(window),
	}
	return nil
}

// CheckRateLimit increments and checks a rate limit counter.
func (m *MemoryStore) CheckRateLimit(
	_ context.Context,
	key string,
	limit int,
	window time.Duration,
) (bool, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.rateLimits[key]
	if !exists || item.isExpired() {
		// First request or expired counter
		m.rateLimits[key] = &expiringItem[int]{
			Data:      1,
			ExpiresAt: time.Now().Add(window),
		}
		return true, limit - 1, nil
	}

	// Increment counter
	item.Data++
	remaining := limit - item.Data
	if remaining < 0 {
		remaining = 0
	}

	return item.Data <= limit, remaining, nil
}

// StoreUser stores a user in memory without expiration.
func (m *MemoryStore) StoreUser(_ context.Context, user *models.UserWithPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users[user.Username] = user
	if user.Email != nil && *user.Email != "" {
		m.usersByEmail[*user.Email] = user
	}
	m.logger.WithField("username", user.Username).Debug("User stored in memory")
	return nil
}

// GetUser retrieves a user by username from memory.
func (m *MemoryStore) GetUser(_ context.Context, username string) (*models.UserWithPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email from memory.
func (m *MemoryStore) GetUserByEmail(_ context.Context, email string) (*models.UserWithPassword, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByEmail[email]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// UpdateUser updates an existing user's information in memory.
func (m *MemoryStore) UpdateUser(_ context.Context, user *models.UserWithPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get existing user to check for email changes
	existingUser, exists := m.users[user.Username]
	if !exists {
		return errors.New("user not found")
	}

	// Handle email key updates
	var oldEmail, newEmail string
	if existingUser.Email != nil {
		oldEmail = *existingUser.Email
	}
	if user.Email != nil {
		newEmail = *user.Email
	}

	if oldEmail != newEmail {
		// Delete old email key if it exists
		if oldEmail != "" {
			delete(m.usersByEmail, oldEmail)
		}
		// Set new email key if email is provided
		if newEmail != "" {
			m.usersByEmail[newEmail] = user
		}
	}

	// Update user data
	m.users[user.Username] = user
	m.logger.WithField("username", user.Username).Debug("User updated in memory")
	return nil
}

// DeleteUser removes a user from memory.
func (m *MemoryStore) DeleteUser(_ context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get user to find email for cleanup
	user, exists := m.users[username]
	if exists && user.Email != nil && *user.Email != "" {
		delete(m.usersByEmail, *user.Email)
	}

	delete(m.users, username)
	m.logger.WithField("username", username).Debug("User deleted from memory")
	return nil
}

// StorePasswordResetToken stores a password reset token with TTL.
func (m *MemoryStore) StorePasswordResetToken(
	_ context.Context,
	token *models.PasswordResetToken,
	ttl time.Duration,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.passwordResets[token.Token] = &expiringItem[*models.PasswordResetToken]{
		Data:      token,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.logger.WithField("token", maskToken(token.Token)).Debug("Password reset token stored in memory")
	return nil
}

// GetPasswordResetToken retrieves a password reset token from memory.
func (m *MemoryStore) GetPasswordResetToken(
	_ context.Context,
	token string,
) (*models.PasswordResetToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.passwordResets[token]
	if !exists || item.isExpired() {
		return nil, errors.New("password reset token not found")
	}

	return item.Data, nil
}

// DeletePasswordResetToken removes a password reset token from memory.
func (m *MemoryStore) DeletePasswordResetToken(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.passwordResets, token)
	m.logger.WithField("token", maskToken(token)).Debug("Password reset token deleted from memory")
	return nil
}
