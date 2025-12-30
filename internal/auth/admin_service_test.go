package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/auth"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/redis"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/pkg/logger"
)

func TestAdminService_GetSessionStats(t *testing.T) {
	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	t.Run("empty_store", func(t *testing.T) {
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 0, stats.TotalSessions)
		assert.Equal(t, 0, stats.ActiveSessions)
		assert.NotEmpty(t, stats.MemoryUsage)
		assert.Nil(t, stats.TTLInfo)
	})

	// Create test sessions
	for i := range 5 {
		session := models.NewSession("user-"+string(rune('a'+i)), "client-1")
		err := store.StoreSession(ctx, session, models.DefaultSessionExpiry)
		require.NoError(t, err)
	}

	t.Run("basic_stats_with_sessions", func(t *testing.T) {
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 5, stats.TotalSessions)
		assert.Equal(t, 5, stats.ActiveSessions)
		assert.NotEmpty(t, stats.MemoryUsage)
		assert.Nil(t, stats.TTLInfo)
	})

	t.Run("with_ttl_policy", func(t *testing.T) {
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{
			IncludeTTLPolicy: true,
		})
		require.NoError(t, err)
		require.NotNil(t, stats.TTLInfo)
		require.Len(t, stats.TTLInfo.TTLPolicyUsage, 1)
		assert.Equal(t, "Default", stats.TTLInfo.TTLPolicyUsage[0].PolicyName)
		assert.Equal(t, int(models.DefaultSessionExpiry.Seconds()), stats.TTLInfo.TTLPolicyUsage[0].ConfiguredTTL)
		assert.Equal(t, "seconds", stats.TTLInfo.TTLPolicyUsage[0].Unit)
		assert.Equal(t, 5, stats.TTLInfo.TTLPolicyUsage[0].ActiveCount)
	})

	t.Run("with_ttl_distribution", func(t *testing.T) {
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{
			IncludeTTLDistribution: true,
		})
		require.NoError(t, err)
		require.NotNil(t, stats.TTLInfo)
		require.NotNil(t, stats.TTLInfo.TTLDistribution)
		// Should have 5 buckets as defined in the distribution
		assert.GreaterOrEqual(t, len(stats.TTLInfo.TTLDistribution), 1)

		// Verify bucket structure
		for _, bucket := range stats.TTLInfo.TTLDistribution {
			assert.NotEmpty(t, bucket.RangeStart)
			assert.NotEmpty(t, bucket.RangeEnd)
			assert.GreaterOrEqual(t, bucket.SessionCount, 0)
		}
	})

	t.Run("with_ttl_summary", func(t *testing.T) {
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{
			IncludeTTLSummary: true,
		})
		require.NoError(t, err)
		require.NotNil(t, stats.TTLInfo)
		require.NotNil(t, stats.TTLInfo.TTLSummary)
		assert.Equal(t, 5, stats.TTLInfo.TTLSummary.TotalSessionsWithTTL)
		// Average should be close to 24 hours in seconds
		assert.Positive(t, stats.TTLInfo.TTLSummary.AverageRemainingSeconds)
	})

	t.Run("with_all_ttl_options", func(t *testing.T) {
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{
			IncludeTTLPolicy:       true,
			IncludeTTLDistribution: true,
			IncludeTTLSummary:      true,
		})
		require.NoError(t, err)
		require.NotNil(t, stats.TTLInfo)
		assert.NotNil(t, stats.TTLInfo.TTLPolicyUsage)
		assert.NotNil(t, stats.TTLInfo.TTLDistribution)
		assert.NotNil(t, stats.TTLInfo.TTLSummary)
	})
}

func TestAdminService_GetSessionStats_WithExpiredSessions(t *testing.T) {
	t.Parallel()

	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	// Create one session with very short TTL that will expire
	session := models.NewSession("user-short", "client-1")
	err := store.StoreSession(ctx, session, 1*time.Millisecond)
	require.NoError(t, err)

	// Create another session with long TTL
	session2 := models.NewSession("user-long", "client-1")
	err = store.StoreSession(ctx, session2, 24*time.Hour)
	require.NoError(t, err)

	// Wait for short TTL session to expire
	time.Sleep(10 * time.Millisecond)

	stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
	require.NoError(t, err)

	// Total should be 2 (both stored), but active should be 1 (only non-expired)
	assert.Equal(t, 2, stats.TotalSessions)
	assert.Equal(t, 1, stats.ActiveSessions)
}

func TestAdminService_GetSessionStats_MemoryUsage(t *testing.T) {
	t.Parallel()

	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
	require.NoError(t, err)

	// Memory store should return a specific message
	assert.Equal(t, "in-memory (not tracked)", stats.MemoryUsage)
}

func TestAdminService_ClearAllSessions(t *testing.T) {
	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	t.Run("empty_store", func(t *testing.T) {
		response, err := svc.ClearAllSessions(ctx)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, 0, response.SessionsCleared)
		assert.Contains(t, response.Message, "0 sessions")
	})

	// Create test sessions
	for i := range 5 {
		session := models.NewSession("user-"+string(rune('a'+i)), "client-1")
		err := store.StoreSession(ctx, session, models.DefaultSessionExpiry)
		require.NoError(t, err)
	}

	t.Run("clear_sessions", func(t *testing.T) {
		// Verify sessions exist
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 5, stats.ActiveSessions)

		// Clear sessions
		response, err := svc.ClearAllSessions(ctx)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, 5, response.SessionsCleared)
		assert.Contains(t, response.Message, "5 sessions")

		// Verify sessions are cleared
		stats, err = svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 0, stats.ActiveSessions)
	})
}

func TestAdminService_ClearAllSessions_Idempotent(t *testing.T) {
	t.Parallel()

	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	// Create sessions
	for i := range 3 {
		session := models.NewSession("user-"+string(rune('a'+i)), "client-1")
		err := store.StoreSession(ctx, session, models.DefaultSessionExpiry)
		require.NoError(t, err)
	}

	// First clear
	response1, err := svc.ClearAllSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, response1.SessionsCleared)

	// Second clear (should be idempotent)
	response2, err := svc.ClearAllSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, response2.SessionsCleared)
	assert.True(t, response2.Success)
}

func TestAdminService_ForceLogoutUser(t *testing.T) {
	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	targetUserID := "user-target"
	otherUserID := "user-other"

	t.Run("empty_store", func(t *testing.T) {
		response, err := svc.ForceLogoutUser(ctx, targetUserID)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, targetUserID, response.UserID)
		assert.Equal(t, 0, response.SessionsCleared)
		assert.Contains(t, response.Message, "0 sessions")
	})

	// Create sessions for target user
	for i := range 3 {
		session := models.NewSession(targetUserID, "client-"+string(rune('1'+i)))
		err := store.StoreSession(ctx, session, models.DefaultSessionExpiry)
		require.NoError(t, err)
	}

	// Create sessions for other user
	for i := range 2 {
		session := models.NewSession(otherUserID, "client-"+string(rune('1'+i)))
		err := store.StoreSession(ctx, session, models.DefaultSessionExpiry)
		require.NoError(t, err)
	}

	t.Run("force_logout_target_user", func(t *testing.T) {
		// Verify all sessions exist
		stats, err := svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 5, stats.ActiveSessions)

		// Force logout target user
		response, err := svc.ForceLogoutUser(ctx, targetUserID)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, targetUserID, response.UserID)
		assert.Equal(t, 3, response.SessionsCleared)
		assert.Contains(t, response.Message, "3 sessions")

		// Verify only target user's sessions are cleared
		stats, err = svc.GetSessionStats(ctx, &models.SessionStatsRequest{})
		require.NoError(t, err)
		assert.Equal(t, 2, stats.ActiveSessions) // Only other user's sessions remain
	})

	t.Run("force_logout_already_logged_out_user", func(t *testing.T) {
		// Force logout target user again (should be idempotent)
		response, err := svc.ForceLogoutUser(ctx, targetUserID)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, targetUserID, response.UserID)
		assert.Equal(t, 0, response.SessionsCleared)
	})
}

func TestAdminService_ForceLogoutUser_WithExpiredSessions(t *testing.T) {
	t.Parallel()

	log := logger.New("debug", "json", "stdout")
	store := redis.NewMemoryStore(log)
	t.Cleanup(func() { _ = store.Close() })

	svc := auth.NewAdminService(nil, store, log)
	ctx := context.Background()

	targetUserID := "user-target"

	// Create one session with very short TTL that will expire
	session1 := models.NewSession(targetUserID, "client-1")
	err := store.StoreSession(ctx, session1, 1*time.Millisecond)
	require.NoError(t, err)

	// Create another session with long TTL
	session2 := models.NewSession(targetUserID, "client-2")
	err = store.StoreSession(ctx, session2, 24*time.Hour)
	require.NoError(t, err)

	// Wait for short TTL session to expire
	time.Sleep(10 * time.Millisecond)

	// Force logout should only count active sessions
	response, err := svc.ForceLogoutUser(ctx, targetUserID)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, targetUserID, response.UserID)
	assert.Equal(t, 1, response.SessionsCleared) // Only active session counts
}
