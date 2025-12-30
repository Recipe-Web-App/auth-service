package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/handlers"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/pkg/logger"
)

// mockAdminService implements auth.AdminService for testing.
type mockAdminService struct {
	getSessionStatsFunc  func(ctx context.Context, req *models.SessionStatsRequest) (*models.SessionStats, error)
	clearAllSessionsFunc func(ctx context.Context) (*models.ClearSessionsResponse, error)
	forceLogoutUserFunc  func(ctx context.Context, userID string) (*models.ForceLogoutResponse, error)
	clearAllCachesFunc   func(ctx context.Context) (*models.ClearAllCachesResponse, error)
}

func (m *mockAdminService) GetSessionStats(
	ctx context.Context,
	req *models.SessionStatsRequest,
) (*models.SessionStats, error) {
	if m.getSessionStatsFunc != nil {
		return m.getSessionStatsFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAdminService) ClearAllSessions(ctx context.Context) (*models.ClearSessionsResponse, error) {
	if m.clearAllSessionsFunc != nil {
		return m.clearAllSessionsFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAdminService) ForceLogoutUser(ctx context.Context, userID string) (*models.ForceLogoutResponse, error) {
	if m.forceLogoutUserFunc != nil {
		return m.forceLogoutUserFunc(ctx, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAdminService) ClearAllCaches(ctx context.Context) (*models.ClearAllCachesResponse, error) {
	if m.clearAllCachesFunc != nil {
		return m.clearAllCachesFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

func TestAdminHandler_GetSessionStats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		queryParams    string
		mockFunc       func(ctx context.Context, req *models.SessionStatsRequest) (*models.SessionStats, error)
		expectedStatus int
		validateReq    func(t *testing.T, req *models.SessionStatsRequest)
		validateResp   func(t *testing.T, resp *models.SessionStats)
	}{
		{
			name:        "successful_stats_retrieval_no_params",
			queryParams: "",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  100,
					ActiveSessions: 95,
					MemoryUsage:    "10.5MB",
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq: func(t *testing.T, req *models.SessionStatsRequest) {
				assert.False(t, req.IncludeTTLPolicy)
				assert.False(t, req.IncludeTTLDistribution)
				assert.False(t, req.IncludeTTLSummary)
			},
			validateResp: func(t *testing.T, resp *models.SessionStats) {
				assert.Equal(t, 100, resp.TotalSessions)
				assert.Equal(t, 95, resp.ActiveSessions)
				assert.Equal(t, "10.5MB", resp.MemoryUsage)
				assert.Nil(t, resp.TTLInfo)
			},
		},
		{
			name:        "successful_stats_with_ttl_policy",
			queryParams: "?includeTtlPolicy=true",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  50,
					ActiveSessions: 50,
					MemoryUsage:    "5MB",
					TTLInfo: &models.TTLInfo{
						TTLPolicyUsage: []models.SessionTTLPolicyStats{
							{PolicyName: "Default", ConfiguredTTL: 86400, Unit: "seconds", ActiveCount: 50},
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq: func(t *testing.T, req *models.SessionStatsRequest) {
				assert.True(t, req.IncludeTTLPolicy)
				assert.False(t, req.IncludeTTLDistribution)
				assert.False(t, req.IncludeTTLSummary)
			},
			validateResp: func(t *testing.T, resp *models.SessionStats) {
				require.NotNil(t, resp.TTLInfo)
				require.Len(t, resp.TTLInfo.TTLPolicyUsage, 1)
				assert.Equal(t, "Default", resp.TTLInfo.TTLPolicyUsage[0].PolicyName)
				assert.Equal(t, 86400, resp.TTLInfo.TTLPolicyUsage[0].ConfiguredTTL)
			},
		},
		{
			name:        "successful_stats_with_ttl_distribution",
			queryParams: "?includeTtlDistribution=true",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  30,
					ActiveSessions: 30,
					MemoryUsage:    "3MB",
					TTLInfo: &models.TTLInfo{
						TTLDistribution: []models.TTLDistributionBucket{
							{RangeStart: "0m", RangeEnd: "15m", SessionCount: 5},
							{RangeStart: "15m", RangeEnd: "60m", SessionCount: 10},
							{RangeStart: "1h", RangeEnd: "6h", SessionCount: 15},
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq: func(t *testing.T, req *models.SessionStatsRequest) {
				assert.False(t, req.IncludeTTLPolicy)
				assert.True(t, req.IncludeTTLDistribution)
				assert.False(t, req.IncludeTTLSummary)
			},
			validateResp: func(t *testing.T, resp *models.SessionStats) {
				require.NotNil(t, resp.TTLInfo)
				require.Len(t, resp.TTLInfo.TTLDistribution, 3)
			},
		},
		{
			name:        "successful_stats_with_ttl_summary",
			queryParams: "?includeTtlSummary=true",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  20,
					ActiveSessions: 20,
					MemoryUsage:    "2MB",
					TTLInfo: &models.TTLInfo{
						TTLSummary: &models.TTLSummary{
							AverageRemainingSeconds: 43200,
							OldestSessionAgeSeconds: 3600,
							TotalSessionsWithTTL:    20,
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq: func(t *testing.T, req *models.SessionStatsRequest) {
				assert.False(t, req.IncludeTTLPolicy)
				assert.False(t, req.IncludeTTLDistribution)
				assert.True(t, req.IncludeTTLSummary)
			},
			validateResp: func(t *testing.T, resp *models.SessionStats) {
				require.NotNil(t, resp.TTLInfo)
				require.NotNil(t, resp.TTLInfo.TTLSummary)
				assert.Equal(t, 43200, resp.TTLInfo.TTLSummary.AverageRemainingSeconds)
			},
		},
		{
			name:        "successful_stats_with_all_ttl_options",
			queryParams: "?includeTtlPolicy=true&includeTtlDistribution=true&includeTtlSummary=true",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  10,
					ActiveSessions: 10,
					MemoryUsage:    "1MB",
					TTLInfo: &models.TTLInfo{
						TTLPolicyUsage: []models.SessionTTLPolicyStats{
							{PolicyName: "Default", ConfiguredTTL: 86400, Unit: "seconds", ActiveCount: 10},
						},
						TTLDistribution: []models.TTLDistributionBucket{
							{RangeStart: "0m", RangeEnd: "15m", SessionCount: 2},
						},
						TTLSummary: &models.TTLSummary{
							AverageRemainingSeconds: 50000,
							OldestSessionAgeSeconds: 1000,
							TotalSessionsWithTTL:    10,
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq: func(t *testing.T, req *models.SessionStatsRequest) {
				assert.True(t, req.IncludeTTLPolicy)
				assert.True(t, req.IncludeTTLDistribution)
				assert.True(t, req.IncludeTTLSummary)
			},
			validateResp: func(t *testing.T, resp *models.SessionStats) {
				require.NotNil(t, resp.TTLInfo)
				require.NotNil(t, resp.TTLInfo.TTLPolicyUsage)
				require.NotNil(t, resp.TTLInfo.TTLDistribution)
				require.NotNil(t, resp.TTLInfo.TTLSummary)
			},
		},
		{
			name:        "service_error",
			queryParams: "",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return nil, errors.New("redis connection failed")
			},
			expectedStatus: http.StatusInternalServerError,
			validateReq:    nil,
			validateResp:   nil,
		},
		{
			name:        "invalid_bool_param_defaults_to_false",
			queryParams: "?includeTtlPolicy=invalid",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  5,
					ActiveSessions: 5,
					MemoryUsage:    "500KB",
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq: func(t *testing.T, req *models.SessionStatsRequest) {
				assert.False(t, req.IncludeTTLPolicy)
			},
			validateResp: nil,
		},
		{
			name:        "zero_sessions",
			queryParams: "",
			mockFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
				return &models.SessionStats{
					TotalSessions:  0,
					ActiveSessions: 0,
					MemoryUsage:    "0B",
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateReq:    nil,
			validateResp: func(t *testing.T, resp *models.SessionStats) {
				assert.Equal(t, 0, resp.TotalSessions)
				assert.Equal(t, 0, resp.ActiveSessions)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedReq *models.SessionStatsRequest
			mockSvc := &mockAdminService{
				getSessionStatsFunc: func(ctx context.Context, req *models.SessionStatsRequest) (*models.SessionStats, error) {
					capturedReq = req
					return tt.mockFunc(ctx, req)
				},
			}

			log := logger.New("debug", "json", "stdout")
			handler := handlers.NewAdminHandler(mockSvc, nil, log)

			req := httptest.NewRequest(http.MethodGet, "/admin/cache/sessions/stats"+tt.queryParams, nil)
			rr := httptest.NewRecorder()

			handler.GetSessionStats(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response models.SessionStats
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)

				if tt.validateReq != nil && capturedReq != nil {
					tt.validateReq(t, capturedReq)
				}

				if tt.validateResp != nil {
					tt.validateResp(t, &response)
				}
			}
		})
	}
}

func TestAdminHandler_GetSessionStats_ContentType(t *testing.T) {
	t.Parallel()

	mockSvc := &mockAdminService{
		getSessionStatsFunc: func(_ context.Context, _ *models.SessionStatsRequest) (*models.SessionStats, error) {
			return &models.SessionStats{
				TotalSessions:  1,
				ActiveSessions: 1,
				MemoryUsage:    "1MB",
			}, nil
		},
	}

	log := logger.New("debug", "json", "stdout")
	handler := handlers.NewAdminHandler(mockSvc, nil, log)

	req := httptest.NewRequest(http.MethodGet, "/admin/cache/sessions/stats", nil)
	rr := httptest.NewRecorder()

	handler.GetSessionStats(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestAdminHandler_ClearSessions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		mockFunc       func(ctx context.Context) (*models.ClearSessionsResponse, error)
		expectedStatus int
		validateResp   func(t *testing.T, resp *models.ClearSessionsResponse)
	}{
		{
			name: "successful_clear_with_sessions",
			mockFunc: func(_ context.Context) (*models.ClearSessionsResponse, error) {
				return &models.ClearSessionsResponse{
					Success:         true,
					Message:         "Successfully cleared 10 sessions from cache",
					SessionsCleared: 10,
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *models.ClearSessionsResponse) {
				assert.True(t, resp.Success)
				assert.Equal(t, 10, resp.SessionsCleared)
				assert.Contains(t, resp.Message, "Successfully cleared")
			},
		},
		{
			name: "successful_clear_no_sessions",
			mockFunc: func(_ context.Context) (*models.ClearSessionsResponse, error) {
				return &models.ClearSessionsResponse{
					Success:         true,
					Message:         "Successfully cleared 0 sessions from cache",
					SessionsCleared: 0,
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *models.ClearSessionsResponse) {
				assert.True(t, resp.Success)
				assert.Equal(t, 0, resp.SessionsCleared)
			},
		},
		{
			name: "service_error",
			mockFunc: func(_ context.Context) (*models.ClearSessionsResponse, error) {
				return nil, errors.New("redis connection failed")
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockSvc := &mockAdminService{
				clearAllSessionsFunc: tt.mockFunc,
			}

			log := logger.New("debug", "json", "stdout")
			handler := handlers.NewAdminHandler(mockSvc, nil, log)

			req := httptest.NewRequest(http.MethodDelete, "/admin/cache/sessions", nil)
			rr := httptest.NewRecorder()

			handler.ClearSessions(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK && tt.validateResp != nil {
				var response models.ClearSessionsResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				tt.validateResp(t, &response)
			}
		})
	}
}

func TestAdminHandler_ClearSessions_ContentType(t *testing.T) {
	t.Parallel()

	mockSvc := &mockAdminService{
		clearAllSessionsFunc: func(_ context.Context) (*models.ClearSessionsResponse, error) {
			return &models.ClearSessionsResponse{
				Success:         true,
				Message:         "Successfully cleared 5 sessions from cache",
				SessionsCleared: 5,
			}, nil
		},
	}

	log := logger.New("debug", "json", "stdout")
	handler := handlers.NewAdminHandler(mockSvc, nil, log)

	req := httptest.NewRequest(http.MethodDelete, "/admin/cache/sessions", nil)
	rr := httptest.NewRecorder()

	handler.ClearSessions(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestAdminHandler_ForceLogout(t *testing.T) {
	t.Parallel()

	validUserID := "550e8400-e29b-41d4-a716-446655440000"

	tests := []struct {
		name           string
		userID         string
		mockFunc       func(ctx context.Context, userID string) (*models.ForceLogoutResponse, error)
		expectedStatus int
		validateResp   func(t *testing.T, resp *models.ForceLogoutResponse)
	}{
		{
			name:   "successful_force_logout_with_sessions",
			userID: validUserID,
			mockFunc: func(_ context.Context, userID string) (*models.ForceLogoutResponse, error) {
				return &models.ForceLogoutResponse{
					Success:         true,
					Message:         "Successfully logged out user and cleared 3 sessions",
					UserID:          userID,
					SessionsCleared: 3,
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *models.ForceLogoutResponse) {
				assert.True(t, resp.Success)
				assert.Equal(t, validUserID, resp.UserID)
				assert.Equal(t, 3, resp.SessionsCleared)
				assert.Contains(t, resp.Message, "Successfully logged out")
			},
		},
		{
			name:   "successful_force_logout_no_sessions",
			userID: validUserID,
			mockFunc: func(_ context.Context, userID string) (*models.ForceLogoutResponse, error) {
				return &models.ForceLogoutResponse{
					Success:         true,
					Message:         "Successfully logged out user and cleared 0 sessions",
					UserID:          userID,
					SessionsCleared: 0,
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *models.ForceLogoutResponse) {
				assert.True(t, resp.Success)
				assert.Equal(t, validUserID, resp.UserID)
				assert.Equal(t, 0, resp.SessionsCleared)
			},
		},
		{
			name:           "invalid_user_id_format",
			userID:         "not-a-uuid",
			mockFunc:       nil, // Should not be called
			expectedStatus: http.StatusBadRequest,
			validateResp:   nil,
		},
		{
			name:           "empty_user_id",
			userID:         "",
			mockFunc:       nil, // Should not be called
			expectedStatus: http.StatusBadRequest,
			validateResp:   nil,
		},
		{
			name:   "service_error",
			userID: validUserID,
			mockFunc: func(_ context.Context, _ string) (*models.ForceLogoutResponse, error) {
				return nil, errors.New("redis connection failed")
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockSvc := &mockAdminService{
				forceLogoutUserFunc: tt.mockFunc,
			}

			log := logger.New("debug", "json", "stdout")
			handler := handlers.NewAdminHandler(mockSvc, nil, log)

			// Create request with mux vars to simulate path parameter
			req := httptest.NewRequest(http.MethodPost, "/admin/user-management/"+tt.userID+"/force-logout", nil)
			req = mux.SetURLVars(req, map[string]string{"userId": tt.userID})
			rr := httptest.NewRecorder()

			handler.ForceLogout(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK && tt.validateResp != nil {
				var response models.ForceLogoutResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				tt.validateResp(t, &response)
			}
		})
	}
}

func TestAdminHandler_ForceLogout_ContentType(t *testing.T) {
	t.Parallel()

	validUserID := "550e8400-e29b-41d4-a716-446655440000"

	mockSvc := &mockAdminService{
		forceLogoutUserFunc: func(_ context.Context, userID string) (*models.ForceLogoutResponse, error) {
			return &models.ForceLogoutResponse{
				Success:         true,
				Message:         "Successfully logged out user and cleared 1 session",
				UserID:          userID,
				SessionsCleared: 1,
			}, nil
		},
	}

	log := logger.New("debug", "json", "stdout")
	handler := handlers.NewAdminHandler(mockSvc, nil, log)

	req := httptest.NewRequest(http.MethodPost, "/admin/user-management/"+validUserID+"/force-logout", nil)
	req = mux.SetURLVars(req, map[string]string{"userId": validUserID})
	rr := httptest.NewRecorder()

	handler.ForceLogout(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

func TestAdminHandler_ClearAllCaches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		mockFunc       func(ctx context.Context) (*models.ClearAllCachesResponse, error)
		expectedStatus int
		validateResp   func(t *testing.T, resp *models.ClearAllCachesResponse)
	}{
		{
			name: "successful_clear_all_caches",
			mockFunc: func(_ context.Context) (*models.ClearAllCachesResponse, error) {
				return &models.ClearAllCachesResponse{
					Success: true,
					Message: "Successfully cleared 156 keys from all caches",
					CachesCleared: map[string]int{
						"sessions":            42,
						"access_tokens":       38,
						"refresh_tokens":      35,
						"authorization_codes": 2,
						"blacklist":           5,
						"clients":             8,
						"users":               20,
						"password_resets":     6,
					},
					TotalKeysCleared: 156,
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *models.ClearAllCachesResponse) {
				assert.True(t, resp.Success)
				assert.Equal(t, 156, resp.TotalKeysCleared)
				assert.Contains(t, resp.Message, "Successfully cleared")
				assert.Equal(t, 42, resp.CachesCleared["sessions"])
				assert.Equal(t, 38, resp.CachesCleared["access_tokens"])
				assert.Equal(t, 8, resp.CachesCleared["clients"])
			},
		},
		{
			name: "successful_clear_empty_caches",
			mockFunc: func(_ context.Context) (*models.ClearAllCachesResponse, error) {
				return &models.ClearAllCachesResponse{
					Success: true,
					Message: "Successfully cleared 0 keys from all caches",
					CachesCleared: map[string]int{
						"sessions":            0,
						"access_tokens":       0,
						"refresh_tokens":      0,
						"authorization_codes": 0,
						"blacklist":           0,
						"clients":             0,
						"users":               0,
						"password_resets":     0,
					},
					TotalKeysCleared: 0,
				}, nil
			},
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, resp *models.ClearAllCachesResponse) {
				assert.True(t, resp.Success)
				assert.Equal(t, 0, resp.TotalKeysCleared)
			},
		},
		{
			name: "service_error",
			mockFunc: func(_ context.Context) (*models.ClearAllCachesResponse, error) {
				return nil, errors.New("redis connection failed")
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockSvc := &mockAdminService{
				clearAllCachesFunc: tt.mockFunc,
			}

			log := logger.New("debug", "json", "stdout")
			handler := handlers.NewAdminHandler(mockSvc, nil, log)

			req := httptest.NewRequest(http.MethodPost, "/admin/cache/clear", nil)
			rr := httptest.NewRecorder()

			handler.ClearAllCaches(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK && tt.validateResp != nil {
				var response models.ClearAllCachesResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				tt.validateResp(t, &response)
			}
		})
	}
}

func TestAdminHandler_ClearAllCaches_ContentType(t *testing.T) {
	t.Parallel()

	mockSvc := &mockAdminService{
		clearAllCachesFunc: func(_ context.Context) (*models.ClearAllCachesResponse, error) {
			return &models.ClearAllCachesResponse{
				Success:          true,
				Message:          "Successfully cleared 10 keys from all caches",
				CachesCleared:    map[string]int{"sessions": 10},
				TotalKeysCleared: 10,
			}, nil
		},
	}

	log := logger.New("debug", "json", "stdout")
	handler := handlers.NewAdminHandler(mockSvc, nil, log)

	req := httptest.NewRequest(http.MethodPost, "/admin/cache/clear", nil)
	rr := httptest.NewRecorder()

	handler.ClearAllCaches(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}
