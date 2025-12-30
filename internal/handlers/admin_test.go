package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/handlers"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/models"
	"github.com/jsamuelsen11/recipe-web-app/auth-service/pkg/logger"
)

// mockAdminService implements auth.AdminService for testing.
type mockAdminService struct {
	getSessionStatsFunc func(ctx context.Context, req *models.SessionStatsRequest) (*models.SessionStats, error)
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
