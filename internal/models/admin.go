// Package models provides data structures for the auth service.
package models

// SessionStats represents statistics about current sessions in the cache.
type SessionStats struct {
	TotalSessions  int      `json:"totalSessions"`
	ActiveSessions int      `json:"activeSessions"`
	MemoryUsage    string   `json:"memoryUsage"`
	TTLInfo        *TTLInfo `json:"ttlInfo,omitempty"`
}

// TTLInfo contains optional TTL-related statistics for sessions.
type TTLInfo struct {
	TTLPolicyUsage  []SessionTTLPolicyStats `json:"ttlPolicyUsage,omitempty"`
	TTLDistribution []TTLDistributionBucket `json:"ttlDistribution,omitempty"`
	TTLSummary      *TTLSummary             `json:"ttlSummary,omitempty"`
}

// SessionTTLPolicyStats represents a breakdown of sessions by their assigned TTL configuration.
type SessionTTLPolicyStats struct {
	PolicyName    string `json:"policyName"`
	ConfiguredTTL int    `json:"configuredTtl"`
	Unit          string `json:"unit,omitempty"`
	ActiveCount   int    `json:"activeCount"`
}

// TTLDistributionBucket represents a histogram bucket showing how many sessions
// expire within a specific time range.
type TTLDistributionBucket struct {
	RangeStart   string `json:"rangeStart"`
	RangeEnd     string `json:"rangeEnd"`
	SessionCount int    `json:"sessionCount"`
}

// TTLSummary represents aggregate TTL statistics across all sessions.
type TTLSummary struct {
	AverageRemainingSeconds int `json:"averageRemainingSeconds"`
	OldestSessionAgeSeconds int `json:"oldestSessionAgeSeconds"`
	TotalSessionsWithTTL    int `json:"totalSessionsWithTtl"`
}

// SessionStatsRequest holds the query parameters for session stats requests.
type SessionStatsRequest struct {
	IncludeTTLPolicy       bool
	IncludeTTLDistribution bool
	IncludeTTLSummary      bool
}
