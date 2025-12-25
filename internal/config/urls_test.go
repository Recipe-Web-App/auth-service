package config_test

import (
	"testing"

	"github.com/jsamuelsen11/recipe-web-app/auth-service/internal/config"
)

func TestConfig_GetServiceURLs(t *testing.T) {
	tests := []struct {
		name                    string
		environment             config.Environment
		wantNotificationBaseURL string
	}{
		{
			name:                    "Local environment returns localhost URLs",
			environment:             config.Local,
			wantNotificationBaseURL: "http://sous-chef-proxy.local/api/v1/notification",
		},
		{
			name:                    "NonProd environment returns Kubernetes internal URLs",
			environment:             config.NonProd,
			wantNotificationBaseURL: "http://notification-service.notification.svc.cluster.local:8000/api/v1/notification",
		},
		{
			name:                    "Prod environment returns Kubernetes internal URLs",
			environment:             config.Prod,
			wantNotificationBaseURL: "http://notification-service.notification.svc.cluster.local:8000/api/v1/notification",
		},
		{
			name:                    "Empty/unrecognized environment defaults to Local",
			environment:             config.Environment("UNKNOWN"),
			wantNotificationBaseURL: "http://sous-chef-proxy.local/api/v1/notification",
		},
		{
			name:                    "Empty string environment defaults to Local",
			environment:             config.Environment(""),
			wantNotificationBaseURL: "http://sous-chef-proxy.local/api/v1/notification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Environment: config.EnvironmentConfig{
					Environment: tt.environment,
				},
			}

			urls := cfg.GetServiceURLs()

			if urls.NotificationServiceBaseURL != tt.wantNotificationBaseURL {
				t.Errorf("GetServiceURLs().NotificationServiceBaseURL = %v, want %v",
					urls.NotificationServiceBaseURL, tt.wantNotificationBaseURL)
			}
		})
	}
}

func TestServiceURLs_NotificationServiceURL_NotEmpty(t *testing.T) {
	// Test that ServiceURLs struct is correctly populated for each environment
	environments := []config.Environment{config.Local, config.NonProd, config.Prod}

	for _, env := range environments {
		t.Run(string(env), func(t *testing.T) {
			cfg := &config.Config{
				Environment: config.EnvironmentConfig{
					Environment: env,
				},
			}

			urls := cfg.GetServiceURLs()

			if urls.NotificationServiceBaseURL == "" {
				t.Errorf("NotificationServiceBaseURL should not be empty for environment %s", env)
			}
		})
	}
}

func TestServiceURLs_ConsistencyBetweenNonProdAndProd(t *testing.T) {
	// Verify that NonProd and Prod use the same Kubernetes internal URL
	nonProdCfg := &config.Config{
		Environment: config.EnvironmentConfig{
			Environment: config.NonProd,
		},
	}

	prodCfg := &config.Config{
		Environment: config.EnvironmentConfig{
			Environment: config.Prod,
		},
	}

	nonProdURLs := nonProdCfg.GetServiceURLs()
	prodURLs := prodCfg.GetServiceURLs()

	if nonProdURLs.NotificationServiceBaseURL != prodURLs.NotificationServiceBaseURL {
		t.Errorf("NonProd and Prod should use the same Kubernetes internal URL, got NonProd=%s, Prod=%s",
			nonProdURLs.NotificationServiceBaseURL, prodURLs.NotificationServiceBaseURL)
	}
}

func TestServiceURLs_LocalVsCluster(t *testing.T) {
	// Verify that Local uses .local domain and NonProd/Prod use cluster URLs
	localCfg := &config.Config{
		Environment: config.EnvironmentConfig{
			Environment: config.Local,
		},
	}

	nonProdCfg := &config.Config{
		Environment: config.EnvironmentConfig{
			Environment: config.NonProd,
		},
	}

	localURLs := localCfg.GetServiceURLs()
	nonProdURLs := nonProdCfg.GetServiceURLs()

	// Local should contain "sous-chef-proxy.local"
	if !contains(localURLs.NotificationServiceBaseURL, "sous-chef-proxy.local") {
		t.Errorf(
			"Local environment should use sous-chef-proxy.local domain, got %s",
			localURLs.NotificationServiceBaseURL,
		)
	}

	// NonProd should contain "cluster.local"
	if !contains(nonProdURLs.NotificationServiceBaseURL, "cluster.local") {
		t.Errorf(
			"NonProd environment should use Kubernetes internal DNS, got %s",
			nonProdURLs.NotificationServiceBaseURL,
		)
	}

	// They should be different
	if localURLs.NotificationServiceBaseURL == nonProdURLs.NotificationServiceBaseURL {
		t.Error("Local and NonProd URLs should be different")
	}
}

// contains is a helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsRecursive(s, substr))
}

func containsRecursive(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
