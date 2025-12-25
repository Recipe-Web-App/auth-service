// Package config provides configuration management for the OAuth2 authentication service.
package config

// ServiceURLs contains URLs for downstream services based on environment.
// URLs are automatically configured based on the current environment setting.
type ServiceURLs struct {
	// NotificationServiceBaseURL is the base URL for the notification service API.
	NotificationServiceBaseURL string
}

// GetServiceURLs returns environment-appropriate URLs for downstream services.
// It reads the environment from the config and returns the corresponding URLs.
// Calling code does not need to know about the environment - it's handled internally.
//
// Example usage:
//
//	cfg, _ := config.Load()
//	urls := cfg.GetServiceURLs()
//	notificationURL := urls.NotificationServiceBaseURL
func (c *Config) GetServiceURLs() ServiceURLs {
	switch c.Environment.Environment {
	case NonProd:
		fallthrough
	case Prod:
		return ServiceURLs{
			NotificationServiceBaseURL: "http://notification-service.notification.svc.cluster.local:8000/api/v1/notification",
		}
	case Local:
		fallthrough
	default:
		return ServiceURLs{
			NotificationServiceBaseURL: "http://sous-chef-proxy.local/api/v1/notification",
		}
	}
}
